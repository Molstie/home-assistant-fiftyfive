"""
50five API client with support for the e-mail one-time password (2FA) login.

``OtpApi`` subclasses ``fiftyfive.Api`` and only replaces ``login()`` and
``make_requests()``. It is only used when a mailbox has been configured; without
one the integration keeps using the plain library ``Api``.

The login flow, as a browser does it:

1. ``GET /Login/Login`` for the session and load balancer (SERVERID) cookies.
2. ``POST /Login/Login`` with e-mail and password (no redirects followed).
3. Follow the redirects one at a time. Back to the login page means the
   credentials were rejected; reaching the 2FA page means a code is needed.
4. Showing the 2FA page sends the mail; read the hidden ``_token`` from it.
5. Wait for the code in the mailbox, then ``POST`` it to ``/2fa_check``.

This module has no Home Assistant dependencies, so ``tools/test_login.py`` can
use it outside Home Assistant. Never log the password or the code.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from json import dumps
from typing import TYPE_CHECKING, Any

from yarl import URL

from fiftyfive import Api, CustomerType, Market

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import ClientSession

    from fiftyfive import Request

_LOGGER = logging.getLogger(__package__)

HTTP_FOUND = 302
MAX_REDIRECTS = 5
SESSION_COOKIE = "PHPSESSID"

# At most one login per 15 minutes, and stop after three failed logins in a
# row. Every login can send a verification mail; never hammer the account.
MIN_LOGIN_INTERVAL = 15 * 60
MAX_STRIKES = 3

_TOKEN_RES = (
    re.compile(r"""name=["']_token["'][^>]*?value=["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""value=["']([^"']+)["'][^>]*?name=["']_token["']""", re.IGNORECASE),
)
_FORM_ACTION_RE = re.compile(
    r"""<form[^>]*?action=["']([^"']*2fa[^"']*)["']""", re.IGNORECASE
)
_INPUT_NAME_RE = re.compile(r"""<input[^>]*?name=["']([^"']+)["']""", re.IGNORECASE)


class OtpLoginError(Exception):
    """Base class for login errors."""


class OtpAuthError(OtpLoginError):
    """The portal rejected the password or the verification code."""


class OtpCodeTimeoutError(OtpAuthError):
    """No verification code arrived in the mailbox in time."""


class OtpMailboxError(OtpLoginError):
    """The mailbox could not be read."""


class OtpFlowError(OtpLoginError):
    """The portal answered in an unexpected way during the login."""


class OtpThrottledError(OtpLoginError):
    """A login was attempted too soon after the previous one."""


class OtpLockedError(OtpLoginError):
    """Too many failed logins in a row; logins are stopped."""


class LoginStep(StrEnum):
    """What the portal wants after the password step."""

    LOGGED_IN = "logged_in"
    TWO_FACTOR = "two_factor"
    REJECTED = "rejected"


@dataclass
class LoginGuard:
    """
    Rate limit and strike counter for logins.

    ``last_attempt`` is wall clock time so it can be persisted across restarts.
    ``on_change`` is called after every change, so the owner can save it.
    """

    last_attempt: float = 0.0
    strikes: int = 0
    on_change: Callable[[], None] | None = field(default=None, repr=False)

    def check(self, now: float) -> None:
        """Raise if a login is not allowed right now."""
        if self.strikes >= MAX_STRIKES:
            msg = (
                f"{self.strikes} failed 50five logins in a row; automatic login "
                "stopped. Check the password and mailbox settings, then save "
                "the options again or re-authenticate."
            )
            raise OtpLockedError(msg)
        wait = self.last_attempt + MIN_LOGIN_INTERVAL - now
        if wait > 0:
            msg = f"Next 50five login allowed in {int(wait)} s"
            raise OtpThrottledError(msg)

    def record_attempt(self, now: float) -> None:
        """Register that a login is starting."""
        self.last_attempt = now
        self._changed()

    def record_failure(self) -> None:
        """Register a failed login."""
        self.strikes += 1
        self._changed()

    def record_success(self) -> None:
        """Register a successful login."""
        if self.strikes:
            self.strikes = 0
            self._changed()

    def as_dict(self) -> dict[str, Any]:
        """Return the persistable state."""
        return {"last_attempt": self.last_attempt, "strikes": self.strikes}

    def _changed(self) -> None:
        if self.on_change:
            self.on_change()


def _path(location: str) -> str:
    """Return the lower case path of a (possibly relative) redirect target."""
    return URL(location).path.lower() if location else ""


def classify_location(location: str) -> LoginStep:
    """Classify a redirect target after a login or 2FA step."""
    path = _path(location)
    if "2fa" in path:
        return LoginStep.TWO_FACTOR
    if "/login" in path:
        return LoginStep.REJECTED
    return LoginStep.LOGGED_IN


def find_token(html: str) -> str | None:
    """Return the hidden CSRF ``_token`` of the 2FA form."""
    for pattern in _TOKEN_RES:
        if match := pattern.search(html):
            return match.group(1)
    return None


class OtpApi(Api):
    """``fiftyfive.Api`` with 2FA login and one retry on an expired session."""

    def __init__(  # noqa: PLR0913
        self,
        session: ClientSession,
        email: str,
        password: str,
        market: Market,
        customer_type: CustomerType = CustomerType.FORMER_SHELL,
        *,
        code_provider: Callable[[datetime], Awaitable[str | None]],
        guard: LoginGuard,
        on_login: Callable[[str], None] | None = None,
        trace: Callable[[str], None] | None = None,
    ) -> None:
        """
        Initialize.

        ``code_provider`` gets the moment the login started and returns the
        code from the mailbox, or ``None`` when none arrived in time.
        ``on_login`` gets the new session cookie after a successful login.
        ``trace`` gets one line per HTTP step (no secrets), for diagnostics.
        """
        super().__init__(
            session=session,
            email=email,
            password=password,
            market=market,
            customer_type=customer_type,
        )
        self.guard = guard
        self._code_provider = code_provider
        self._on_login = on_login
        self._trace = trace
        self._lock = asyncio.Lock()
        self._generation = 0

    # -- session cookie -----------------------------------------------------

    def session_cookie(self) -> str | None:
        """Return the current portal session cookie, if any."""
        cookie = self.session.cookie_jar.filter_cookies(URL(self.url)).get(
            SESSION_COOKIE
        )
        return cookie.value if cookie else None

    def restore_session_cookie(self, value: str) -> None:
        """Put a previously saved session cookie back into the jar."""
        self.session.cookie_jar.update_cookies(
            {SESSION_COOKIE: value}, response_url=URL(self.url)
        )

    def clear_session(self) -> None:
        """Forget all portal cookies."""
        host = URL(self.url).host
        if host:
            self.session.cookie_jar.clear_domain(host)

    # -- login --------------------------------------------------------------

    async def login(self) -> bool:
        """Log in, including the 2FA step when the portal asks for it."""
        generation = self._generation
        async with self._lock:
            # Another caller logged in while we were waiting for the lock.
            if generation != self._generation and self.session_cookie():
                return True
            await self._login()
            self._generation += 1
            return True

    async def _login(self) -> None:
        now = time.time()
        self.guard.check(now)
        self.guard.record_attempt(now)
        try:
            await self._login_steps(started=datetime.now(UTC))
        except Exception:
            # Network errors count too: a verification mail may have been sent.
            self.guard.record_failure()
            raise

        self.guard.record_success()
        cookie = self.session_cookie()
        if cookie and self._on_login:
            self._on_login(cookie)

    async def _login_steps(self, started: datetime) -> None:
        self.clear_session()
        login_url = f"{self.url}/Login/Login"
        # Open the login page first, like a browser does. That sets the session
        # cookie and the load balancer cookie (SERVERID) the whole flow must
        # stick to; without it later steps can land on another backend.
        await self._hop("GET", login_url)

        data = {
            "emailField": self.email,
            "passwordField": self.password,
            "Login": "Log in",
        }
        status, location, _ = await self._hop(
            "POST", login_url, data=data, headers=self._form_headers(login_url)
        )
        if status != HTTP_FOUND or classify_location(location) is LoginStep.REJECTED:
            msg = "50five rejected the e-mail address or password"
            raise OtpAuthError(msg)

        # Follow the redirects one by one, exactly where the portal sends us.
        for _ in range(MAX_REDIRECTS):
            step = classify_location(location)
            if step is LoginStep.REJECTED:
                msg = "50five dropped the session after the password was accepted"
                raise OtpFlowError(msg)
            url = self._same_origin(location)
            status, location, html = await self._hop("GET", url)
            if step is LoginStep.TWO_FACTOR:
                if status != HTTPStatus.OK:
                    msg = (
                        "50five did not show the verification page "
                        f"(HTTP {status}); no verification mail was sent"
                    )
                    raise OtpFlowError(msg)
                await self._submit_code(url, html, started)
                return
            if status != HTTP_FOUND:
                return  # A normal page: logged in without 2FA.
        msg = "Too many redirects after the 50five login"
        raise OtpFlowError(msg)

    async def _submit_code(self, page_url: str, html: str, started: datetime) -> None:
        token = find_token(html)
        inputs = sorted(set(_INPUT_NAME_RE.findall(html)))
        self._trace_line(
            f"  form: token={'yes' if token else 'no'} inputs={','.join(inputs)}"
        )

        code = await self._code_provider(started)
        if not code:
            msg = "No 50five verification code arrived in the mailbox in time"
            raise OtpCodeTimeoutError(msg)

        action = _FORM_ACTION_RE.search(html)
        check_url = self._same_origin(action.group(1) if action else "/2fa_check")
        data = {"_auth_code": code, "VerifyOtp": "Verify"}
        if token:
            data["_token"] = token
        status, target, _ = await self._hop(
            "POST", check_url, data=data, headers=self._form_headers(page_url)
        )
        if status != HTTP_FOUND or classify_location(target) is not LoginStep.LOGGED_IN:
            msg = "50five rejected the verification code"
            raise OtpAuthError(msg)

    def _same_origin(self, target: str) -> str:
        """
        Turn a redirect target or form action into a URL on the portal itself.

        The portal redirects to absolute ``http://`` URLs. Following those
        literally drops the session cookie (it is ``secure``), so only the
        path and query are used, always on the https base URL.
        """
        url = URL(target)
        if url.is_absolute() and url.host != URL(self.url).host:
            msg = f"Unexpected redirect to another host ({url.host})"
            raise OtpFlowError(msg)
        return str(URL(self.url).join(URL(url.path_qs)))

    def _form_headers(self, referer: str) -> dict[str, str]:
        return {"Origin": self.url, "Referer": referer}

    async def _hop(self, method: str, url: str, **kwargs: Any) -> tuple[int, str, str]:
        """Do one request without following redirects; return status, Location, body."""
        async with self.session.request(
            method, url, allow_redirects=False, **kwargs
        ) as response:
            status = response.status
            location = response.headers.get("Location", "")
            body = await response.text() if status == HTTPStatus.OK else ""
            cookies = ",".join(sorted(response.cookies)) or "-"
        self._log(
            f"{method} {URL(url).path}", status, location, f"set-cookie={cookies}"
        )
        return status, location, body

    # -- requests -----------------------------------------------------------

    async def make_requests(self, requests: list[Request]) -> Any:
        """Make requests; on an expired session log in once and retry once."""
        if not self.session_cookie():
            await self.login()

        result = await self._request(requests)
        if requests and not result:
            _LOGGER.debug("50five session expired, logging in again")
            self.clear_session()
            await self.login()
            result = await self._request(requests)
        return result if result is not None else []

    async def _request(self, requests: list[Request]) -> Any:
        """Return the decoded answer, or ``None`` when the session is not valid."""
        params = {"requests": dumps(dict(enumerate([r.request for r in requests])))}
        # No redirects: an expired session is redirected to the (http://)
        # login page, which only tells us to log in again.
        async with self.session.get(
            self.api, params=params, allow_redirects=False
        ) as response:
            if response.status != HTTPStatus.OK:
                location = response.headers.get("Location", "")
                self._log("GET /api/ajax", response.status, location)
                return None
            try:
                return await response.json(content_type=None)
            except ValueError:
                self._log("GET /api/ajax", response.status, "not JSON")
                return None

    def _log(self, step: str, status: int, location: str, extra: str = "") -> None:
        """Log one HTTP step without query strings or secrets."""
        where = _path(location) if location.startswith(("http", "/")) else location
        self._trace_line(f"{step} -> {status} {where} {extra}".rstrip())

    def _trace_line(self, line: str) -> None:
        _LOGGER.debug(line)
        if self._trace:
            self._trace(line)
