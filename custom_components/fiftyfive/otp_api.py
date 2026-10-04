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

from fiftyfive import Api, CustomerType, Market, NetworkOverview

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

# What ``_request`` returns for a redirect or a non-JSON answer: the session
# is not valid. Distinct from ``None``, which is a valid JSON ``null``.
_EXPIRED = object()

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
    """The portal rejected the e-mail address or password."""


class OtpCodeError(OtpLoginError):
    """The portal rejected the verification code."""


class OtpCodeTimeoutError(OtpCodeError):
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


def _retrieve_exception(task: asyncio.Task[None]) -> None:
    """Mark a failed login as seen, also when every waiter was cancelled."""
    if not task.cancelled():
        task.exception()


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
        on_login: Callable[[dict[str, str]], None] | None = None,
        trace: Callable[[str], None] | None = None,
    ) -> None:
        """
        Initialize.

        ``code_provider`` gets the moment the login started and returns the
        code from the mailbox, or ``None`` when none arrived in time.
        ``on_login`` gets the portal cookies after a successful login, so they
        can be saved and restored with ``restore_cookies`` after a restart.
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
        # One login at a time. The lock guards starting it; the task is what
        # callers that arrive during a login wait for, so they all get its
        # outcome (4 Oct 2026, see login()).
        self._lock = asyncio.Lock()
        self._login_task: asyncio.Task[None] | None = None

    # -- session cookie -----------------------------------------------------

    def session_cookie(self) -> str | None:
        """Return the current portal session cookie, if any."""
        cookie = self.session.cookie_jar.filter_cookies(URL(self.url)).get(
            SESSION_COOKIE
        )
        return cookie.value if cookie else None

    def portal_cookies(self) -> dict[str, str]:
        """Return all portal cookies (session and load balancer)."""
        return {
            name: morsel.value
            for name, morsel in self.session.cookie_jar.filter_cookies(
                URL(self.url)
            ).items()
        }

    def restore_cookies(self, cookies: dict[str, str]) -> None:
        """Put previously saved portal cookies back into the jar."""
        if cookies:
            self.session.cookie_jar.update_cookies(cookies, response_url=URL(self.url))

    def clear_session(self) -> None:
        """Forget all portal cookies."""
        host = URL(self.url).host
        if host:
            self.session.cookie_jar.clear_domain(host)

    # -- login --------------------------------------------------------------

    async def login(self) -> bool:
        """
        Log in, including the 2FA step when the portal asks for it.

        At most one login runs at a time. A caller that arrives while one is
        running does not start its own: it waits for the running one and gets
        the same outcome, success or the same exception. Before, a waiter
        started its own login after a failed one, the guard refused it, and
        the waiter reported OtpThrottledError instead of the real cause.

        The login itself runs as a shielded task, so a caller that is
        cancelled (a service call timing out) does not abort it for the
        others.
        """
        async with self._lock:
            task = self._login_task
            if task is None or task.done():
                task = asyncio.create_task(self._login())
                task.add_done_callback(_retrieve_exception)
                self._login_task = task
        await asyncio.shield(task)
        return True

    def _login_running(self) -> bool:
        return self._login_task is not None and not self._login_task.done()

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
        if self._on_login and self.session_cookie():
            self._on_login(self.portal_cookies())

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
            raise OtpCodeError(msg)

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
        """
        Make requests; on an expired session log in once and retry once.

        Home Assistant calls this from several places at once: the coordinator
        (every 5 s while the charger reports a session) next to services and
        buttons. Three rules keep those callers from breaking each other's
        session (4 Oct 2026):

        - No request while a login is running: join the login instead. A
          request with the fresh, not yet verified cookie only confuses the
          portal and comes back "expired".
        - Never clear the cookie jar here. Only the login clears it, and only
          one login runs at a time. An "expired" answer for an older cookie
          than the current one is retried on the current session, without a
          login.
        - An empty answer alone does not mean "expired": a command may answer
          empty. Only a redirect or a non-JSON answer does, or an empty answer
          while a check request on the same session is empty too.
        """
        if self._login_running() or not self.session_cookie():
            await self.login()

        cookie = self.session_cookie()
        result = await self._request(requests)
        if requests and await self._expired(result, cookie):
            _LOGGER.debug("50five session expired, logging in again")
            await self._renew(cookie)
            result = await self._request(requests)
        return [] if result is None or result is _EXPIRED else result

    async def _expired(self, result: Any, cookie: str | None) -> bool:
        """Return whether ``result``, answered for ``cookie``, means expired."""
        if result is _EXPIRED:
            return True
        if result:
            return False
        if self._login_running() or self.session_cookie() != cookie:
            # The answer belongs to a session that is being or has been
            # replaced; the retry runs on the new one.
            return True
        check = await self._request([NetworkOverview()])
        return check is _EXPIRED or not check

    async def _renew(self, stale: str | None) -> None:
        """
        Get a working session after an expired answer for the cookie ``stale``.

        Join a running login; use a session another caller set up while our
        request was under way; only log in when the jar still holds ``stale``.
        """
        current = self.session_cookie()
        if not self._login_running() and current and current != stale:
            return
        await self.login()

    async def _request(self, requests: list[Request]) -> Any:
        """Return the decoded answer, or ``_EXPIRED`` when the portal redirects."""
        params = {"requests": dumps(dict(enumerate([r.request for r in requests])))}
        # No redirects: an expired session is redirected to the (http://)
        # login page, which only tells us to log in again.
        async with self.session.get(
            self.api, params=params, allow_redirects=False
        ) as response:
            if response.status != HTTPStatus.OK:
                location = response.headers.get("Location", "")
                self._log("GET /api/ajax", response.status, location)
                return _EXPIRED
            try:
                return await response.json(content_type=None)
            except ValueError:
                self._log("GET /api/ajax", response.status, "not JSON")
                return _EXPIRED

    def _log(self, step: str, status: int, location: str, extra: str = "") -> None:
        """Log one HTTP step without query strings or secrets."""
        where = _path(location) if location.startswith(("http", "/")) else location
        self._trace_line(f"{step} -> {status} {where} {extra}".rstrip())

    def _trace_line(self, line: str) -> None:
        _LOGGER.debug(line)
        if self._trace:
            self._trace(line)
