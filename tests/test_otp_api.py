"""Tests for the 2FA login and the login guard, against a local fake portal."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from fiftyfive import CustomerType, Market, NetworkOverview
from fiftyfive_fork.otp_api import (
    MAX_STRIKES,
    MIN_LOGIN_INTERVAL,
    LoginGuard,
    LoginStep,
    OtpApi,
    OtpAuthError,
    OtpCodeTimeoutError,
    OtpLockedError,
    OtpThrottledError,
    classify_location,
    find_token,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from datetime import datetime

TWO_FA_HTML = """
<form method="post" action="/2fa_check">
  <input type="hidden" name="_token" value="csrf-abc">
  <input type="text" name="_auth_code">
  <input type="submit" name="VerifyOtp" value="Verify">
</form>
"""
OVERVIEW = [[{"IDX": "1234727754", "NAME": "Laadpaal", "STATUS": "0"}]]


@dataclass
class Portal:
    """
    Fake 50five portal.

    ``two_factor``: the password step redirects to /2fa (or via / when
    ``via_start_page``). ``valid_sessions`` are the session ids the API accepts.
    """

    two_factor: bool = True
    via_start_page: bool = False
    password_ok: bool = True
    valid_code: str = "654321"
    expired_answer: str = "empty"  # or "login_page"
    ajax_broken: bool = False
    valid_sessions: set[str] = field(default_factory=set)
    logins: int = 0
    code_posts: list[dict] = field(default_factory=list)
    _counter: int = 0

    def _new_session(self) -> str:
        self._counter += 1
        return f"sess{self._counter}"

    async def login(self, request: web.Request) -> web.Response:
        """POST /Login/Login."""
        self.logins += 1
        form = await request.post()
        assert form["Login"] == "Log in"
        sid = self._new_session()
        if not self.password_ok:
            target = "/Login/Login"
        elif self.two_factor and not self.via_start_page:
            target = "/2fa"
        else:
            target = "/"
            if not self.two_factor:
                self.valid_sessions.add(sid)
        response = web.HTTPFound(target)
        response.set_cookie("PHPSESSID", sid)
        raise response

    async def start(self, request: web.Request) -> web.Response:
        """GET /."""
        sid = request.cookies.get("PHPSESSID", "")
        if sid in self.valid_sessions:
            raise web.HTTPFound(location="/Overview")
        raise web.HTTPFound(location="/2fa" if self.two_factor else "/Login/Login")

    async def two_fa_page(self, _: web.Request) -> web.Response:
        """GET /2fa."""
        return web.Response(text=TWO_FA_HTML, content_type="text/html")

    async def two_fa_check(self, request: web.Request) -> web.Response:
        """POST /2fa_check."""
        form = dict(await request.post())
        self.code_posts.append(form)
        if (
            form.get("_auth_code") != self.valid_code
            or form.get("_token") != "csrf-abc"
        ):
            raise web.HTTPFound(location="/2fa")
        self.valid_sessions.add(request.cookies["PHPSESSID"])
        raise web.HTTPFound(location="/")

    async def ajax(self, request: web.Request) -> web.Response:
        """GET /api/ajax."""
        sid = request.cookies.get("PHPSESSID")
        if sid in self.valid_sessions and not self.ajax_broken:
            return web.json_response(OVERVIEW, content_type="text/html")
        if self.expired_answer == "login_page":
            raise web.HTTPFound(location="/Login/Login")
        return web.json_response([], content_type="text/html")

    async def login_page(self, _: web.Request) -> web.Response:
        """GET /Login/Login."""
        return web.Response(text="<html>login</html>", content_type="text/html")


class Codes:
    """Fake mailbox: hands out queued codes and records calls."""

    def __init__(self, *codes: str | None) -> None:
        """Initialize."""
        self.codes = list(codes)
        self.calls: list[datetime] = []

    async def __call__(self, started: datetime) -> str | None:
        """Return the next code."""
        self.calls.append(started)
        return self.codes.pop(0) if self.codes else None


@pytest.fixture
def portal() -> Portal:
    """Return the fake portal state."""
    return Portal()


@pytest.fixture
async def base_url(portal: Portal) -> AsyncIterator[str]:
    """Run the fake portal and return its URL."""
    app = web.Application()
    app.router.add_post("/Login/Login", portal.login)
    app.router.add_get("/Login/Login", portal.login_page)
    app.router.add_get("/", portal.start)
    app.router.add_get("/2fa", portal.two_fa_page)
    app.router.add_post("/2fa_check", portal.two_fa_check)
    app.router.add_get("/api/ajax", portal.ajax)
    async with TestServer(app) as server:
        yield str(server.make_url("")).rstrip("/")


@pytest.fixture
async def session() -> AsyncIterator[aiohttp.ClientSession]:
    """Return a client session; unsafe=True allows cookies for 127.0.0.1."""
    async with aiohttp.ClientSession(
        cookie_jar=aiohttp.CookieJar(unsafe=True)
    ) as client:
        yield client


def make_api(
    session: aiohttp.ClientSession,
    base_url: str,
    codes: Codes,
    guard: LoginGuard | None = None,
    logins: list[str] | None = None,
) -> OtpApi:
    """Build an OtpApi pointed at the fake portal."""
    api = OtpApi(
        session=session,
        email="user@example.com",
        password="secret",  # noqa: S106
        market=Market.NL,
        customer_type=CustomerType.FORMER_SHELL,
        code_provider=codes,
        guard=guard or LoginGuard(),
        on_login=logins.append if logins is not None else None,
    )
    api.url = base_url
    api.api = f"{base_url}/api/ajax"
    return api


def test_classify_location() -> None:
    """Redirect targets are classified on their path."""
    assert classify_location("/2fa") is LoginStep.TWO_FACTOR
    assert classify_location("https://x.evc-net.com/2fa?a=1") is LoginStep.TWO_FACTOR
    assert classify_location("/Login/Login") is LoginStep.REJECTED
    assert classify_location("/") is LoginStep.LOGGED_IN
    assert classify_location("/Overview") is LoginStep.LOGGED_IN


def test_find_token() -> None:
    """The CSRF token is found in either attribute order."""
    assert find_token(TWO_FA_HTML) == "csrf-abc"
    assert find_token('<input value="t2" type="hidden" name="_token">') == "t2"
    assert find_token("<form></form>") is None


async def test_login_without_2fa(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """No 2FA: the mailbox is never touched."""
    portal.two_factor = False
    codes = Codes("123456")
    api = make_api(session, base_url, codes)

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert codes.calls == []
    assert api.guard.strikes == 0


async def test_login_with_2fa(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """2FA: token and code are posted once; the new session is reported."""
    codes = Codes("654321")
    logins: list[str] = []
    api = make_api(session, base_url, codes, logins=logins)

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert len(codes.calls) == 1
    assert portal.code_posts == [
        {"_auth_code": "654321", "VerifyOtp": "Verify", "_token": "csrf-abc"}
    ]
    assert logins == ["sess1"]
    assert api.guard.strikes == 0


async def test_2fa_detected_via_start_page(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """A login redirect to / that then lands on /2fa still triggers 2FA."""
    portal.via_start_page = True
    codes = Codes("654321")
    api = make_api(session, base_url, codes)

    await api.login()

    assert len(codes.calls) == 1
    assert api.session_cookie() in portal.valid_sessions


async def test_password_rejected(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """A redirect back to the login page is a real auth error and a strike."""
    portal.password_ok = False
    codes = Codes("654321")
    api = make_api(session, base_url, codes)

    with pytest.raises(OtpAuthError):
        await api.login()

    assert codes.calls == []
    assert api.guard.strikes == 1


async def test_wrong_or_old_code(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """A rejected code is a strike; it is submitted exactly once."""
    api = make_api(session, base_url, Codes("000000"))

    with pytest.raises(OtpAuthError):
        await api.login()

    assert len(portal.code_posts) == 1
    assert api.guard.strikes == 1


async def test_no_mail_in_time(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """No code in the mailbox: nothing is submitted, one strike."""
    api = make_api(session, base_url, Codes(None))

    with pytest.raises(OtpCodeTimeoutError):
        await api.login()

    assert portal.code_posts == []
    assert api.guard.strikes == 1


async def test_throttle_blocks_second_login(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """A second login within 15 minutes makes no HTTP request at all."""
    portal.password_ok = False
    api = make_api(session, base_url, Codes())

    with pytest.raises(OtpAuthError):
        await api.login()
    with pytest.raises(OtpThrottledError):
        await api.login()

    assert portal.logins == 1


async def test_locked_guard_makes_no_request(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """After three strikes nothing is sent, also not after the interval."""
    api = make_api(session, base_url, Codes(), guard=LoginGuard(strikes=MAX_STRIKES))

    with pytest.raises(OtpLockedError):
        await api.make_requests([NetworkOverview()])

    assert portal.logins == 0


def test_guard_locks_after_three_strikes() -> None:
    """Three failures in a row stop all logins, even long after."""
    guard = LoginGuard(strikes=MAX_STRIKES)
    with pytest.raises(OtpLockedError):
        guard.check(time.time() + 10 * MIN_LOGIN_INTERVAL)


def test_guard_interval_and_persistence() -> None:
    """The interval is enforced and every change is reported."""
    changes: list[dict] = []
    guard = LoginGuard()
    guard.on_change = lambda: changes.append(guard.as_dict())

    guard.check(1000.0)
    guard.record_attempt(1000.0)
    with pytest.raises(OtpThrottledError):
        guard.check(1000.0 + MIN_LOGIN_INTERVAL - 1)
    guard.check(1000.0 + MIN_LOGIN_INTERVAL)
    guard.record_failure()
    guard.record_success()

    assert changes == [
        {"last_attempt": 1000.0, "strikes": 0},
        {"last_attempt": 1000.0, "strikes": 1},
        {"last_attempt": 1000.0, "strikes": 0},
    ]


async def test_saved_cookie_is_used_without_login(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """With a valid saved session no login happens."""
    portal.valid_sessions.add("saved")
    api = make_api(session, base_url, Codes())
    api.restore_session_cookie("saved")

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert portal.logins == 0


@pytest.mark.parametrize("expired_answer", ["empty", "login_page"])
async def test_expired_session_logs_in_once_and_retries(
    session: aiohttp.ClientSession, base_url: str, portal: Portal, expired_answer: str
) -> None:
    """An empty answer or the login page means expired: log in once, retry once."""
    portal.expired_answer = expired_answer
    api = make_api(session, base_url, Codes("654321"))
    api.restore_session_cookie("stale")

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert portal.logins == 1


async def test_still_empty_after_relogin_returns_empty(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """No loop: if the portal keeps answering empty, return after one retry."""
    portal.two_factor = False
    portal.ajax_broken = True
    api = make_api(session, base_url, Codes())
    api.restore_session_cookie("stale")

    assert await api.make_requests([NetworkOverview()]) == []
    assert portal.logins == 1
