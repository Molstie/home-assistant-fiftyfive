"""Tests for the 2FA login and the login guard, against a local fake portal."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from json import loads
from typing import TYPE_CHECKING, Any

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from fiftyfive import Channel, CustomerType, Market, NetworkOverview, Stop
from fiftyfive_fork.otp_api import (
    MAX_STRIKES,
    MIN_LOGIN_INTERVAL,
    LoginGuard,
    LoginStep,
    OtpApi,
    OtpAuthError,
    OtpCodeError,
    OtpCodeTimeoutError,
    OtpFlowError,
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
# The fake portal is a real local HTTP server.
pytestmark = pytest.mark.usefixtures("socket_enabled")

OVERVIEW = [[{"IDX": "1234727754", "NAME": "Laadpaal", "STATUS": "0"}]]


@dataclass
class Portal:
    """
    Fake 50five portal, modelled on what the real one did on 3 Oct 2026.

    ``GET /Login/Login`` hands out PHPSESSID and the load balancer cookie
    SERVERID. A request without SERVERID lands on "another backend" that does
    not know the session. The password POST redirects to /Overview, which
    redirects to /2fa while the code is still pending.
    """

    two_factor: bool = True
    password_ok: bool = True
    valid_code: str = "654321"
    expired_answer: str = "empty"  # or "login_page"
    ajax_broken: bool = False
    valid_sessions: set[str] = field(default_factory=set)
    pending: set[str] = field(default_factory=set)
    logins: int = 0
    code_posts: list[dict] = field(default_factory=list)
    two_fa_pages_shown: int = 0
    two_fa_page_bounces: bool = False
    redirect_base: str = ""  # set to the server's own absolute URL
    # Answer to an action (start/stop/block/unblock) on a valid session. What
    # the real portal sends is not known; it may well be falsy.
    action_answer: Any = field(default_factory=lambda: [{"result": "ok"}])
    ajax_calls: list[tuple[str | None, list[str]]] = field(default_factory=list)
    ajax_gates: dict[str, asyncio.Event] = field(default_factory=dict)
    _counter: int = 0

    def _to(self, path: str) -> str:
        """Redirect target: absolute http:// on the real host, like the portal."""
        return f"{self.redirect_base}{path}"

    def _session(self, request: web.Request) -> str | None:
        if request.cookies.get("SERVERID") != "b1":
            return None
        return request.cookies.get("PHPSESSID")

    async def login_page(self, _: web.Request) -> web.Response:
        """GET /Login/Login."""
        self._counter += 1
        response = web.Response(text="<html>login</html>", content_type="text/html")
        response.set_cookie("PHPSESSID", f"sess{self._counter}")
        response.set_cookie("SERVERID", "b1")
        return response

    async def login(self, request: web.Request) -> web.Response:
        """POST /Login/Login."""
        self.logins += 1
        form = await request.post()
        assert form["Login"] == "Log in"
        assert request.headers["Referer"].endswith("/Login/Login")
        sid = self._session(request)
        if not self.password_ok or sid is None:
            raise web.HTTPFound(location=self._to("/Login/Login"))
        (self.pending if self.two_factor else self.valid_sessions).add(sid)
        raise web.HTTPFound(location=self._to("/Overview"))

    async def overview(self, request: web.Request) -> web.Response:
        """GET /Overview."""
        sid = self._session(request)
        if sid in self.valid_sessions:
            return web.Response(text="<html>overview</html>", content_type="text/html")
        if sid in self.pending:
            raise web.HTTPFound(location=self._to("/2fa"))
        raise web.HTTPFound(location=self._to("/Login/Login"))

    async def two_fa_page(self, request: web.Request) -> web.Response:
        """GET /2fa: showing it sends the mail."""
        if self.two_fa_page_bounces or self._session(request) not in self.pending:
            raise web.HTTPFound(location=self._to("/Login/Login"))
        self.two_fa_pages_shown += 1
        return web.Response(text=TWO_FA_HTML, content_type="text/html")

    async def two_fa_check(self, request: web.Request) -> web.Response:
        """POST /2fa_check."""
        form = dict(await request.post())
        self.code_posts.append(form)
        sid = self._session(request)
        if (
            sid not in self.pending
            or form.get("_auth_code") != self.valid_code
            or form.get("_token") != "csrf-abc"
        ):
            raise web.HTTPFound(location=self._to("/2fa"))
        self.pending.discard(sid)
        self.valid_sessions.add(sid)
        raise web.HTTPFound(location=self._to("/"))

    async def ajax(self, request: web.Request) -> web.Response:
        """GET /api/ajax."""
        sid = request.cookies.get("PHPSESSID")
        methods = [r["method"] for r in loads(request.query["requests"]).values()]
        self.ajax_calls.append((sid, methods))
        if sid is not None and sid in self.ajax_gates:
            # Hold this answer back until the test releases it: a request that
            # is still in flight while another caller logs in.
            await self.ajax_gates.pop(sid).wait()
        if sid in self.valid_sessions and not self.ajax_broken:
            if "action" in methods:
                return web.json_response(self.action_answer, content_type="text/html")
            return web.json_response(OVERVIEW, content_type="text/html")
        if self.expired_answer == "login_page":
            raise web.HTTPFound(location=self._to("/Login/Login"))
        return web.json_response([], content_type="text/html")


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


class SlowCodes(Codes):
    """Mailbox that only hands out a code when the test says so."""

    def __init__(self, *codes: str | None) -> None:
        """Initialize."""
        super().__init__(*codes)
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self, started: datetime) -> str | None:
        """Signal that the login waits for the mail, then wait for the test."""
        self.waiting.set()
        await self.release.wait()
        return await super().__call__(started)


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
    app.router.add_get("/Overview", portal.overview)
    app.router.add_get("/2fa", portal.two_fa_page)
    app.router.add_post("/2fa_check", portal.two_fa_check)
    app.router.add_get("/api/ajax", portal.ajax)
    async with TestServer(app) as server:
        url = str(server.make_url("")).rstrip("/")
        portal.redirect_base = portal.redirect_base or url
        yield url


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
    logins: list[dict[str, str]] | None = None,
) -> OtpApi:
    """Build an OtpApi pointed at the fake portal."""
    api = OtpApi(
        session=session,
        email="user@example.com",
        password="secret",
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


async def test_http_redirect_stays_on_https(session: aiohttp.ClientSession) -> None:
    """The portal redirects to http://; follow on https, path only (3 Oct 2026)."""
    api = make_api(session, "https://50five-snl.evc-net.com", Codes())

    assert (
        api._same_origin("http://50five-snl.evc-net.com/Overview")  # noqa: SLF001
        == "https://50five-snl.evc-net.com/Overview"
    )
    assert (
        api._same_origin("/2fa?x=1")  # noqa: SLF001
        == "https://50five-snl.evc-net.com/2fa?x=1"
    )
    with pytest.raises(OtpFlowError):
        api._same_origin("https://evil.example.com/2fa")  # noqa: SLF001


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
    logins: list[dict[str, str]] = []
    api = make_api(session, base_url, codes, logins=logins)

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert len(codes.calls) == 1
    assert portal.code_posts == [
        {"_auth_code": "654321", "VerifyOtp": "Verify", "_token": "csrf-abc"}
    ]
    assert logins == [{"PHPSESSID": "sess1", "SERVERID": "b1"}]
    assert api.guard.strikes == 0


async def test_2fa_page_falls_back_to_login(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """If /2fa bounces to the login page: stop, no code is asked or sent."""
    portal.two_fa_page_bounces = True
    codes = Codes("654321")
    api = make_api(session, base_url, codes)

    with pytest.raises(OtpFlowError):
        await api.login()

    assert codes.calls == []
    assert portal.code_posts == []
    assert api.guard.strikes == 1


async def test_cookies_stick_through_the_whole_flow(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """Session and SERVERID cookies from the login page are used throughout."""
    api = make_api(session, base_url, Codes("654321"))

    await api.login()

    assert portal.two_fa_pages_shown == 1
    assert api.session_cookie() in portal.valid_sessions


async def test_redirect_to_other_host_is_refused(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """A redirect to another host is never followed."""
    codes = Codes("654321")
    api = make_api(session, base_url, codes)
    portal.redirect_base = "https://evil.example.com"

    with pytest.raises(OtpFlowError):
        await api.login()

    assert codes.calls == []


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

    with pytest.raises(OtpCodeError):
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
    api.restore_cookies({"PHPSESSID": "saved", "SERVERID": "b1"})

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert portal.logins == 0


@pytest.mark.parametrize("expired_answer", ["empty", "login_page"])
async def test_expired_session_logs_in_once_and_retries(
    session: aiohttp.ClientSession, base_url: str, portal: Portal, expired_answer: str
) -> None:
    """An empty answer or the login page means expired: log in once, retry once."""
    portal.expired_answer = expired_answer
    api = make_api(session, base_url, Codes("654321"))
    api.restore_cookies({"PHPSESSID": "stale"})

    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    assert portal.logins == 1


async def test_still_empty_after_relogin_returns_empty(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """No loop: if the portal keeps answering empty, return after one retry."""
    portal.two_factor = False
    portal.ajax_broken = True
    api = make_api(session, base_url, Codes())
    api.restore_cookies({"PHPSESSID": "stale"})

    assert await api.make_requests([NetworkOverview()]) == []
    assert portal.logins == 1


# -- concurrent callers (4 Oct 2026) ------------------------------------------
#
# Home Assistant calls the client from several places at once: the coordinator
# (every 5 s while the charger reports a session) and the services and buttons
# (start, stop, block, unblock). On 4 Oct the live integration showed three
# patterns, all with the automatic OTP login:
#
#   12:05:12  button: "50five rejected the verification code", and on the same
#             millisecond the coordinator: "Next 50five login allowed in 888 s"
#   12:20 and 13:23  a login succeeds (code mail sent), and 16 s later the next
#             call needs a new login: "Next 50five login allowed in 884 s";
#             two minutes later the coordinator fails the same way
#
# The tests below reproduce each pattern against the fake portal.

STOP = Stop(channel=Channel(recharge_spot_id="1234727754", channel_id="1"))


async def test_waiter_gets_the_outcome_of_the_running_login(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """
    Gap 1: a caller that waits for a running login shares its outcome.

    Before the fix the waiter got the lock after the failed login and tried
    itself, which the guard blocked: OtpThrottledError instead of the real
    cause (12:05:12, coordinator next to the button).
    """
    codes = SlowCodes("000000")  # 50five rejects this code
    api = make_api(session, base_url, codes)

    first = asyncio.create_task(api.login())
    await codes.waiting.wait()
    second = asyncio.create_task(api.login())
    await asyncio.sleep(0)
    codes.release.set()

    results = await asyncio.gather(first, second, return_exceptions=True)

    assert [type(r) for r in results] == [OtpCodeError, OtpCodeError]
    assert portal.logins == 1
    assert len(portal.code_posts) == 1
    assert api.guard.strikes == 1


async def test_request_during_login_does_not_break_it(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """
    Gap 2a: a request while a login waits for the code leaves that login alone.

    The login has already set a fresh PHPSESSID that is not verified yet. A
    second caller saw that cookie, got the "expired" answer and cleared the
    jar outside the lock; the code was then posted without a session and
    50five rejected it (12:05 and 12:35). The second caller then hit the
    guard.
    """
    codes = SlowCodes("654321")
    api = make_api(session, base_url, codes)

    button = asyncio.create_task(api.make_requests([STOP]))
    await codes.waiting.wait()
    coordinator = asyncio.create_task(api.make_requests([NetworkOverview()]))
    # Let the coordinator's request go out and come back while the login
    # still waits for the mail.
    for _ in range(50):
        await asyncio.sleep(0.01)
        if len(portal.ajax_calls) >= 1:
            break
    codes.release.set()

    assert await button == [{"result": "ok"}]
    assert await coordinator == OVERVIEW
    assert portal.logins == 1
    assert len(portal.code_posts) == 1
    assert api.guard.strikes == 0
    assert api.session_cookie() in portal.valid_sessions


async def test_late_expired_answer_does_not_wipe_the_new_session(
    session: aiohttp.ClientSession, base_url: str, portal: Portal
) -> None:
    """
    Gap 2b: an "expired" answer for an old cookie must not clear a newer one.

    The coordinator's request left with the old cookie; meanwhile a service
    call logged in. When the old answer came back the coordinator cleared the
    jar, so the next call had no cookie, needed a login and hit the guard -
    16 s after a successful login (12:20, 13:23), and the coordinator itself
    failed too.
    """
    api = make_api(session, base_url, Codes("654321"))
    api.restore_cookies({"PHPSESSID": "stale", "SERVERID": "b1"})
    gate = asyncio.Event()
    portal.ajax_gates["stale"] = gate

    coordinator = asyncio.create_task(api.make_requests([NetworkOverview()]))
    for _ in range(50):
        await asyncio.sleep(0.01)
        if portal.ajax_calls:
            break
    # The service call: its own request with the old cookie is answered
    # "expired" at once, it logs in and its retry succeeds.
    assert await api.make_requests([STOP]) == [{"result": "ok"}]
    fresh = api.session_cookie()
    assert fresh in portal.valid_sessions

    gate.set()  # now the coordinator's old answer arrives
    assert await coordinator == OVERVIEW
    assert api.session_cookie() == fresh

    # The next command goes straight through on the same session.
    assert await api.make_requests([STOP]) == [{"result": "ok"}]
    assert portal.logins == 1
    assert api.guard.strikes == 0


@pytest.mark.parametrize("answer", [[], None, False, {}])
async def test_empty_answer_to_a_command_is_not_an_expired_session(
    session: aiohttp.ClientSession, base_url: str, portal: Portal, answer: Any
) -> None:
    """
    Gap 3: a valid but empty answer to a command does not mean "log in again".

    Every falsy answer was treated as an expired session: clear the jar, log
    in, and with a login less than 15 minutes old that is OtpThrottledError -
    on a session that was fine. Only a redirect, a non-JSON answer, or an
    empty answer while a check request is empty too, means expired.
    """
    api = make_api(session, base_url, Codes("654321"))
    assert await api.make_requests([NetworkOverview()]) == OVERVIEW
    cookie = api.session_cookie()
    portal.action_answer = answer

    assert await api.make_requests([STOP]) == ([] if answer is None else answer)
    assert api.session_cookie() == cookie
    assert portal.logins == 1
