"""Tests for reading the verification code from IMAP."""

from __future__ import annotations

import imaplib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import ClassVar, Self

import pytest
from fiftyfive_fork import imap_otp
from fiftyfive_fork.imap_otp import ImapOtpError, ImapSettings, find_code

SETTINGS = ImapSettings(
    host="imap.example.com",
    port=993,
    username="me@example.com",
    password="app-password",  # noqa: S106
    folder="50five-codes",
)
NOW = datetime(2026, 10, 3, 16, 51, 23, tzinfo=UTC)


def mail(
    code: str, subject: str = "Uw verificatiecode", *, html: bool = False
) -> bytes:
    """Build a 50five verification mail."""
    msg = EmailMessage()
    msg["From"] = "noreply@lastmilesolutions.com"
    msg["Subject"] = subject
    text = (
        f"Beste Martin, Uw verificatiecode is: {code}. Deze code is 10 minuten geldig."
    )
    if html:
        msg.set_content(
            f"<p>Uw verificatiecode is:&nbsp;<strong>{code}</strong>.</p>",
            subtype="html",
        )
    else:
        msg.set_content(text)
    return msg.as_bytes()


class FakeImap:
    """Minimal stand-in for imaplib.IMAP4_SSL."""

    instances: ClassVar[list[FakeImap]] = []
    messages: ClassVar[dict[bytes, tuple[datetime, bytes]]] = {}
    fail_login = False

    def __init__(self, host: str, port: int, timeout: int) -> None:
        """Record the connection."""
        self.host, self.port, self.timeout = host, port, timeout
        self.selected: str | None = None
        self.stored: list[bytes] = []
        self.searches: list[tuple] = []
        FakeImap.instances.append(self)

    def __enter__(self) -> Self:
        """Enter."""
        return self

    def __exit__(self, *args: object) -> None:
        """Exit."""

    def login(self, user: str, password: str) -> None:
        """Log in or fail."""
        if FakeImap.fail_login:
            msg = "[AUTHENTICATIONFAILED] Invalid credentials"
            raise imaplib.IMAP4.error(msg)
        assert (user, password) == (SETTINGS.username, SETTINGS.password)

    def select(self, folder: str) -> tuple[str, list]:
        """Select a folder."""
        self.selected = folder
        return ("OK", [b"1"]) if folder == '"50five-codes"' else ("NO", [b"no"])

    def uid(self, command: str, *args: object) -> tuple[str, list]:
        """Handle SEARCH, FETCH and STORE."""
        if command == "SEARCH":
            self.searches.append(args)
            return "OK", [b" ".join(FakeImap.messages)]
        if command == "FETCH":
            received, raw = FakeImap.messages[args[0]]
            stamp = imaplib.Time2Internaldate(received.timestamp())
            return "OK", [
                (f"1 (UID 1 INTERNALDATE {stamp} BODY[] {{1}}".encode(), raw),
                b")",
            ]
        if command == "STORE":
            self.stored.append(args[0])
            return "OK", []
        raise AssertionError(command)


@pytest.fixture(autouse=True)
def fake_imap(monkeypatch: pytest.MonkeyPatch) -> type[FakeImap]:
    """Replace IMAP4_SSL."""
    FakeImap.instances = []
    FakeImap.messages = {}
    FakeImap.fail_login = False
    monkeypatch.setattr(imap_otp.imaplib, "IMAP4_SSL", FakeImap)
    return FakeImap


def test_newest_recent_code_is_used_and_marked_seen() -> None:
    """The newest mail after the login moment wins and is marked as read."""
    FakeImap.messages = {
        b"1": (NOW - timedelta(days=7), mail("185442")),
        b"2": (NOW + timedelta(seconds=20), mail("738667")),
        b"3": (NOW + timedelta(seconds=5), mail("111111")),
    }

    found = find_code(SETTINGS, NOW)

    assert found is not None
    assert found.code == "738667"
    assert FakeImap.instances[0].stored == [b"2"]
    search = FakeImap.instances[0].searches[0]
    assert search[:3] == (None, "FROM", '"noreply@lastmilesolutions.com"')


def test_old_code_is_ignored() -> None:
    """A code from before the login attempt (beyond the margin) is never used."""
    FakeImap.messages = {b"1": (NOW - timedelta(minutes=5), mail("185442"))}

    assert find_code(SETTINGS, NOW) is None


def test_margin_accepts_slight_clock_difference() -> None:
    """A mail stamped a few seconds before the attempt is still accepted."""
    FakeImap.messages = {b"1": (NOW - timedelta(seconds=10), mail("185442"))}

    found = find_code(SETTINGS, NOW, mark_seen=False)

    assert found is not None
    assert FakeImap.instances[0].stored == []


def test_other_subject_is_ignored() -> None:
    """Other mails from the same sender (invoices) are skipped."""
    FakeImap.messages = {
        b"1": (
            NOW + timedelta(seconds=5),
            mail("123456", subject="Uw terugbetalingsdocument"),
        )
    }

    assert find_code(SETTINGS, NOW) is None


def test_html_body() -> None:
    """The code is found in an HTML-only mail."""
    FakeImap.messages = {b"1": (NOW + timedelta(seconds=5), mail("424242", html=True))}

    found = find_code(SETTINGS, NOW)

    assert found is not None
    assert found.code == "424242"


def test_excluded_uid_is_skipped() -> None:
    """A mail already used is not handed out twice."""
    FakeImap.messages = {b"1": (NOW + timedelta(seconds=5), mail("424242"))}

    assert find_code(SETTINGS, NOW, exclude_uids=frozenset({b"1"})) is None


def test_login_failure_raises_without_password_in_message() -> None:
    """A failed IMAP login raises ImapOtpError and does not leak the password."""
    FakeImap.fail_login = True

    with pytest.raises(ImapOtpError) as info:
        find_code(SETTINGS, NOW)

    assert SETTINGS.password not in str(info.value)


def test_missing_folder_raises() -> None:
    """A folder that does not exist is an error, not 'no mail'."""
    settings = ImapSettings(**{**SETTINGS.__dict__, "folder": "bestaat-niet"})

    with pytest.raises(ImapOtpError):
        find_code(settings, NOW)
