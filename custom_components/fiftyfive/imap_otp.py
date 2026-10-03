"""
Read the 50five e-mail verification code from an IMAP mailbox.

This module only uses the standard library and has no Home Assistant
dependencies, so ``tools/test_login.py`` can use it outside Home Assistant.
All functions are blocking; call them from an executor.
"""

from __future__ import annotations

import email
import imaplib
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.header import decode_header, make_header
from html import unescape

DEFAULT_IMAP_HOST = "imap.gmail.com"
DEFAULT_IMAP_PORT = 993
DEFAULT_IMAP_FOLDER = "INBOX"
DEFAULT_IMAP_SENDER = "noreply@lastmilesolutions.com"

SUBJECT_KEYWORD = "verificatiecode"
CODE_RE = re.compile(r"verificatiecode is:[\s\xa0]*(\d{6})", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

# Accept mails that arrived up to this long before the login attempt, to absorb
# clock differences between Home Assistant and the mail server.
RECEIVE_MARGIN = timedelta(seconds=30)
IMAP_TIMEOUT = 30


class ImapOtpError(Exception):
    """Raised when the mailbox cannot be read (login, folder, network)."""


class ImapFolderError(ImapOtpError):
    """Raised when the configured folder does not exist."""


@dataclass(frozen=True)
class ImapSettings:
    """Connection settings for the mailbox that receives the codes."""

    host: str
    port: int
    username: str
    password: str
    folder: str = DEFAULT_IMAP_FOLDER
    sender: str = DEFAULT_IMAP_SENDER


@dataclass(frozen=True)
class FoundCode:
    """A verification code found in the mailbox."""

    code: str
    received: datetime
    uid: bytes


def _quote_folder(folder: str) -> str:
    """Quote a folder name for IMAP (labels may contain spaces or slashes)."""
    escaped = folder.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _message_text(msg: email.message.Message) -> str:
    """Return all text/plain and text/html parts as one plain string."""
    texts: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if part.get_content_subtype() == "html":
            text = unescape(TAG_RE.sub(" ", text))
        texts.append(text)
    return "\n".join(texts)


def extract_code(msg: email.message.Message) -> str | None:
    """Return the six digit code from a 50five verification mail, if any."""
    subject = str(make_header(decode_header(msg.get("Subject", ""))))
    if SUBJECT_KEYWORD not in subject.lower():
        return None
    match = CODE_RE.search(_message_text(msg))
    return match.group(1) if match else None


def check_mailbox(settings: ImapSettings) -> None:
    """Log in and open the folder; raise ImapOtpError when that fails."""
    try:
        with imaplib.IMAP4_SSL(
            settings.host, settings.port, timeout=IMAP_TIMEOUT
        ) as imap:
            imap.login(settings.username, settings.password)
            status, _ = imap.select(_quote_folder(settings.folder), readonly=True)
    except (imaplib.IMAP4.error, OSError) as exception:
        msg = f"IMAP error: {type(exception).__name__}"
        raise ImapOtpError(msg) from exception
    if status != "OK":
        msg = f"Cannot open IMAP folder {settings.folder!r}"
        raise ImapFolderError(msg)


def find_code(
    settings: ImapSettings,
    not_before: datetime,
    *,
    mark_seen: bool = True,
    exclude_uids: frozenset[bytes] = frozenset(),
) -> FoundCode | None:
    """
    Return the newest code that arrived at or after ``not_before`` (minus margin).

    ``not_before`` must be timezone aware. Mails are matched on sender, subject
    and the server's receive time (INTERNALDATE), never on the Date header.
    """
    threshold = not_before - RECEIVE_MARGIN
    try:
        with imaplib.IMAP4_SSL(
            settings.host, settings.port, timeout=IMAP_TIMEOUT
        ) as imap:
            imap.login(settings.username, settings.password)
            status, _ = imap.select(_quote_folder(settings.folder))
            if status != "OK":
                msg = f"Cannot open IMAP folder {settings.folder!r}"
                raise ImapFolderError(msg)

            # SINCE only has day granularity; the exact check is done below.
            since = (threshold - timedelta(days=1)).strftime("%d-%b-%Y")
            status, data = imap.uid(
                "SEARCH", None, "FROM", f'"{settings.sender}"', "SINCE", since
            )
            if status != "OK" or not data or not data[0]:
                return None

            best: FoundCode | None = None
            for uid in data[0].split():
                if uid in exclude_uids:
                    continue
                found = _fetch_code(imap, uid, threshold)
                if found and (best is None or found.received > best.received):
                    best = found

            if best and mark_seen:
                imap.uid("STORE", best.uid, "+FLAGS", "(\\Seen)")
            return best
    except (imaplib.IMAP4.error, OSError) as exception:
        msg = f"IMAP error: {type(exception).__name__}"
        raise ImapOtpError(msg) from exception


def _fetch_code(
    imap: imaplib.IMAP4_SSL, uid: bytes, threshold: datetime
) -> FoundCode | None:
    """Fetch one message and return its code if it is recent enough."""
    status, data = imap.uid("FETCH", uid, "(INTERNALDATE BODY.PEEK[])")
    if status != "OK" or not data or not isinstance(data[0], tuple):
        return None
    header, raw = data[0]
    stamp = imaplib.Internaldate2tuple(header)
    if stamp is None:
        return None
    received = datetime.fromtimestamp(time.mktime(stamp), tz=UTC)
    if received < threshold:
        return None
    code = extract_code(email.message_from_bytes(raw))
    if code is None:
        return None
    return FoundCode(code=code, received=received, uid=uid)
