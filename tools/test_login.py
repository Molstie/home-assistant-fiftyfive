# ruff: noqa: T201, INP001
r"""
Test the 50five login with e-mail verification code, outside Home Assistant.

Two modes:

  imap   Only reads the mailbox: finds the newest existing verification mail.
         Does not contact 50five at all.
  login  One real login: password, verification code from the mailbox (or
         typed in with --manual-code), then fetches the charger overview.

Run from the repository root, for example:

  uv run --python 3.13 --with aiohttp --with fiftyfive==0.6.0 \\
      python tools/test_login.py imap --folder 50five-codes

Credentials come from environment variables or are asked with getpass; they
are never written anywhere. The login mode keeps a guard file in your home
directory and refuses to run more than once per 15 minutes or after three
failed logins in a row (--reset-strikes clears the counter, use with care).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib
import json
import os
import sys
import time
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

INTEGRATION = Path(__file__).resolve().parent.parent / "custom_components" / "fiftyfive"
GUARD_FILE = Path.home() / ".fiftyfive-test-login.json"
POLL_INTERVAL = 10
POLL_TIMEOUT = 120


def _load_modules() -> tuple[types.ModuleType, types.ModuleType]:
    """
    Import otp_api and imap_otp without running the integration's __init__.

    The package directory is called ``fiftyfive``, like the PyPI library it
    uses, so it is mounted under another name.
    """
    package = types.ModuleType("fiftyfive_fork")
    package.__path__ = [str(INTEGRATION)]
    sys.modules["fiftyfive_fork"] = package
    return (
        importlib.import_module("fiftyfive_fork.otp_api"),
        importlib.import_module("fiftyfive_fork.imap_otp"),
    )


otp_api, imap_otp = _load_modules()


def _ask(env: str, prompt: str, *, secret: bool = False, default: str = "") -> str:
    if value := os.environ.get(env):
        return value
    if secret:
        return getpass.getpass(f"{prompt}: ")
    answer = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return answer or default


def _imap_settings(args: argparse.Namespace) -> imap_otp.ImapSettings:
    return imap_otp.ImapSettings(
        host=args.imap_host,
        port=args.imap_port,
        username=_ask("IMAP_USER", "IMAP-gebruiker (volledig e-mailadres)"),
        password=_ask("IMAP_PASSWORD", "IMAP app-wachtwoord", secret=True),
        folder=args.folder,
        sender=args.sender,
    )


def _mask(code: str) -> str:
    return "****" + code[-2:]


def run_imap(args: argparse.Namespace) -> int:
    """Find the newest existing verification mail, read-only."""
    settings = _imap_settings(args)
    not_before = datetime.now(UTC) - timedelta(days=args.days)
    print(f"Zoeken in map {settings.folder!r} naar mail van {settings.sender} ...")
    try:
        found = imap_otp.find_code(settings, not_before, mark_seen=False)
    except imap_otp.ImapOtpError as exception:
        print(f"MISLUKT: {exception} ({exception.__cause__})")
        return 1
    if not found:
        print(f"Geen verificatiemail gevonden in de laatste {args.days} dagen.")
        return 1
    local = found.received.astimezone()
    print(f"OK: code {_mask(found.code)} ontvangen op {local:%d-%m-%Y %H:%M:%S}")
    return 0


def _load_guard() -> otp_api.LoginGuard:
    state = {}
    if GUARD_FILE.exists():
        state = json.loads(GUARD_FILE.read_text())
    guard = otp_api.LoginGuard(
        last_attempt=float(state.get("last_attempt", 0)),
        strikes=int(state.get("strikes", 0)),
    )
    guard.on_change = lambda: GUARD_FILE.write_text(json.dumps(guard.as_dict()))
    return guard


async def _login(args: argparse.Namespace, guard: otp_api.LoginGuard) -> int:
    import aiohttp  # noqa: PLC0415
    from fiftyfive import CustomerType, Market, NetworkOverview  # noqa: PLC0415

    email = _ask("FIFTYFIVE_EMAIL", "50five e-mailadres")
    password = _ask("FIFTYFIVE_PASSWORD", "50five wachtwoord", secret=True)
    settings = None if args.manual_code else _imap_settings(args)

    async def code_provider(started: datetime) -> str | None:
        if settings is None:
            code = await asyncio.to_thread(input, "Verificatiecode uit de mail: ")
            return code.strip() or None
        print(f"Wachten op de codemail (max {POLL_TIMEOUT} s) ...")
        deadline = time.monotonic() + POLL_TIMEOUT
        while time.monotonic() < deadline:
            found = await asyncio.to_thread(imap_otp.find_code, settings, started)
            if found:
                print(f"  code {_mask(found.code)} gevonden")
                return found.code
            await asyncio.sleep(POLL_INTERVAL)
        return None

    async with aiohttp.ClientSession() as session:
        api = otp_api.OtpApi(
            session=session,
            email=email,
            password=password,
            market=Market(args.market),
            customer_type=CustomerType(args.customer_type),
            code_provider=code_provider,
            guard=guard,
            trace=lambda line: print(f"  {line}"),
        )
        try:
            await api.login()
        except otp_api.OtpLoginError as exception:
            print(f"LOGIN MISLUKT: {type(exception).__name__}: {exception}")
            print(f"Mislukte pogingen op rij: {guard.strikes}/{otp_api.MAX_STRIKES}")
            return 1
        print("Ingelogd. Overzicht ophalen ...")
        networks = await api.make_requests([NetworkOverview()])
        if not networks or not networks[0]:
            print("MISLUKT: lege networkOverview")
            return 1
        for network in networks[0]:
            print(f"  laadpaal {network.get('NAME')!r}: STATUS={network.get('STATUS')}")
        print("OK")
        return 0


def run_login(args: argparse.Namespace) -> int:
    """Do one real login, guarded."""
    guard = _load_guard()
    if args.reset_strikes:
        guard.strikes = 0
        guard.on_change()
    try:
        guard.check(time.time())
    except otp_api.OtpLoginError as exception:
        print(f"GEWEIGERD: {exception}")
        return 2
    return asyncio.run(_login(args, guard))


def main() -> int:
    """Parse arguments and run."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("mode", choices=["imap", "login"])
    parser.add_argument("--imap-host", default=imap_otp.DEFAULT_IMAP_HOST)
    parser.add_argument("--imap-port", type=int, default=imap_otp.DEFAULT_IMAP_PORT)
    parser.add_argument("--folder", default=imap_otp.DEFAULT_IMAP_FOLDER)
    parser.add_argument("--sender", default=imap_otp.DEFAULT_IMAP_SENDER)
    parser.add_argument("--days", type=int, default=30, help="imap: hoe ver terug")
    parser.add_argument("--market", default="nl")
    parser.add_argument("--customer-type", default="shell")
    parser.add_argument("--manual-code", action="store_true")
    parser.add_argument("--reset-strikes", action="store_true")
    args = parser.parse_args()
    return run_imap(args) if args.mode == "imap" else run_login(args)


if __name__ == "__main__":
    sys.exit(main())
