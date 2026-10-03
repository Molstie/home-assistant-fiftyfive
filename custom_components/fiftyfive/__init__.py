"""
Custom integration to integrate 50five with Home Assistant.

For more details about this integration, please refer to
https://github.com/Crazy-Duck/home-assistant-fiftyfive
"""

from __future__ import annotations

import asyncio
from functools import partial
from time import monotonic
from typing import TYPE_CHECKING

from homeassistant.const import CONF_COUNTRY, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.loader import async_get_loaded_integration

from fiftyfive import CustomerType

from .api import FiftyfiveApiClient
from .const import (
    CONF_CUST_TYPE,
    CONF_IMAP_FOLDER,
    CONF_IMAP_HOST,
    CONF_IMAP_PASSWORD,
    CONF_IMAP_PORT,
    CONF_IMAP_SENDER,
    CONF_IMAP_USERNAME,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    LOGGER,
    OTP_POLL_INTERVAL,
    OTP_POLL_TIMEOUT,
)
from .coordinator import FiftyfiveDataUpdateCoordinator
from .data import FiftyfiveData
from .imap_otp import (
    DEFAULT_IMAP_FOLDER,
    DEFAULT_IMAP_HOST,
    DEFAULT_IMAP_PORT,
    DEFAULT_IMAP_SENDER,
    ImapOtpError,
    ImapSettings,
    find_code,
)
from .otp_api import LoginGuard, OtpApi, OtpMailboxError
from .service_handler import ChargerServiceHandler
from .session_store import FiftyfiveSessionStore

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime
    from typing import Any

    from aiohttp import ClientSession
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.typing import ConfigType

    from .data import FiftyfiveConfigEntry

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.SENSOR,
]


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old config entries."""
    if config_entry.version == 1:
        LOGGER.debug(
            "Migrating config from version %s",
            config_entry.version,
        )
        new_data = {**config_entry.data}
        new_data[CONF_CUST_TYPE] = CustomerType.FORMER_SHELL

        hass.config_entries.async_update_entry(config_entry, data=new_data, version=2)
        LOGGER.debug(
            "Migrating to config version %s successful",
            config_entry.version,
        )
    return True


async def async_setup(hass: HomeAssistant, _: ConfigType) -> bool:
    """Set up the integration (global)."""
    handler = ChargerServiceHandler(hass=hass)

    hass.services.async_register(DOMAIN, "start_charge_session", handler.handle_start)
    hass.services.async_register(DOMAIN, "stop_charge_session", handler.handle_stop)
    hass.services.async_register(
        DOMAIN, "soft_reset_charger", handler.handle_soft_reset
    )
    hass.services.async_register(
        DOMAIN, "hard_reset_charger", handler.handle_hard_reset
    )
    hass.services.async_register(DOMAIN, "unlock_connector", handler.handle_unlock)
    hass.services.async_register(DOMAIN, "block_charger", handler.handle_block)
    hass.services.async_register(DOMAIN, "unblock_charger", handler.handle_unblock)

    return True


# https://developers.home-assistant.io/docs/config_entries_index/#setting-up-an-entry
async def async_setup_entry(
    hass: HomeAssistant,
    entry: FiftyfiveConfigEntry,
) -> bool:
    """Set up this integration using UI."""
    coordinator = FiftyfiveDataUpdateCoordinator(
        hass=hass,
        logger=LOGGER,
        name=DOMAIN,
        update_interval=DEFAULT_UPDATE_INTERVAL,
    )
    # Brittle but less mess than overriding __init__
    coordinator.fast_polling_until = 0

    # A dedicated session per entry: a stale cookie from a failed login stays
    # in this session only and is gone after a reload. Closed on unload.
    session = async_create_clientsession(hass)

    entry.runtime_data = FiftyfiveData(
        client=FiftyfiveApiClient(
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
            market=entry.data[CONF_COUNTRY],
            customer_type=entry.data[CONF_CUST_TYPE],
            session=session,
            api=await _async_otp_api(hass, entry, session),
        ),
        integration=async_get_loaded_integration(hass, entry.domain),
        coordinator=coordinator,
    )

    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # No update listener: the options flow reloads the entry itself (also when
    # setup failed) and the reauth flow reloads after updating the password.

    return True


def imap_settings(options: Mapping[str, Any]) -> ImapSettings | None:
    """Return the mailbox settings, or None when no mailbox is configured."""
    if not options.get(CONF_IMAP_USERNAME) or not options.get(CONF_IMAP_PASSWORD):
        return None
    return ImapSettings(
        host=options.get(CONF_IMAP_HOST) or DEFAULT_IMAP_HOST,
        port=int(options.get(CONF_IMAP_PORT) or DEFAULT_IMAP_PORT),
        username=options[CONF_IMAP_USERNAME],
        password=options[CONF_IMAP_PASSWORD],
        folder=options.get(CONF_IMAP_FOLDER) or DEFAULT_IMAP_FOLDER,
        sender=options.get(CONF_IMAP_SENDER) or DEFAULT_IMAP_SENDER,
    )


async def _async_otp_api(
    hass: HomeAssistant, entry: FiftyfiveConfigEntry, session: ClientSession
) -> OtpApi | None:
    """Return an OtpApi when a mailbox is configured; None keeps v0.10.0 behaviour."""
    settings = imap_settings(entry.options)
    if settings is None:
        return None

    store = FiftyfiveSessionStore(hass, entry.entry_id)
    await store.async_load()
    guard = LoginGuard(
        last_attempt=float(store.guard.get("last_attempt", 0)),
        strikes=int(store.guard.get("strikes", 0)),
    )
    guard.on_change = lambda: store.set_guard(guard.as_dict())

    api = OtpApi(
        session=session,
        email=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        market=entry.data[CONF_COUNTRY],
        customer_type=entry.data[CONF_CUST_TYPE],
        code_provider=partial(_async_wait_for_code, hass, settings),
        guard=guard,
        on_login=store.set_cookies,
    )
    api.restore_cookies(store.cookies)
    return api


async def _async_wait_for_code(
    hass: HomeAssistant, settings: ImapSettings, started: datetime
) -> str | None:
    """Poll the mailbox for the verification code of the login that started."""
    LOGGER.info("50five asks for a verification code; checking the mailbox")
    deadline = monotonic() + OTP_POLL_TIMEOUT
    while True:
        try:
            found = await hass.async_add_executor_job(find_code, settings, started)
        except ImapOtpError as exception:
            raise OtpMailboxError(str(exception)) from exception
        if found:
            return found.code
        if monotonic() >= deadline:
            return None
        await asyncio.sleep(OTP_POLL_INTERVAL)


async def async_unload_entry(
    hass: HomeAssistant,
    entry: FiftyfiveConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(
    hass: HomeAssistant,
    entry: FiftyfiveConfigEntry,
) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_remove_entry(
    hass: HomeAssistant,
    entry: FiftyfiveConfigEntry,
) -> None:
    """Delete the saved session when the entry is removed."""
    await FiftyfiveSessionStore(hass, entry.entry_id).async_remove()
