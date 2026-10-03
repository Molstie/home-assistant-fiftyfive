"""Integration tests against Home Assistant (pytest-homeassistant-custom-component)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from fiftyfive import Api, NetworkOverview
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.fiftyfive import imap_settings
from custom_components.fiftyfive.const import DOMAIN
from custom_components.fiftyfive.otp_api import OtpApi, OtpCodeTimeoutError

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

ENTRY_ID = "01KJNJ241H89HK65FCBNGQW8JN"
IDX = "1234727754"
DATA = {
    "username": "user@example.com",
    "password": "secret",
    "country": "nl",
    "customer_type": "shell",
}
IMAP_OPTIONS = {
    "imap_username": "me@example.com",
    "imap_password": "app-password",
    "imap_host": "imap.gmail.com",
    "imap_port": 993,
    "imap_folder": "50five-codes",
    "imap_sender": "noreply@lastmilesolutions.com",
}
NETWORK = {
    "IDX": IDX,
    "NAME": "KW44",
    "STATUS": None,
    "SOFTWARE_VERSION": "1.0",
    "CONNECTOR": "Type 2",
}
DETAIL = {
    "MOM_POWER_KW": 0,
    "TRANS_ENERGY_DELIVERED_KWH": 0,
    "TRANSACTION_TIME_H_M": "",
    "CARDID": None,
    "NOTIFICATION": "Beschikbaar",
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Load integrations from custom_components."""
    return enable_custom_integrations


async def portal(_: Any, requests: list) -> Any:
    """Answer like a logged-in portal."""
    if isinstance(requests[0], NetworkOverview):
        return [[NETWORK]]
    return [[DETAIL] for _ in requests]


async def logged_out(_: Any, __: list) -> Any:
    """Answer like the portal does to a refused session."""
    return []


def make_entry(hass: HomeAssistant, options: dict | None = None) -> MockConfigEntry:
    """Add the 50five entry as it exists on the NAS (version 2)."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        entry_id=ENTRY_ID,
        unique_id="user-example-com",
        title=DATA["username"],
        data=DATA,
        options=options or {},
    )
    entry.add_to_hass(hass)
    return entry


async def test_without_mailbox_behaves_like_v0_10_0(hass: HomeAssistant) -> None:
    """No IMAP options: the library Api is used; device and entities as before."""
    entry = make_entry(hass)
    with (
        patch.object(Api, "make_requests", portal),
        patch.object(OtpApi, "make_requests", side_effect=AssertionError),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.LOADED
    assert not isinstance(entry.runtime_data.client._api, OtpApi)  # noqa: SLF001
    devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    assert [d.identifiers for d in devices] == [{(DOMAIN, IDX)}]
    ent_reg = er.async_get(hass)
    assert ent_reg.async_get_entity_id("sensor", DOMAIN, f"{IDX}_status")
    assert ent_reg.async_get_entity_id("button", DOMAIN, f"{IDX}_unblock")


async def test_refused_login_without_mailbox_is_auth_failed(
    hass: HomeAssistant,
) -> None:
    """Without a mailbox an empty answer still means 'Invalid credentials'."""
    entry = make_entry(hass)
    with patch.object(Api, "make_requests", logged_out):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert entry.reason == "Invalid credentials"


async def test_options_in_setup_error_reload_the_entry(hass: HomeAssistant) -> None:
    """The kip-en-ei: fill in the mailbox while setup failed; saving reloads."""
    entry = make_entry(hass)
    with patch.object(Api, "make_requests", logged_out):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_ERROR

    with (
        patch("custom_components.fiftyfive.config_flow.check_mailbox"),
        patch.object(OtpApi, "make_requests", portal),
    ):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], IMAP_OPTIONS
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options["imap_folder"] == "50five-codes"
    assert entry.data == DATA  # v0.10.0 can still read the entry
    assert entry.state is ConfigEntryState.LOADED
    assert isinstance(entry.runtime_data.client._api, OtpApi)  # noqa: SLF001


async def test_options_errors_and_switching_off(hass: HomeAssistant) -> None:
    """Bad mailbox settings show an error; an empty user switches OTP off."""
    entry = make_entry(hass, options=IMAP_OPTIONS)
    with patch.object(OtpApi, "make_requests", portal):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    from custom_components.fiftyfive.imap_otp import (  # noqa: PLC0415
        ImapFolderError,
        ImapOtpError,
    )

    for error, field in (
        (ImapOtpError("x"), "base"),
        (ImapFolderError("x"), "imap_folder"),
    ):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        with patch(
            "custom_components.fiftyfive.config_flow.check_mailbox", side_effect=error
        ):
            result = await hass.config_entries.options.async_configure(
                result["flow_id"], {**IMAP_OPTIONS, "imap_password": ""}
            )
        assert result["type"] is FlowResultType.FORM
        assert field in result["errors"]

    with patch.object(Api, "make_requests", portal):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {**IMAP_OPTIONS, "imap_username": "", "imap_password": ""},
        )
        await hass.async_block_till_done()

    assert imap_settings(entry.options) is None
    assert entry.state is ConfigEntryState.LOADED
    assert not isinstance(entry.runtime_data.client._api, OtpApi)  # noqa: SLF001


async def test_empty_password_keeps_saved_app_password(hass: HomeAssistant) -> None:
    """Saving the options without retyping the app password keeps it."""
    entry = make_entry(hass, options=IMAP_OPTIONS)
    with (
        patch.object(OtpApi, "make_requests", portal),
        patch("custom_components.fiftyfive.config_flow.check_mailbox"),
    ):
        await hass.config_entries.async_setup(entry.entry_id)
        result = await hass.config_entries.options.async_init(entry.entry_id)
        await hass.config_entries.options.async_configure(
            result["flow_id"], {**IMAP_OPTIONS, "imap_password": ""}
        )
        await hass.async_block_till_done()

    assert entry.options["imap_password"] == "app-password"


async def test_otp_failure_is_retry_not_reauth(hass: HomeAssistant) -> None:
    """A missed code makes the entry retry; only 3 strikes lead to reauth."""
    entry = make_entry(hass, options=IMAP_OPTIONS)

    async def no_code(_: Any, __: list) -> Any:
        raise OtpCodeTimeoutError

    with patch.object(OtpApi, "make_requests", no_code):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_reauth_flow_no_longer_crashes(hass: HomeAssistant) -> None:
    """The first reauth step shows the form; the new password is saved."""
    entry = make_entry(hass)
    with patch.object(Api, "make_requests", logged_out):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    with patch.object(Api, "make_requests", portal):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"password": "new-secret"}
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data == {**DATA, "password": "new-secret"}
    assert entry.state is ConfigEntryState.LOADED
