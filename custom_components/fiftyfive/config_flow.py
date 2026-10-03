"""Adds config flow for FiftyFive."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_COUNTRY, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from slugify import slugify

from fiftyfive import Api, CustomerType, Market, NetworkOverview

from . import imap_settings
from .const import (
    CONF_CUST_TYPE,
    CONF_IMAP_FOLDER,
    CONF_IMAP_HOST,
    CONF_IMAP_PASSWORD,
    CONF_IMAP_PORT,
    CONF_IMAP_SENDER,
    CONF_IMAP_USERNAME,
    DOMAIN,
    LOGGER,
)
from .imap_otp import (
    DEFAULT_IMAP_FOLDER,
    DEFAULT_IMAP_HOST,
    DEFAULT_IMAP_PORT,
    DEFAULT_IMAP_SENDER,
    ImapFolderError,
    ImapOtpError,
    check_mailbox,
)
from .session_store import FiftyfiveSessionStore


class FiftyfiveFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for FiftyFive."""

    VERSION = 2

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,  # noqa: ARG004
    ) -> FiftyfiveOptionsFlow:
        """Return the options flow (mailbox for the verification code)."""
        return FiftyfiveOptionsFlow()

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        _errors: dict[str, str] = {}
        if user_input is not None:
            if not await self._test_credentials(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                market=user_input[CONF_COUNTRY],
                customer_type=user_input[CONF_CUST_TYPE],
            ):
                LOGGER.warning("Invalid credentials/market.")
                _errors["base"] = "auth"
            else:
                await self.async_set_unique_id(
                    unique_id=slugify(user_input[CONF_USERNAME])
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_USERNAME],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=(user_input or {}).get(CONF_USERNAME, vol.UNDEFINED),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT,
                        ),
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD,
                        ),
                    ),
                    vol.Optional(
                        CONF_COUNTRY,
                        default=(user_input or {}).get(CONF_COUNTRY, Market.NONE),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[m.value for m in Market], translation_key="country"
                        )
                    ),
                    vol.Required(
                        CONF_CUST_TYPE,
                        default=(user_input or {}).get(
                            CONF_CUST_TYPE, CustomerType.FORMER_SHELL
                        ),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[c.value for c in CustomerType],
                            translation_key="customer_type",
                        )
                    ),
                },
            ),
            errors=_errors,
            description_placeholders={
                "docs_url": "https://github.com/Crazy-Duck/home-assistant-fiftyfive"
            },
        )

    async def async_step_reauth(
        self, entry_data: config_entries.Mapping[str, Any]
    ) -> config_entries.ConfigFlowResult:
        """Perform reauthentication upon an API authentication error."""
        self.username = entry_data[CONF_USERNAME]
        self.country = entry_data[CONF_COUNTRY]
        self.customer_type = entry_data[CONF_CUST_TYPE]
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Confirm reauthentication dialog."""
        _errors: dict[str, str] = {}
        if user_input is not None:
            entry = self._get_reauth_entry()
            # With a mailbox configured a test login would need a verification
            # code; the reload after saving does the real (guarded) login.
            if imap_settings(
                entry.options
            ) is None and not await self._test_credentials(
                username=self.username,
                password=user_input[CONF_PASSWORD],
                market=self.country,
                customer_type=self.customer_type,
            ):
                LOGGER.warning("Invalid credentials/market.")
                _errors["base"] = "auth"
            else:
                await FiftyfiveSessionStore(
                    self.hass, entry.entry_id
                ).async_reset_strikes()
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]}
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD,
                        ),
                    ),
                },
            ),
            errors=_errors,
            description_placeholders={
                "docs_url": "https://github.com/Crazy-Duck/home-assistant-fiftyfive"
            },
        )

    async def _test_credentials(
        self, username: str, password: str, market: Market, customer_type: CustomerType
    ) -> Any:
        """Validate credentials."""
        client = Api(
            session=async_create_clientsession(self.hass),
            email=username,
            password=password,
            market=market,
            customer_type=customer_type,
        )
        return await client.make_requests([NetworkOverview()])


class FiftyfiveOptionsFlow(config_entries.OptionsFlowWithReload):
    """
    Mailbox settings for the e-mail verification code.

    Leave the user empty to switch the automatic code off (v0.10.0 behaviour).
    Saving reloads the entry, also when its setup had failed.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Show and validate the mailbox settings."""
        current = dict(self.config_entry.options)
        errors: dict[str, str] = {}
        if user_input is not None:
            options = {**current, **user_input}
            # An empty password field keeps the saved app password.
            if not user_input.get(CONF_IMAP_PASSWORD):
                options[CONF_IMAP_PASSWORD] = current.get(CONF_IMAP_PASSWORD, "")
            if not options.get(CONF_IMAP_USERNAME):
                options[CONF_IMAP_USERNAME] = ""
                options[CONF_IMAP_PASSWORD] = ""
            elif (settings := imap_settings(options)) is None:
                errors[CONF_IMAP_PASSWORD] = "imap_password_required"
            else:
                try:
                    await self.hass.async_add_executor_job(check_mailbox, settings)
                except ImapFolderError:
                    errors[CONF_IMAP_FOLDER] = "imap_folder"
                except ImapOtpError:
                    errors["base"] = "imap_auth"
            if not errors:
                await FiftyfiveSessionStore(
                    self.hass, self.config_entry.entry_id
                ).async_reset_strikes()
                return self.async_create_entry(data=options)
            current = {**options, CONF_IMAP_PASSWORD: ""}

        text = selector.TextSelector()
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_IMAP_USERNAME,
                        description={
                            "suggested_value": current.get(CONF_IMAP_USERNAME)
                        },
                    ): text,
                    vol.Optional(CONF_IMAP_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    ),
                    vol.Required(
                        CONF_IMAP_HOST,
                        default=current.get(CONF_IMAP_HOST) or DEFAULT_IMAP_HOST,
                    ): text,
                    vol.Required(
                        CONF_IMAP_PORT,
                        default=int(current.get(CONF_IMAP_PORT) or DEFAULT_IMAP_PORT),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                    vol.Required(
                        CONF_IMAP_FOLDER,
                        default=current.get(CONF_IMAP_FOLDER) or DEFAULT_IMAP_FOLDER,
                    ): text,
                    vol.Required(
                        CONF_IMAP_SENDER,
                        default=current.get(CONF_IMAP_SENDER) or DEFAULT_IMAP_SENDER,
                    ): text,
                }
            ),
            errors=errors,
        )
