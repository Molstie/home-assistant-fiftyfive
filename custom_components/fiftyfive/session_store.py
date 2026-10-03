"""Persist the portal cookies and the login guard across restarts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.helpers.storage import Store

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

STORAGE_VERSION = 1
SAVE_DELAY = 1


class FiftyfiveSessionStore:
    """
    Session cookies and login guard state for one config entry.

    Kept in ``.storage/fiftyfive.<entry_id>``, not in the entry data: changing
    the entry would reload the integration, and v0.10.0 never reads this file.
    """

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        """Initialize."""
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry_id}"
        )
        self.cookies: dict[str, str] = {}
        self.guard: dict[str, Any] = {}

    async def async_load(self) -> None:
        """Load the saved state."""
        data = await self._store.async_load() or {}
        self.cookies = dict(data.get("cookies", {}))
        self.guard = dict(data.get("guard", {}))

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Remember the cookies of a successful login."""
        self.cookies = dict(cookies)
        self._schedule_save()

    def set_guard(self, guard: dict[str, Any]) -> None:
        """Remember the login guard state."""
        self.guard = dict(guard)
        self._schedule_save()

    async def async_reset_strikes(self) -> None:
        """Allow logins again after the settings were changed by the user."""
        await self.async_load()
        if self.guard.get("strikes"):
            self.guard["strikes"] = 0
            await self._store.async_save(self._data())

    async def async_remove(self) -> None:
        """Delete the file."""
        await self._store.async_remove()

    def _data(self) -> dict[str, Any]:
        return {"cookies": self.cookies, "guard": self.guard}

    def _schedule_save(self) -> None:
        self._store.async_delay_save(self._data, SAVE_DELAY)
