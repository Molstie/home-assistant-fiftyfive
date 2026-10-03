"""Constants for 50five."""

from datetime import timedelta
from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

DOMAIN = "fiftyfive"
DEFAULT_UPDATE_INTERVAL = timedelta(minutes=5)
CHARGING_UPDATE_INTERVAL = timedelta(seconds=5)

FAST_POLL_TIME = 30

CONF_CUST_TYPE = "customer_type"

# E-mail one-time password (2FA) via IMAP; stored in the entry options.
CONF_IMAP_HOST = "imap_host"
CONF_IMAP_PORT = "imap_port"
CONF_IMAP_USERNAME = "imap_username"
CONF_IMAP_PASSWORD = "imap_password"  # noqa: S105
CONF_IMAP_FOLDER = "imap_folder"
CONF_IMAP_SENDER = "imap_sender"

OTP_POLL_INTERVAL = 10
OTP_POLL_TIMEOUT = 120
