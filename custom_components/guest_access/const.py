"""Constants for the Guest Access integration."""

DOMAIN = "guest_access"

CONF_SECRET_KEY = "secret_key"
CONF_SIGNING_KEY = "signing_key"
CONF_ENTITY = "entity"
CONF_ALLOWED_ACTION = "allowed_action"
CONF_EXPIRATION_TIME = "expiration_time"
CONF_LOCAL_ONLY = "local_only"
CONF_ALLOWED_CIDRS = "allowed_cidrs"
CONF_TOKEN_VERSION = "token_version"
CONF_TOKEN_USES = "token_uses"
CONF_TOKEN_MAX_USES = "token_max_uses"
CONF_SHOW_QR_NOTIFICATION = "show_qr_notification"

DATA_TOKEN_MANAGER = "token_manager"
DATA_PAIRING_STORE = "pairing_store"
DATA_CONFIG_ENTRIES = "config_entries"
DATA_API_REGISTERED = "api_registered"
DATA_STORAGE_LOCK = "storage_lock"

SERVICE_CREATE_PASS = "create_pass"
SERVICE_REVOKE_ALL = "revoke_all"
EVENT_REVOKE_ALL = f"{DOMAIN}.revoke_all"
EVENT_GUEST_ACCESS_USED = "guest_access_used"
PAIRING_CODE_TTL_SECONDS = 5 * 60
ALLOWED_ENTITY_DOMAINS = ("lock", "cover")
ALLOWED_ACTIONS = ("door.open", "garage.open")
DEFAULT_LOCAL_ONLY = False
DEFAULT_ALLOWED_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)
TOKEN_ISSUER = DOMAIN
TOKEN_AUDIENCE = "localkey_ios"
DEFAULT_TOKEN_VERSION = 1
DEFAULT_TOKEN_MAX_USES = 10
DEFAULT_ENTRY_TITLE = "Guest Access"

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.keys"
