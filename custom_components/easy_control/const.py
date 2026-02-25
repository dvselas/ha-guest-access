"""Constants for the HA Easy Control integration."""

DOMAIN = "easy_control"

CONF_SECRET_KEY = "secret_key"
CONF_SIGNING_KEY = "signing_key"
CONF_ENTITY = "entity"
CONF_ENTITIES = "entities"
CONF_ALLOWED_ACTION = "allowed_action"
CONF_EXPIRATION_TIME = "expiration_time"
CONF_LOCAL_ONLY = "local_only"
CONF_ALLOWED_CIDRS = "allowed_cidrs"
CONF_TOKEN_VERSION = "token_version"
CONF_TOKEN_USES = "token_uses"
CONF_TOKEN_MAX_USES = "token_max_uses"
CONF_SHOW_QR_NOTIFICATION = "show_qr_notification"
CONF_REQUIRE_ADMIN_APPROVAL = "require_admin_approval"
CONF_DEFAULT_REQUIRE_ADMIN_APPROVAL = "default_require_admin_approval"
CONF_REQUIRE_DEVICE_BINDING = "require_device_binding"
CONF_REQUIRE_ACTION_PROOF = "require_action_proof"
CONF_PAIR_RATE_LIMIT_PER_MIN = "pair_rate_limit_per_min"
CONF_ACTION_RATE_LIMIT_PER_MIN = "action_rate_limit_per_min"
CONF_QR_RATE_LIMIT_PER_MIN = "qr_rate_limit_per_min"
CONF_STATES_RATE_LIMIT_PER_MIN = "states_rate_limit_per_min"
CONF_NONCE_TTL_SECONDS = "nonce_ttl_seconds"
CONF_ACTION_PROOF_CLOCK_SKEW_SECONDS = "action_proof_clock_skew_seconds"
CONF_DEVICE_ID = "device_id"
CONF_DEVICE_PUBLIC_KEY = "device_public_key"
CONF_SIGNING_KEYS = "signing_keys"
CONF_ACTIVE_KID = "active_kid"
CONF_REVOKED_TOKEN_JTIS = "revoked_token_jtis"
CONF_ISSUED_TOKENS = "issued_tokens"
CONF_CNF = "cnf"
CONF_JKT = "jkt"

DATA_TOKEN_MANAGER = "token_manager"
DATA_PAIRING_STORE = "pairing_store"
DATA_CONFIG_ENTRIES = "config_entries"
DATA_API_REGISTERED = "api_registered"
DATA_STORAGE_LOCK = "storage_lock"
DATA_NONCE_STORE = "nonce_store"
DATA_RATE_LIMITER = "rate_limiter"

SERVICE_CREATE_PASS = "create_guest_pass"
SERVICE_REVOKE_ALL = "revoke_all_guest_pass"
SERVICE_REVOKE_PASS = "revoke_guest_pass"
SERVICE_APPROVE_PAIRING = "approve_pairing_request"
SERVICE_REJECT_PAIRING = "reject_pairing_request"
EVENT_REVOKE_ALL = f"{DOMAIN}.{SERVICE_REVOKE_ALL}"
EVENT_REVOKE_PASS = f"{DOMAIN}.{SERVICE_REVOKE_PASS}"
EVENT_PAIRING_APPROVED = f"{DOMAIN}.{SERVICE_APPROVE_PAIRING}"
EVENT_PAIRING_REJECTED = f"{DOMAIN}.{SERVICE_REJECT_PAIRING}"
EVENT_GUEST_ACCESS_USED = "easy_control_used"
EVENT_RATE_LIMITED = f"{DOMAIN}.rate_limited"
PAIRING_CODE_TTL_SECONDS = 5 * 60
ALLOWED_ENTITY_DOMAINS = ("lock", "cover", "switch", "light", "sensor", "climate", "binary_sensor")
ALLOWED_ACTIONS = (
    "door.open",
    "garage.open",
    "switch.toggle",
    "light.toggle",
    "climate.read",
    "sensor.read",
    "binary_sensor.read",
)
READ_ONLY_DOMAINS = frozenset({"sensor", "binary_sensor", "climate"})

# Maps entity domain → default allowed action (auto-inferred, not user-specified).
DOMAIN_ACTION_MAP: dict[str, str] = {
    "lock": "door.open",
    "cover": "garage.open",
    "switch": "switch.toggle",
    "light": "light.toggle",
    "climate": "climate.read",
    "sensor": "sensor.read",
    "binary_sensor": "binary_sensor.read",
}

# Maps (action) → (service_domain, service_name) for actionable domains.
ACTION_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "door.open": ("lock", "unlock"),
    "garage.open": ("cover", "open_cover"),
    "switch.toggle": ("switch", "toggle"),
    "light.toggle": ("light", "toggle"),
}
DEFAULT_LOCAL_ONLY = False
DEFAULT_ALLOWED_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)
TOKEN_ISSUER = DOMAIN
TOKEN_AUDIENCE = "localkey_ios"
DEFAULT_TOKEN_VERSION = 1
# 0 means unlimited uses until token expiry/revocation.
DEFAULT_TOKEN_MAX_USES = 0
DEFAULT_ENTRY_TITLE = "HA Easy Control"
DEFAULT_REQUIRE_ADMIN_APPROVAL = False
DEFAULT_REQUIRE_DEVICE_BINDING = False
DEFAULT_REQUIRE_ACTION_PROOF = False
DEFAULT_PAIR_RATE_LIMIT_PER_MIN = 10
DEFAULT_ACTION_RATE_LIMIT_PER_MIN = 30
DEFAULT_QR_RATE_LIMIT_PER_MIN = 20
DEFAULT_STATES_RATE_LIMIT_PER_MIN = 30
DEFAULT_NONCE_TTL_SECONDS = 45
DEFAULT_ACTION_PROOF_CLOCK_SKEW_SECONDS = 30

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.keys"
