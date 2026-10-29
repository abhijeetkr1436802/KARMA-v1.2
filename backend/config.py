import os
import math
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env_file(path):
    """Minimal .env reader: KEY=VALUE per line, # comments, optional quotes.
    Real environment variables always win (we only setdefault)."""
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, val)
    except (FileNotFoundError, OSError):
        pass


# Load the project-root .env first (source installs), so KARMA_DATA_DIR resolves below.
_load_env_file(Path(BASE_DIR) / ".env")
DATA_DIR = Path(os.environ.get("KARMA_DATA_DIR", str(Path.home() / ".karma"))).resolve()
# Then load the per-install .env inside the data dir (where the GUI / .exe saves the key).
_load_env_file(DATA_DIR / ".env")
ENV_FILE = DATA_DIR / ".env"
DB_PATH = str(DATA_DIR / "karma.db")
LOG_DIR = DATA_DIR / "logs"
ADMIN_TOKEN_FILE = DATA_DIR / "admin-token"
ADMIN_TOKEN = os.environ.get("KARMA_ADMIN_TOKEN", "")
PRODUCTION = os.environ.get("KARMA_ENV", "development") == "production"
DOMAIN = os.environ.get("KARMA_DOMAIN", "karma-honeypot.com")
ALLOWED_HOSTS = os.environ.get("KARMA_ALLOWED_HOSTS", f"localhost,127.0.0.1,[::1],{DOMAIN},www.{DOMAIN}").split(",")
# Created by tools/make_cert.py; when present the dashboard serves HTTPS on 443.
TLS_CERT = DATA_DIR / "tls" / "server.pem"
TLS_KEY = DATA_DIR / "tls" / "server-key.pem"
TLS_ENABLED = TLS_CERT.is_file() and TLS_KEY.is_file()
ENABLE_SENSORS = os.environ.get("KARMA_ENABLE_SENSORS", "1") == "1"
# An operator-selected lab marker, never an inferred attacker location.
LAB_LOCATION_ENABLED = os.environ.get("KARMA_LAB_LOCATION_ENABLED", "1") == "1"
LAB_CITY = os.environ.get("KARMA_LAB_CITY", "Bengaluru")
LAB_COUNTRY = os.environ.get("KARMA_LAB_COUNTRY", "India")
LAB_LAT = float(os.environ.get("KARMA_LAB_LAT", "12.9716"))
LAB_LNG = float(os.environ.get("KARMA_LAB_LNG", "77.5946"))
# Public attacker IPs are located with the free ip-api.com service (cached; set 0 for fully offline use).
GEOIP_ENABLED = os.environ.get("KARMA_GEOIP_ENABLED", "1") == "1"
CALLBACK_BASE_URL = os.environ.get("KARMA_CALLBACK_BASE_URL", "")
ENGAGEMENT_MODE = os.environ.get("KARMA_ENGAGEMENT_MODE", "contain")
if ENGAGEMENT_MODE not in ("observe", "contain"):
    raise ValueError("KARMA_ENGAGEMENT_MODE must be observe or contain")
if not (math.isfinite(LAB_LAT) and -90 <= LAB_LAT <= 90 and
        math.isfinite(LAB_LNG) and -180 <= LAB_LNG <= 180):
    raise ValueError("Lab latitude/longitude must be finite and within geographic bounds")
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_CLIENTS = 64
MAX_EVENTS = int(os.environ.get("KARMA_MAX_EVENTS", "100000"))
if MAX_EVENTS < 100:
    raise ValueError("KARMA_MAX_EVENTS must be at least 100")

HOST = os.environ.get("KARMA_HOST", "127.0.0.1")
SENSOR_HOST = os.environ.get("KARMA_SENSOR_HOST", "0.0.0.0")
COOKIE_SECURE = PRODUCTION or TLS_ENABLED or os.environ.get("KARMA_COOKIE_SECURE") == "1"
PORT_API = int(os.environ.get("KARMA_PORT", "443" if TLS_ENABLED else "8000"))
DASHBOARD_URL = (f"https://{DOMAIN}" + ("" if PORT_API == 443 else f":{PORT_API}")) if TLS_ENABLED else f"http://localhost:{PORT_API}"
PORT_SSH_HONEYPOT = 2222
# Decoy banners; the desktop launcher can override them before starting the server.
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
FTP_BANNER = "220 Aegis Corporate File Service ready."
PORT_WEB_HONEYPOT = 8080
DECOY_PORTS = [21, 23, 3389]  # FTP, Telnet, RDP decoy probes

# Threat scoring threshold for automated IP quarantine
QUARANTINE_SCORE_THRESHOLD = 75
# Also block quarantined IPs in Windows Firewall / iptables (needs Administrator/root). Off by default.
FIREWALL_BLOCK = os.environ.get("KARMA_FIREWALL_BLOCK", "0") == "1"

# DeepSeek AI Threat Intelligence & Cybersecurity Copilot Configuration
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


def set_deepseek_key(key):
    """Persist the DeepSeek key to the per-install .env and apply it immediately
    (no restart needed). Used by the desktop launcher / packaged .exe."""
    global DEEPSEEK_API_KEY
    key = (key or "").strip()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lines = []
    if ENV_FILE.exists():
        lines = [l for l in ENV_FILE.read_text(encoding="utf-8").splitlines()
                 if not l.strip().startswith("DEEPSEEK_API_KEY=")]
    if key:
        lines.append(f"DEEPSEEK_API_KEY={key}")
    ENV_FILE.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass
    os.environ["DEEPSEEK_API_KEY"] = key
    DEEPSEEK_API_KEY = key
    return bool(key)

# Default Honeytokens
DEFAULT_HONEYTOKENS = [
    {
        "token_id": "ht-aws-01",
        "name": "Decoy AWS Production Key",
        "type": "API Key",
        "token_value": "AKIAIOSFODNN7EXAMPLE_DECOY_KEY_99",
        "description": "Embedded in fake git repository leak"
    },
    {
        "token_id": "ht-admin-url",
        "name": "Secret DB Admin Portal",
        "type": "Decoy URL",
        "token_value": "/secret-vault-admin-login-php",
        "description": "Hidden hyper-link decoy in fake web portal"
    },
    {
        "token_id": "ht-ssh-key",
        "name": "Staging Server Private Key",
        "type": "Credentials",
        "token_value": "root:SuperSecretStaging2026!",
        "description": "Fake credentials in configuration file decoy"
    }
]
