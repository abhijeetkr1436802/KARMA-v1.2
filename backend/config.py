import os
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = Path(os.environ.get("KARMA_DATA_DIR", str(Path.home() / ".karma"))).resolve()
DB_PATH = str(DATA_DIR / "karma.db")
LOG_DIR = DATA_DIR / "logs"
ADMIN_TOKEN_FILE = DATA_DIR / "admin-token"
ADMIN_TOKEN = os.environ.get("KARMA_ADMIN_TOKEN", "")
PRODUCTION = os.environ.get("KARMA_ENV", "development") == "production"
COOKIE_SECURE = PRODUCTION or os.environ.get("KARMA_COOKIE_SECURE") == "1"
ALLOWED_HOSTS = os.environ.get("KARMA_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
ENABLE_SENSORS = os.environ.get("KARMA_ENABLE_SENSORS", "1") == "1"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_CLIENTS = 64
MAX_EVENTS = int(os.environ.get("KARMA_MAX_EVENTS", "100000"))
if MAX_EVENTS < 100:
    raise ValueError("KARMA_MAX_EVENTS must be at least 100")

HOST = os.environ.get("KARMA_HOST", "127.0.0.1")
SENSOR_HOST = os.environ.get("KARMA_SENSOR_HOST", "0.0.0.0")
PORT_API = 8000
PORT_SSH_HONEYPOT = 2222
PORT_WEB_HONEYPOT = 8080
DECOY_PORTS = [21, 23, 3389]  # FTP, Telnet, RDP decoy probes

# Threat scoring threshold for automated IP quarantine
QUARANTINE_SCORE_THRESHOLD = 75

# DeepSeek AI Threat Intelligence & Cybersecurity Copilot Configuration
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"

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
