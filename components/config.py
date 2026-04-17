import yaml
import os
from pathlib import Path

# Load config.yaml from root
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.yaml"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {}

_config = load_config()

app_config = _config.get("app", {})
SITE_PATH = app_config.get("site_path", "")
CUSTOM_LOGO = app_config.get("logo", "")
CUSTOM_SUBTITLE = app_config.get("subtitle", "Collaborative Process Mapping")
CONTACT_EMAIL = app_config.get("contact_email", "testuser@unfoundry.co.uk")
BPMN_TEMPLATES_PATH = BASE_DIR / app_config.get("templates_path", "bpmn_templates")
BPMN_TEMPLATES_PATH.mkdir(exist_ok=True, parents=True)

auth_config = _config.get("auth", {})
LOGIN_METHOD = auth_config.get("method", "username,password")
AUTH_CREDENTIALS = auth_config.get("credentials", "admin,password")
ADMINS = auth_config.get("admins", [])

storage_config = _config.get("storage", {})
DIAGRAM_STORAGE_PATH = BASE_DIR / storage_config.get("diagram_path", "diagram_storage")
DIAGRAM_STORAGE_PATH.mkdir(exist_ok=True, parents=True)
SQL_INSTANCE_TYPE = storage_config.get("sql_instance_type", "sqlite")
DB_CONNECTION_STRING = storage_config.get("db_connection_string", "sqlite:///./diagrams.db")

sessions_config = _config.get("sessions", {})
HEARTBEAT_FREQUENCY_SEC = int(sessions_config.get("heartbeat_frequency_sec", 15))
IDLE_TIMEOUT_MIN = int(sessions_config.get("idle_timeout_min", 15))

git_config = _config.get("git", {})
GIT_BACKUP_ENABLED = git_config.get("backup_enabled", False)
GIT_COMMIT_FORMAT = git_config.get("commit_format", "Edited by: <last_edited_by>")
GIT_COMMIT_SYNTAX = git_config.get("commit_syntax", "git add . && git commit -m \"<commit_msg>\" && git push origin")
