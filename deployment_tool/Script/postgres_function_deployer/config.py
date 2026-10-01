import os
from pathlib import Path
from urllib.parse import quote

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)

EXPECTED_FUNCTIONS = [
    name.strip()
    for name in os.getenv("EXPECTED_FUNCTIONS", "").replace(",", "\n").splitlines()
    if name.strip()
]

EXPECTED_TABLES = [
    name.strip()
    for name in os.getenv("EXPECTED_TABLES", "").replace(",", "\n").splitlines()
    if name.strip()
]
TABLE_NAME_PATTERN = os.getenv("TABLE_NAME_PATTERN", "%")

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "local-development-only-change-me")
HOST = os.getenv("FLASK_HOST") or ("0.0.0.0" if os.getenv("RENDER") else "127.0.0.1")
PORT = int(os.getenv("PORT") or os.getenv("FLASK_PORT", "5000"))
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
PG_DEFAULTS = {
    "host": os.getenv("PG_HOST", "localhost"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "database": os.getenv("PG_DATABASE", "MyDatabase"),
    "username": os.getenv("PG_USER", "postgres"),
}
PG_PASSWORD = os.getenv("PG_PASSWORD", "")
ADMIN_BOOTSTRAP_PASSKEY = os.getenv("ADMIN_BOOTSTRAP_PASSKEY", "")

APP_DATABASE_URL = os.getenv("APP_DATABASE_URL", "").strip()
if not APP_DATABASE_URL:
    app_db_host = os.getenv("PG_HOST", "localhost").strip()
    app_db_port = int(os.getenv("PG_PORT", "5432"))
    app_db_name = os.getenv("PG_DATABASE", "MyDatabase").strip()
    app_db_user = os.getenv("PG_USER", "postgres").strip()
    app_db_password = PG_PASSWORD
    app_db_sslmode = os.getenv("PG_SSLMODE", "prefer").strip()
    if app_db_host and app_db_name and app_db_user:
        if ":" in app_db_host and not app_db_host.startswith("["):
            app_db_host = f"[{app_db_host}]"
        credentials = quote(app_db_user, safe="")
        if app_db_password:
            credentials += f":{quote(app_db_password, safe='')}"
        APP_DATABASE_URL = (
            f"postgresql://{credentials}@{app_db_host}:{app_db_port}/"
            f"{quote(app_db_name, safe='')}?sslmode={quote(app_db_sslmode, safe='')}"
        )
