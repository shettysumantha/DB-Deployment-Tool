import getpass
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[2] / ".env", override=False)

from core.config.config import ADMIN_BOOTSTRAP_PASSKEY
from core.security.security_service import admin_exists, create_bootstrap_admin, initialize_security

initialize_security()

username = input("Admin username: ").strip()
email = input("Admin email: ").strip()
password = getpass.getpass("Password: ")
confirmation = getpass.getpass("Confirm password: ")
passkey = getpass.getpass("Admin bootstrap passkey: ")
if password != confirmation:
    raise SystemExit("Passwords do not match.")

try:
    create_bootstrap_admin(
        {"username": username, "email": email, "password": password, "passkey": passkey},
        ADMIN_BOOTSTRAP_PASSKEY,
    )
except ValueError as exc:
    raise SystemExit(str(exc)) from exc
print("Admin account created successfully.")
