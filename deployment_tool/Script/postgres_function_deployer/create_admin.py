import getpass
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)

from config import ADMIN_BOOTSTRAP_PASSKEY
from services.security_service import admin_exists, create_bootstrap_admin, initialize_security

initialize_security()

if admin_exists():
    print("An Admin account already exists. No changes made.")
    raise SystemExit(0)

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
