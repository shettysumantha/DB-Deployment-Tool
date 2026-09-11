import getpass
import os
import sys

from dotenv import load_dotenv

from services.security_service import password_hash, security_connection

load_dotenv()

username = input("Username: ").strip()
email = input("Email: ").strip() or None
full_name = input("Full name: ").strip() or username
password = getpass.getpass("Password: ")
confirmation = getpass.getpass("Confirm password: ")
if not username or not password or password != confirmation:
    raise SystemExit("Username and matching non-empty passwords are required.")

with security_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO app_security.users (username, email, full_name, password_hash) VALUES (%s, %s, %s, %s) RETURNING user_id",
            (username, email, full_name, password_hash(password)),
        )
        user_id = cur.fetchone()[0]
        cur.execute("SELECT role_id FROM app_security.roles WHERE role_name = 'ADMIN' AND is_active")
        role = cur.fetchone()
        if not role:
            raise SystemExit("ADMIN role is missing. Run database_security.sql first.")
        cur.execute("INSERT INTO app_security.user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, role[0]))
    conn.commit()
print(f"Created administrator: {username}")
