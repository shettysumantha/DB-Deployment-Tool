from pathlib import Path

from services.security_service import security_connection

with security_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(Path(__file__).with_name("database_security.sql").read_text(encoding="utf-8"))
    conn.commit()
print("Authentication schema and seed data are ready.")
