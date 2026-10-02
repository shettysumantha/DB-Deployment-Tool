from pathlib import Path

script_path = Path(__file__).with_name("database_security.sql")
print(f"Manually execute the authentication database script with PostgreSQL/DB Solo: {script_path}")
