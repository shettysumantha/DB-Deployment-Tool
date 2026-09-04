import getpass
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
CREDENTIALS_DB = Path(os.getenv("CREDENTIALS_DB", BASE_DIR / "database_credentials.sqlite3")).resolve()


DDL = """
CREATE TABLE IF NOT EXISTS tbl_database_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    database_alias TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    database_name TEXT NOT NULL,
    username TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    updated_date TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(host, port, database_name, username)
)
"""


def _row_to_public(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "databaseAlias": row["database_alias"],
        "host": row["host"],
        "port": row["port"],
        "databaseName": row["database_name"],
        "username": row["username"],
    }


@contextmanager
def store():
    CREDENTIALS_DB.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(CREDENTIALS_DB)
    database.row_factory = sqlite3.Row
    try:
        database.execute(DDL)
        database.commit()
        yield database
    finally:
        database.close()


def list_databases():
    with store() as database:
        rows = database.execute(
            "SELECT id, database_alias, host, port, database_name, username "
            "FROM tbl_database_credentials WHERE is_active = 1 "
            "ORDER BY database_alias COLLATE NOCASE, id"
        ).fetchall()
    return [_row_to_public(row) for row in rows]


def get_database(database_id):
    try:
        database_id = int(database_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Database selection is invalid.") from exc
    with store() as database:
        row = database.execute(
            "SELECT id, database_alias, host, port, database_name, username "
            "FROM tbl_database_credentials WHERE id = ? AND is_active = 1",
            (database_id,),
        ).fetchone()
    if not row:
        raise ValueError("The selected database configuration was not found.")
    return _row_to_public(row)


def connection_config(record, password):
    password = str(password or "")
    if not password:
        raise ValueError("Password is required for every database connection.")
    return {
        "host": record["host"],
        "port": record["port"],
        "database": record["databaseName"],
        "username": record["username"],
        "password": password,
    }


def save_database(alias, config):
    alias = str(alias or "").strip()
    if not alias or len(alias) > 100:
        raise ValueError("Database alias is required and must be 100 characters or fewer.")
    created_by = os.getenv("APP_USER") or getpass.getuser() or "local-user"
    try:
        with store() as database:
            cursor = database.execute(
                "INSERT INTO tbl_database_credentials "
                "(database_alias, host, port, database_name, username, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (alias, config["host"], config["port"], config["database"], config["username"], created_by),
            )
            database.commit()
            database_id = cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError(
            "This database configuration already exists. Please select it from the existing database list."
        ) from exc
    return get_database(database_id)


def update_database(database_id, alias, config):
    alias = str(alias or "").strip()
    if not alias or len(alias) > 100:
        raise ValueError("Database alias is required and must be 100 characters or fewer.")
    editor = os.getenv("APP_USER") or getpass.getuser() or "local-user"
    try:
        with store() as database:
            database.execute(
                "UPDATE tbl_database_credentials SET database_alias = ?, host = ?, port = ?, "
                "database_name = ?, username = ?, updated_by = ?, updated_date = CURRENT_TIMESTAMP "
                "WHERE id = ? AND is_active = 1",
                (alias, config["host"], config["port"], config["database"], config["username"], editor, int(database_id)),
            )
            if database.total_changes == 0:
                raise ValueError("The selected database configuration was not found.")
            database.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError(
            "This database configuration already exists. Please select it from the existing database list."
        ) from exc
    return get_database(database_id)