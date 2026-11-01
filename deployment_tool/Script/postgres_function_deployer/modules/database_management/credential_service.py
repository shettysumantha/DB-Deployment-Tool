import getpass
import os
import threading
from contextlib import contextmanager

import psycopg2
from cryptography.fernet import Fernet, InvalidToken
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from core.config.config import APP_DATABASE_URL


# ==========================================================
# LOAD ENVIRONMENT
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env"
)

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False
)


# ==========================================================
# APPLICATION DATABASE CONFIGURATION
# ==========================================================

APP_DB_URL = APP_DATABASE_URL


# ==========================================================
# VALIDATE APPLICATION DATABASE CONFIGURATION
# ==========================================================

def _validate_database_url():
    if not APP_DB_URL:
        raise RuntimeError(
            "APP_DATABASE_URL is not configured.\n"
            "Add the PostgreSQL application database "
            "connection URL to the .env file."
        )


# ==========================================================
# POSTGRESQL TABLE
# ==========================================================

DDL = """
CREATE TABLE IF NOT EXISTS tbl_database_credentials (
    id BIGSERIAL PRIMARY KEY,

    database_alias VARCHAR(100) NOT NULL,

    host TEXT NOT NULL,

    port INTEGER NOT NULL,

    database_name TEXT NOT NULL,

    username TEXT NOT NULL,

    environment VARCHAR(20) NOT NULL DEFAULT 'DEVELOPMENT',

    sslmode TEXT,

    created_by TEXT NOT NULL,

    created_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_by TEXT,

    updated_date TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT uq_tbl_database_credentials
        UNIQUE (
            host,
            port,
            database_name,
            username
        )
);

ALTER TABLE tbl_database_credentials
    ADD COLUMN IF NOT EXISTS environment VARCHAR(20)
    NOT NULL DEFAULT 'DEVELOPMENT';

ALTER TABLE tbl_database_credentials
    ADD COLUMN IF NOT EXISTS password_ciphertext TEXT;
"""

ENVIRONMENTS = {"LOCAL", "DEVELOPMENT", "TEST", "PRODUCTION"}
_schema_initialized = False
_schema_lock = threading.Lock()


def _clean_environment(value):
    environment = str(value or "DEVELOPMENT").strip().upper()
    if environment not in ENVIRONMENTS:
        raise ValueError("Environment must be LOCAL, DEVELOPMENT, TEST, or PRODUCTION.")
    return environment


def _password_cipher():
    key = os.getenv("DATABASE_CREDENTIALS_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "DATABASE_CREDENTIALS_ENCRYPTION_KEY must be configured before saving or reusing database passwords."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "DATABASE_CREDENTIALS_ENCRYPTION_KEY must be a valid Fernet key."
        ) from exc


def _encrypt_password(password):
    return _password_cipher().encrypt(str(password).encode("utf-8")).decode("ascii")


def _decrypt_password(ciphertext):
    try:
        return _password_cipher().decrypt(str(ciphertext).encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "A saved database password could not be decrypted. Verify the configured encryption key."
        ) from exc


# ==========================================================
# APPLICATION DATABASE CONNECTION
# ==========================================================

@contextmanager
def store():
    global _schema_initialized

    _validate_database_url()

    database = None

    try:

        database = psycopg2.connect(
            APP_DB_URL
        )

        database.autocommit = False

        if not _schema_initialized:
            with _schema_lock:
                if not _schema_initialized:
                    with database.cursor(cursor_factory=RealDictCursor) as cursor:
                        cursor.execute(DDL)
                    database.commit()
                    _schema_initialized = True

        yield database

    except Exception:

        if database:
            database.rollback()

        raise

    finally:

        if database:
            database.close()


# ==========================================================
# ROW CONVERSION
# ==========================================================

def _row_to_public(row):

    if not row:
        return None

    return {
        "id": row["id"],

        "databaseAlias":
            row["database_alias"],

        "host":
            row["host"],

        "port":
            row["port"],

        "databaseName":
            row["database_name"],

        "username":
            row["username"],

        "environment":
            row["environment"],

        "sslmode":
            row["sslmode"] or "",
    }


# ==========================================================
# LIST DATABASE CONFIGURATIONS
# ==========================================================

def list_databases():

    with store() as database:

        with database.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    database_alias,
                    host,
                    port,
                    database_name,
                    username,
                    environment,
                    sslmode
                FROM tbl_database_credentials
                WHERE is_active = TRUE
                ORDER BY
                    LOWER(database_alias),
                    id
                """
            )

            rows = cursor.fetchall()

    return [
        _row_to_public(row)
        for row in rows
    ]


# ==========================================================
# GET DATABASE CONFIGURATION
# ==========================================================

def get_database(database_id):

    try:

        database_id = int(
            database_id
        )

    except (
        TypeError,
        ValueError
    ) as exc:

        raise ValueError(
            "Database selection is invalid."
        ) from exc

    with store() as database:

        with database.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    database_alias,
                    host,
                    port,
                    database_name,
                    username,
                    environment,
                    sslmode
                FROM tbl_database_credentials
                WHERE id = %s
                  AND is_active = TRUE
                """,
                (
                    database_id,
                )
            )

            row = cursor.fetchone()

    if not row:

        raise ValueError(
            "The selected database configuration "
            "was not found."
        )

    return _row_to_public(
        row
    )


def get_database_password(database_id):
    try:
        database_id = int(database_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Database selection is invalid.") from exc

    with store() as database:
        with database.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """SELECT password_ciphertext
                   FROM tbl_database_credentials
                   WHERE id = %s AND is_active = TRUE""",
                (database_id,),
            )
            row = cursor.fetchone()

    if not row or not row["password_ciphertext"]:
        return None
    return _decrypt_password(row["password_ciphertext"])


def delete_database(database_id):
    try:
        database_id = int(database_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Database selection is invalid.") from exc

    with store() as database:
        with database.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """DELETE FROM tbl_database_credentials
                   WHERE id = %s
                   RETURNING id""",
                (database_id,),
            )
            deleted = cursor.fetchone()
        if not deleted:
            raise ValueError("The selected saved connection was not found.")
        database.commit()


# ==========================================================
# BUILD CONNECTION CONFIGURATION
# ==========================================================

def connection_config(
    record,
    password=None,
):

    password = str(password or "")
    if not password and record.get("id"):
        password = get_database_password(record["id"]) or ""

    if not password and not record.get("id"):

        raise ValueError(
            "Password is required for "
            "every database connection."
        )

    config = {

        "host":
            record["host"],

        "port":
            record["port"],

        "database":
            record["databaseName"],

        "username":
            record["username"],

        "password":
            password,
    }

    # ------------------------------------------------------
    # SSL CONFIGURATION
    # ------------------------------------------------------
    # The current UI does not require the user to enter
    # SSL mode. Render PostgreSQL requires SSL/TLS.
    #
    # If an SSL mode was saved in the database, use it.
    # Otherwise default to "require".
    # ------------------------------------------------------

    sslmode = str(
        (
            record or {}
        ).get(
            "sslmode"
        ) or ""
    ).strip()

    if not sslmode:
        sslmode = "require"

    config["sslmode"] = sslmode

    return config


# ==========================================================
# SAVE DATABASE CONFIGURATION
# ==========================================================

def save_database(
    alias,
    config,
    environment=None,
):

    alias = str(
        alias or ""
    ).strip()

    if (
        not alias
        or len(alias) > 100
    ):

        raise ValueError(
            "Database alias is required "
            "and must be 100 characters "
            "or fewer."
        )

    created_by = (
        os.getenv(
            "APP_USER"
        )
        or getpass.getuser()
        or "local-user"
    )

    # ------------------------------------------------------
    # SSL MODE
    # ------------------------------------------------------
    # If the UI does not provide sslmode, save "require"
    # so the configuration is ready for Render PostgreSQL.
    # ------------------------------------------------------

    sslmode = str(
        config.get(
            "sslmode",
            ""
        )
    ).strip()

    if not sslmode:
        sslmode = "require"

    environment = _clean_environment(environment or config.get("environment"))

    try:

        with store() as database:

            with database.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:

                cursor.execute(
                    """
                    INSERT INTO
                        tbl_database_credentials
                    (
                        database_alias,
                        host,
                        port,
                        database_name,
                        username,
                        environment,
                        sslmode,
                        password_ciphertext,
                        created_by
                    )
                    VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING id
                    """,
                    (
                        alias,
                        config["host"],
                        config["port"],
                        config["database"],
                        config["username"],
                        environment,
                        sslmode,
                        _encrypt_password(config["password"]),
                        created_by,
                    )
                )

                row = cursor.fetchone()

                database.commit()

                database_id = row[
                    "id"
                ]

    except psycopg2.errors.UniqueViolation:

        raise ValueError(
            "This database configuration "
            "already exists. Please select "
            "it from the existing database list."
        )

    return get_database(
        database_id
    )


# ==========================================================
# UPDATE DATABASE CONFIGURATION
# ==========================================================

def update_database(
    database_id,
    alias,
    config,
    environment=None,
):

    alias = str(
        alias or ""
    ).strip()

    if (
        not alias
        or len(alias) > 100
    ):

        raise ValueError(
            "Database alias is required "
            "and must be 100 characters "
            "or fewer."
        )

    try:

        database_id = int(
            database_id
        )

    except (
        TypeError,
        ValueError
    ) as exc:

        raise ValueError(
            "Database selection is invalid."
        ) from exc

    editor = (
        os.getenv(
            "APP_USER"
        )
        or getpass.getuser()
        or "local-user"
    )

    # ------------------------------------------------------
    # SSL MODE
    # ------------------------------------------------------

    sslmode = str(
        config.get(
            "sslmode",
            ""
        )
    ).strip()

    if not sslmode:
        sslmode = "require"

    environment = _clean_environment(environment) if environment is not None else None

    try:

        with store() as database:

            with database.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE
                        tbl_database_credentials
                    SET
                        database_alias = %s,
                        host = %s,
                        port = %s,
                        database_name = %s,
                        username = %s,
                        environment = COALESCE(%s, environment),
                        sslmode = %s,
                        password_ciphertext = %s,
                        updated_by = %s,
                        updated_date =
                            CURRENT_TIMESTAMP
                    WHERE
                        id = %s
                        AND is_active = TRUE
                    """,
                    (
                        alias,
                        config["host"],
                        config["port"],
                        config["database"],
                        config["username"],
                        environment,
                        sslmode,
                        _encrypt_password(config["password"]),
                        editor,
                        database_id,
                    )
                )

                if cursor.rowcount == 0:

                    raise ValueError(
                        "The selected database "
                        "configuration was not found."
                    )

            database.commit()

    except psycopg2.errors.UniqueViolation:

        raise ValueError(
            "This database configuration "
            "already exists. Please select "
            "it from the existing database list."
        )

    return get_database(
        database_id
    )