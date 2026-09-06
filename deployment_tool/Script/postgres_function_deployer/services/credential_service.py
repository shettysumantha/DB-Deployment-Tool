import getpass
import os
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv


# ==========================================================
# LOAD ENVIRONMENT
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env"
)

load_dotenv(
    dotenv_path=ENV_FILE,
    override=True
)


# ==========================================================
# APPLICATION DATABASE CONFIGURATION
# ==========================================================

APP_DB_URL = os.getenv(
    "APP_DATABASE_URL",
    ""
).strip()


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
"""


# ==========================================================
# APPLICATION DATABASE CONNECTION
# ==========================================================

@contextmanager
def store():

    _validate_database_url()

    database = None

    try:

        database = psycopg2.connect(
            APP_DB_URL
        )

        database.autocommit = False

        with database.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:

            cursor.execute(
                DDL
            )

        database.commit()

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


# ==========================================================
# BUILD CONNECTION CONFIGURATION
# ==========================================================

def connection_config(
    record,
    password
):

    password = str(
        password or ""
    )

    if not password:

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
    config
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
                        sslmode,
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
                        sslmode,
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
    config
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
                        sslmode = %s,
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
                        sslmode,
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