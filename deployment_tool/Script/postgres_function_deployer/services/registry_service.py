import os
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv

from .db_service import connection


# ==========================================================
# LOAD .ENV
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

ENV_FILE = BASE_DIR / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=True
)

# ==========================================================
# APPLICATION DATABASE CONFIGURATION
# ==========================================================

def _application_database_config():
    database_url = os.getenv("APP_DATABASE_URL", "").strip()

    if not database_url:
        return None

    parsed = urlparse(database_url)

    if parsed.scheme not in ("postgresql", "postgres") or not parsed.hostname:
        raise ValueError(
            "APP_DATABASE_URL must be a PostgreSQL connection URL."
        )

    query_params = parse_qs(parsed.query)

    sslmode = query_params.get(
        "sslmode",
        ["require"]
    )[0]

    return {
        "host": parsed.hostname,
        "port": parsed.port or 5432,
        "database": (parsed.path or "").lstrip("/"),
        "username": parsed.username or "",
        "password": parsed.password or "",
        "sslmode": sslmode,
    }


def application_database_configured():
    return bool(
        os.getenv("APP_DATABASE_URL", "").strip()
    )


# ==========================================================
# REGISTRY DATABASE CONNECTION
# ==========================================================

@contextmanager
def registry_connection(live_config):

    application_config = _application_database_config()

    if application_config:
        with connection(application_config) as conn:
            yield conn
        return

    # Fallback to LIVE database only when
    # APP_DATABASE_URL is not configured.
    with connection(live_config) as conn:
        yield conn


# ==========================================================
# INSERT BACKUP REGISTRY RECORD
# ==========================================================

def insert_backup(
    config,
    object_type,
    record,
    backup,
    deployment_id,
    version,
    deployment_type,
    status="PENDING",
    notes=""
):

    with registry_connection(config) as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO public.tbl_deployment_backup_registry
                (
                    object_type,
                    schema_name,
                    object_name,
                    object_signature,
                    backup_file_name,
                    backup_file_path,
                    backup_file_type,
                    backup_created_at,
                    deployment_version,
                    deployment_id,
                    deployment_type,
                    previous_object_status,
                    deployment_status,
                    deployed_by,
                    file_size_bytes,
                    file_checksum,
                    notes
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'SQL',
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    current_user,
                    %s,
                    %s,
                    %s
                )
                RETURNING backup_id
                """,
                (
                    object_type,
                    record.get(
                        "schema",
                        "public"
                    ),
                    record["name"],
                    record.get(
                        "signature",
                        record.get("key")
                    ),
                    backup.get(
                        "file_name"
                    ),
                    backup.get(
                        "file_path"
                    ),
                    backup.get(
                        "created_at"
                    ),
                    version,
                    deployment_id,
                    deployment_type,
                    status,
                    status,
                    backup.get(
                        "size"
                    ),
                    backup.get(
                        "checksum"
                    ),
                    notes,
                )
            )

            row = cursor.fetchone()

            backup_id = row[0]

        conn.commit()

    return backup_id


# ==========================================================
# UPDATE DEPLOYMENT STATUS
# ==========================================================

def update_status(
    config,
    deployment_id,
    status
):

    with registry_connection(config) as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                UPDATE public.tbl_deployment_backup_registry
                SET
                    deployment_status = %s,
                    deployed_at = now(),
                    updated_at = now()
                WHERE deployment_id = %s
                """,
                (
                    status,
                    deployment_id,
                )
            )

        conn.commit()


# ==========================================================
# SEARCH BACKUP REGISTRY
# ==========================================================

def search_backups(
    config,
    params
):

    clauses = []
    values = []

    searchable_fields = (
        "backup_id",
        "backup_file_name",
        "object_name",
        "object_type",
        "deployment_id",
        "deployment_version",
        "deployment_status",
    )

    for field in searchable_fields:

        if params.get(field):

            clauses.append(
                f"{field}::text ILIKE %s"
            )

            values.append(
                f"%{params[field]}%"
            )

    if clauses:

        where_clause = (
            " WHERE "
            + " AND ".join(clauses)
        )

    else:

        where_clause = ""

    query = (
        """
        SELECT
            backup_id,
            object_type,
            schema_name,
            object_name,
            backup_file_name,
            backup_file_path,
            deployment_version,
            backup_created_at,
            deployment_id,
            deployment_status,
            file_size_bytes,
            file_checksum
        FROM public.tbl_deployment_backup_registry
        """
        + where_clause
        + """
        ORDER BY
            backup_created_at DESC NULLS LAST
        LIMIT 200
        """
    )

    with registry_connection(config) as conn:

        with conn.cursor() as cursor:

            cursor.execute(
                query,
                values
            )

            columns = [
                column[0]
                for column in cursor.description
            ]

            rows = cursor.fetchall()

            records = [
                dict(
                    zip(
                        columns,
                        row
                    )
                )
                for row in rows
            ]

            for record in records:

                if record.get(
                    "backup_created_at"
                ):

                    record[
                        "backup_created_at"
                    ] = record[
                        "backup_created_at"
                    ].isoformat()

            return records