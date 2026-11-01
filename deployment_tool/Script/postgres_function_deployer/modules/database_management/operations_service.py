import json
import re
import secrets

import psycopg2
from psycopg2.extras import RealDictCursor

from core.database.db_service import clean_config


QUERY_TIMEOUT_MS = 5000
QUERY_MAX_ROWS = 500
QUERY_MAX_COLUMNS = 100
QUERY_MAX_CELL_LENGTH = 10000
QUERY_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
QUERY_FETCH_BATCH = 10
VACUUM_TIMEOUT_MS = 30000
MAX_QUERY_LENGTH = 10000

_FORBIDDEN_KEYWORDS = {
    "ALTER", "ANALYZE", "BEGIN", "CALL", "CHECKPOINT", "COMMIT", "COPY",
    "CREATE", "DEALLOCATE", "DELETE", "DISCARD", "DO", "DROP", "EXECUTE",
    "FOR", "GRANT", "INSERT", "LOCK", "MERGE", "PREPARE", "REFRESH", "REINDEX",
    "RESET", "REVOKE", "ROLLBACK", "SET", "TRUNCATE", "UPDATE", "VACUUM",
}
_FORBIDDEN_FUNCTIONS = {
    "DBLINK", "LO_EXPORT", "LO_IMPORT", "LO_UNLINK", "NEXTVAL",
    "PG_ADVISORY_LOCK", "PG_ADVISORY_XACT_LOCK", "PG_CANCEL_BACKEND",
    "PG_LS_DIR", "PG_NOTIFY", "PG_READ_BINARY_FILE", "PG_READ_FILE",
    "PG_RELOAD_CONF", "PG_ROTATE_LOGFILE", "PG_SLEEP", "PG_STAT_FILE",
    "PG_TERMINATE_BACKEND", "SETVAL", "SET_CONFIG",
}
_FORBIDDEN_FUNCTION_PREFIXES = ("DBLINK_", "LO_", "PG_ADVISORY_", "PG_SLEEP_")
_IDENTIFIER = r"(?:[a-z_][a-z0-9_$]*)(?:\.(?:[a-z_][a-z0-9_$]*))?"
_VACUUM_ANALYZE = re.compile(
    rf"\s*VACUUM\s+ANALYZE\s+({_IDENTIFIER})\s*;?\s*",
    re.IGNORECASE,
)


def _tokens_and_semicolons(sql):
    tokens = []
    quoted_function_tokens = []
    semicolons = 0
    index = 0
    length = len(sql)

    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = length if newline == -1 else newline + 1
            continue
        if sql.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if sql.startswith("/*", index):
                    depth += 1
                    index += 2
                elif sql.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise ValueError("SQL contains an unterminated comment.")
            continue
        if char == '"':
            index += 1
            quoted_identifier = []
            while index < length:
                if sql[index] == '"':
                    if index + 1 < length and sql[index + 1] == '"':
                        quoted_identifier.append('"')
                        index += 2
                        continue
                    index += 1
                    break
                quoted_identifier.append(sql[index])
                index += 1
            else:
                raise ValueError("SQL contains an unterminated quoted identifier.")
            next_index = index
            while next_index < length and sql[next_index].isspace():
                next_index += 1
            if next_index < length and sql[next_index] == "(":
                quoted_function_tokens.append("".join(quoted_identifier).upper())
            continue
        if char == "'":
            quote = char
            index += 1
            while index < length:
                if sql[index] == quote:
                    if index + 1 < length and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                if sql[index] == "\\" and quote == "'" and index + 1 < length:
                    index += 2
                else:
                    index += 1
            else:
                raise ValueError("SQL contains an unterminated quoted value.")
            continue
        if char == "$":
            delimiter = re.match(r"\$[a-zA-Z_0-9]*\$", sql[index:])
            if delimiter:
                tag = delimiter.group(0)
                end = sql.find(tag, index + len(tag))
                if end == -1:
                    raise ValueError("SQL contains an unterminated quoted value.")
                index = end + len(tag)
                continue
        if char == ";":
            semicolons += 1
            index += 1
            continue
        word = re.match(r"[a-zA-Z_][a-zA-Z_0-9$]*", sql[index:])
        if word:
            tokens.append(word.group(0).upper())
            index += len(word.group(0))
            continue
        index += 1

    return tokens, quoted_function_tokens, semicolons


def _contains_forbidden_function(tokens):
    return any(
        token in _FORBIDDEN_FUNCTIONS
        or token.startswith(_FORBIDDEN_FUNCTION_PREFIXES)
        for token in tokens
    )


def validate_read_query(sql):
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("Enter a SELECT query.")
    if len(sql) > MAX_QUERY_LENGTH:
        raise ValueError(f"SQL query must be {MAX_QUERY_LENGTH} characters or fewer.")

    tokens, quoted_function_tokens, semicolons = _tokens_and_semicolons(sql)
    if not tokens or tokens[0] not in {"SELECT", "WITH"}:
        raise ValueError("Only read-only SELECT queries are allowed.")
    if semicolons > 1 or (semicolons == 1 and not sql.rstrip().endswith(";")):
        raise ValueError("Submit exactly one SQL statement.")
    if _FORBIDDEN_KEYWORDS.intersection(tokens):
        raise ValueError("The SQL query contains a disallowed operation.")
    if "INTO" in tokens:
        raise ValueError("SELECT INTO is not allowed.")
    if _contains_forbidden_function(tokens) or _contains_forbidden_function(
        quoted_function_tokens
    ):
        raise ValueError("The SQL query contains a disallowed function.")

    return sql.strip().rstrip(";").strip()


def _connect(config, *, autocommit=False, readonly=False):
    connection_config = clean_config(config)
    connection_config.update(
        connect_timeout=10,
        application_name="postgres-function-deployer",
    )
    connection = psycopg2.connect(**connection_config)
    connection.autocommit = autocommit
    if readonly:
        connection.set_session(readonly=True, autocommit=False)
    return connection


def _health_query(cursor, sql):
    cursor.execute(sql)
    return cursor.fetchone()


def inspect_database(config):
    connection = _connect(config, readonly=True)
    try:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SET LOCAL statement_timeout = '5000ms'")
            facts = _health_query(
                cursor,
                """
                SELECT current_database() AS database_name,
                       current_user AS connected_as,
                       version() AS server_version,
                       pg_database_size(current_database())::bigint AS database_size_bytes,
                       current_setting('max_connections')::integer AS max_connections,
                       (SELECT count(*)::integer FROM pg_stat_activity
                        WHERE datname = current_database()) AS current_connections
                """,
            )
            stats = _health_query(
                cursor,
                """
                SELECT round(
                    100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2
                ) AS cache_hit_percent,
                xact_commit::bigint AS transactions_committed,
                xact_rollback::bigint AS transactions_rolled_back,
                deadlocks::bigint AS deadlocks
                FROM pg_stat_database
                WHERE datname = current_database()
                """,
            ) or {}
            cursor.execute(
                """
                SELECT schemaname, relname AS table_name,
                       n_live_tup::bigint AS estimated_rows,
                       n_dead_tup::bigint AS dead_rows,
                       last_vacuum::text AS last_vacuum,
                       last_autovacuum::text AS last_autovacuum,
                       last_analyze::text AS last_analyze,
                       last_autoanalyze::text AS last_autoanalyze
                FROM pg_stat_user_tables
                ORDER BY n_dead_tup DESC, schemaname, relname
                LIMIT 20
                """
            )
            tables = [dict(row) for row in cursor.fetchall()]
        return {
            "database": dict(facts),
            "statistics": dict(stats),
            "tables": tables,
        }
    finally:
        connection.close()


def _json_value(value):
    if isinstance(value, str) and len(value) > QUERY_MAX_CELL_LENGTH:
        return value[:QUERY_MAX_CELL_LENGTH] + "... [truncated]"
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"[binary data: {len(value)} bytes]"
    return value


def execute_read_query(config, sql):
    query = validate_read_query(sql)
    connection = _connect(config, readonly=True)
    try:
        with connection.cursor() as setup_cursor:
            setup_cursor.execute(
                f"SET LOCAL statement_timeout = '{QUERY_TIMEOUT_MS}ms'"
            )
        with connection.cursor(name=f"db_query_{secrets.token_hex(8)}") as cursor:
            cursor.itersize = QUERY_FETCH_BATCH
            cursor.execute(query)
            if cursor.description is None:
                raise ValueError("The query did not return a result set.")
            if len(cursor.description) > QUERY_MAX_COLUMNS:
                raise ValueError(f"Queries may return at most {QUERY_MAX_COLUMNS} columns.")
            columns = [column.name for column in cursor.description]
            rows = []
            response_size = 0
            truncated = False
            truncation_reason = None
            while len(rows) <= QUERY_MAX_ROWS:
                batch = cursor.fetchmany(QUERY_FETCH_BATCH)
                if not batch:
                    break
                for row in batch:
                    if len(rows) == QUERY_MAX_ROWS:
                        truncated = True
                        truncation_reason = "row_limit"
                        break
                    converted = [_json_value(value) for value in row]
                    row_size = len(
                        json.dumps(
                            converted,
                            ensure_ascii=True,
                            default=str,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
                    if response_size + row_size > QUERY_MAX_RESPONSE_BYTES:
                        truncated = True
                        truncation_reason = "response_size"
                        break
                    rows.append(converted)
                    response_size += row_size
                if truncated:
                    break
            return {
                "columns": columns,
                "rows": [[_json_value(value) for value in row] for row in rows],
                "truncated": truncated,
                "truncation_reason": truncation_reason,
                "row_limit": QUERY_MAX_ROWS,
            }
    finally:
        connection.close()


def vacuum_analyze(config, command):
    if not isinstance(command, str) or len(command) > MAX_QUERY_LENGTH:
        raise ValueError("Enter a targeted VACUUM ANALYZE command.")
    match = _VACUUM_ANALYZE.fullmatch(command)
    if not match:
        raise ValueError(
            "Only targeted VACUUM ANALYZE <table> commands are allowed."
        )

    table_name = match.group(1)
    connection = _connect(config, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SET statement_timeout = '{VACUUM_TIMEOUT_MS}ms'")
            cursor.execute(f"VACUUM (ANALYZE) {table_name}")
        return {"message": f"VACUUM ANALYZE completed for {table_name}."}
    finally:
        connection.close()
