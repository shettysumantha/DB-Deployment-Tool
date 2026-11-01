import logging
import re
import sys

from flask import g, has_request_context, request, session
from psycopg2.extras import RealDictCursor

from core.security.security_service import security_connection


_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key)\b(\s*[=:]\s*)[^\s,;&]+"
)
_MAX_MESSAGE_LENGTH = 4000


def _safe_message(message):
    cleaned = _SENSITIVE_VALUE.sub(r"\1\2[REDACTED]", str(message))
    return cleaned.replace("\x00", "")[:_MAX_MESSAGE_LENGTH]


def write_error_log(
    *,
    log_level,
    error_type,
    error_message,
    endpoint=None,
    http_method=None,
    http_status=None,
    user_id=None,
    username=None,
    request_id=None,
):
    with security_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO public.tbl_errorlogs (
                    log_level, error_type, error_message, endpoint, http_method,
                    http_status, user_id, username, request_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(log_level)[:16],
                    str(error_type)[:200] if error_type else None,
                    _safe_message(error_message),
                    endpoint[:500] if endpoint else None,
                    http_method[:16] if http_method else None,
                    http_status,
                    user_id,
                    username[:100] if username else None,
                    request_id[:64] if request_id else None,
                ),
            )
        conn.commit()


def list_error_logs(limit=100, offset=0):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT error_id, logged_at, log_level, error_type, error_message,
                       endpoint, http_method, http_status, username, request_id
                FROM public.tbl_errorlogs
                ORDER BY logged_at DESC, error_id DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]


class DatabaseErrorLogHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.ERROR)

    def emit(self, record):
        if record.name.startswith("database.error_logging"):
            return

        endpoint = None
        http_method = None
        http_status = None
        user_id = None
        username = None
        request_id = None
        if has_request_context():
            endpoint = request.url_rule.rule if request.url_rule else request.path
            http_method = request.method
            http_status = getattr(g, "error_http_status", None)
            user_id = session.get("user_id")
            username = session.get("username")
            request_id = getattr(g, "request_id", None)

        error_type = None
        if record.exc_info and record.exc_info[0]:
            error_type = record.exc_info[0].__name__
        elif record.levelname == "ERROR":
            error_type = "ApplicationError"

        try:
            write_error_log(
                log_level=record.levelname,
                error_type=error_type,
                error_message=record.getMessage(),
                endpoint=endpoint,
                http_method=http_method,
                http_status=http_status,
                user_id=user_id,
                username=username,
                request_id=request_id,
            )
        except Exception as exc:
            sys.stderr.write(
                "Application error could not be written to public.tbl_errorlogs "
                f"({type(exc).__name__}).\n"
            )
            sys.stderr.flush()
