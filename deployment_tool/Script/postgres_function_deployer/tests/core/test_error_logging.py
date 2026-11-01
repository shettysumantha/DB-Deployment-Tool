import logging
import unittest
from unittest.mock import MagicMock, patch

from flask import g, session

from core import error_logging


class ApplicationErrorLoggingTests(unittest.TestCase):
    def test_write_error_log_redacts_common_secrets_and_commits(self):
        connection = MagicMock()
        with patch.object(
            error_logging, "security_connection", return_value=connection
        ):
            error_logging.write_error_log(
                log_level="ERROR",
                error_type="RuntimeError",
                error_message="connection failed password=hunter2 token=abc123",
                endpoint="/admin/modules",
                http_method="GET",
                http_status=500,
                user_id=7,
                username="admin",
                request_id="request-id",
            )

        parameters = connection.__enter__.return_value.cursor.return_value.__enter__.return_value.execute.call_args.args[1]
        self.assertIn("password=[REDACTED]", parameters[2])
        self.assertIn("token=[REDACTED]", parameters[2])
        self.assertNotIn("hunter2", parameters[2])
        self.assertNotIn("abc123", parameters[2])
        connection.__enter__.return_value.commit.assert_called_once_with()

    def test_error_handler_records_route_actor_and_request_id(self):
        from app import app

        with app.test_request_context("/admin/modules", method="GET"):
            session.update(user_id=7, username="admin")
            g.request_id = "request-id"
            g.error_http_status = 500
            exception = RuntimeError("module query failed")
            record = logging.LogRecord(
                name="postgres_function_deployer.app",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="module query failed",
                args=(),
                exc_info=(RuntimeError, exception, None),
            )
            with patch.object(error_logging, "write_error_log") as write_log:
                error_logging.DatabaseErrorLogHandler().emit(record)

        write_log.assert_called_once_with(
            log_level="ERROR",
            error_type="RuntimeError",
            error_message="module query failed",
            endpoint="/admin/modules",
            http_method="GET",
            http_status=500,
            user_id=7,
            username="admin",
            request_id="request-id",
        )

    def test_unhandled_error_handler_returns_generic_500_and_logs_request_id(self):
        import app as app_module

        with app_module.app.test_request_context("/admin/modules", method="GET"):
            g.request_id = "request-id"
            exception = RuntimeError("internal detail")
            with patch.object(app_module.app.logger, "error") as log_error:
                response, status = app_module.handle_unexpected_error(exception)

        self.assertEqual(status, 500)
        self.assertIn("Contact an administrator", response)
        log_error.assert_called_once()
        self.assertEqual(log_error.call_args.args[0], "Unhandled application error")
        self.assertNotIn("internal detail", response)

    def test_catalog_migration_contains_cockroach_compatible_error_log_schema(self):
        from pathlib import Path

        app_root = Path(__file__).resolve().parents[2]
        migration = (
            app_root / "database" / "migrations"
            / "20261101_module_endpoint_catalog.sql"
        ).read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS public.tbl_errorlogs", migration)
        self.assertIn("logged_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP", migration)
        self.assertIn("error_message TEXT NOT NULL", migration)
        self.assertIn("ON DELETE NO ACTION", migration)
        self.assertNotIn("ON DELETE RESTRICT", migration)

    def test_fresh_install_schema_includes_error_log_table(self):
        from pathlib import Path

        app_root = Path(__file__).resolve().parents[2]
        schema = (app_root / "database" / "database_security.sql").read_text(
            encoding="utf-8"
        )

        self.assertIn("CREATE TABLE IF NOT EXISTS public.tbl_errorlogs", schema)
        self.assertIn("CREATE INDEX IF NOT EXISTS ix_tbl_errorlogs_logged_at", schema)


if __name__ == "__main__":
    unittest.main()
