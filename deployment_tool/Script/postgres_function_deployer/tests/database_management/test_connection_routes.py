import unittest
from unittest.mock import patch


class DatabaseConnectionRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core.security import security_service

        with patch.object(security_service, "initialize_security", return_value=True):
            import app as app_module
        cls.app_module = app_module

    def setUp(self):
        app = self.app_module
        self.patches = [
            patch.object(app, "ensure_security_initialized", return_value=True),
            patch.object(
                app,
                "user_session_state",
                return_value={
                    "is_active": True,
                    "session_version": 1,
                    "must_change_password": False,
                },
            ),
            patch.object(app, "user_menus", return_value=[]),
            patch.object(app, "user_roles", return_value=[]),
            patch.object(app, "require_any_permission", return_value=None),
            patch.object(app, "require_permission", return_value=None),
        ]
        for active_patch in self.patches:
            active_patch.start()
        self.addCleanup(self._stop_patches)
        self.client = app.app.test_client()
        with self.client.session_transaction() as user_session:
            user_session.update(
                user_id=7,
                session_version=1,
                _csrf_token="test-csrf",
            )

    def _stop_patches(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def _headers(self):
        return {"X-CSRFToken": "test-csrf"}

    def test_saved_connection_is_connected_only_after_explicit_connect(self):
        record = {
            "id": 22,
            "host": "db.example.test",
            "databaseName": "test_db",
        }
        with self.client.session_transaction() as user_session:
            user_session["connected_database_id"] = 17
        with patch.object(self.app_module, "get_database", return_value=record), patch.object(
            self.app_module, "_payload_config", return_value={"database": "test_db"}
        ), patch.object(
            self.app_module, "test_connection", return_value={"database": "test_db"}
        ) as test_connection:
            response = self.client.post(
                "/api/database-connections/22/connect",
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["connected_connection"], record)
        test_connection.assert_called_once_with({"database": "test_db"})
        with self.client.session_transaction() as user_session:
            self.assertEqual(user_session["connected_database_id"], 22)

    def test_failed_connect_does_not_leave_a_connection_active(self):
        with self.client.session_transaction() as user_session:
            user_session["connected_database_id"] = 17
        with patch.object(
            self.app_module, "get_database", side_effect=ValueError("not found")
        ):
            response = self.client.post(
                "/api/database-connections/999/connect",
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(response.json["connected_connection"])
        with self.client.session_transaction() as user_session:
            self.assertNotIn("connected_database_id", user_session)

    def test_legacy_auto_selected_connection_is_not_treated_as_connected(self):
        with self.client.session_transaction() as user_session:
            user_session["active_database_id"] = 17
        with patch.object(self.app_module, "inspect_database") as inspect_database:
            response = self.client.get("/api/database-health")
        self.assertEqual(response.status_code, 409)
        inspect_database.assert_not_called()
        with self.client.session_transaction() as user_session:
            self.assertNotIn("active_database_id", user_session)
            self.assertNotIn("connected_database_id", user_session)

    def test_disconnect_keeps_the_saved_connection_and_clears_session_state(self):
        with self.client.session_transaction() as user_session:
            user_session["connected_database_id"] = 17
        with patch.object(self.app_module, "_connected_database_record", return_value=None):
            response = self.client.post(
                "/api/database-connections/17/disconnect",
                headers=self._headers(),
            )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json["connected_connection"])
        with self.client.session_transaction() as user_session:
            self.assertNotIn("connected_database_id", user_session)

    def test_create_connection_does_not_require_alias(self):
        record = {"id": 17, "host": "db.example.test", "databaseName": "demo"}
        with patch.object(
            self.app_module,
            "_payload_config",
            return_value={"host": "db.example.test", "database": "demo"},
        ), patch.object(
            self.app_module, "test_connection", return_value={"database": "demo"}
        ), patch.object(
            self.app_module, "save_database", return_value=record
        ) as save_database:
            response = self.client.post(
                "/api/admin/database-connections",
                json={
                    "host": "db.example.test",
                    "port": "5432",
                    "database": "demo",
                    "username": "demo_user",
                    "password": "demo-password",
                    "environment": "TEST",
                },
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["database"], record)
        self.assertIsNone(save_database.call_args.args[0])
        with self.client.session_transaction() as user_session:
            self.assertNotIn("connected_database_id", user_session)

    def test_delete_removes_only_selected_saved_connection_and_clears_active_state(self):
        with self.client.session_transaction() as user_session:
            user_session["connected_database_id"] = 17
        with patch.object(self.app_module, "delete_database") as delete_database:
            response = self.client.delete(
                "/api/admin/database-connections/17",
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 200)
        delete_database.assert_called_once_with(17)
        with self.client.session_transaction() as user_session:
            self.assertNotIn("connected_database_id", user_session)

    def test_database_health_requires_an_active_connection(self):
        with patch.object(self.app_module, "_connected_database_record", return_value=None), patch.object(
            self.app_module, "inspect_database"
        ) as inspect_database:
            response = self.client.get("/api/database-health")

        self.assertEqual(response.status_code, 409)
        inspect_database.assert_not_called()

    def test_database_tools_page_renders_for_authorized_users(self):
        response = self.client.get("/database-tools")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SQL Query Tool", response.data)
        self.assertIn(b"Restricted SQL query", response.data)
        self.assertIn(b'<div class="database-tools page-shell">', response.data)

    def test_database_health_dashboard_uses_saved_connections(self):
        with patch.object(self.app_module, "list_databases", return_value=[]):
            response = self.client.get("/database-health")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Database Health Dashboard", response.data)
        self.assertIn(b"No database connections available.", response.data)
        self.assertIn(b"Go to Database Management", response.data)

    def test_error_log_page_shows_at_most_220_recent_logs(self):
        logged_error = {
            "error_id": 1,
            "logged_at": None,
            "log_level": "ERROR",
            "error_type": "RuntimeError",
            "error_message": "test failure",
            "module": "admin_modules",
            "operation": "GET /admin/modules",
            "endpoint": "/admin/modules",
            "http_method": "GET",
            "http_status": 500,
            "username": "admin",
            "request_id": "test-request",
        }
        with patch.object(
            self.app_module, "list_error_logs", return_value=[logged_error]
        ) as list_error_logs:
            response = self.client.get("/admin/error-logs")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Application Error Logs", response.data)
        self.assertIn(b"test failure", response.data)
        list_error_logs.assert_called_once_with(220, 0, "")

    def test_error_log_page_and_api_enforce_permission(self):
        def enforce_permission(code, permission="can_view"):
            if not self.app_module._permission_granted(code, permission):
                from flask import abort
                abort(403)

        with patch.object(self.app_module, "_permission_granted", return_value=False), patch.object(
            self.app_module, "require_permission", side_effect=enforce_permission
        ), patch.object(
            self.app_module, "list_error_logs"
        ) as list_error_logs:
            response = self.client.get("/admin/error-logs")
            api_response = self.client.get("/api/admin/error-logs")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(api_response.status_code, 403)
        list_error_logs.assert_not_called()

    def test_database_health_uses_only_the_active_saved_connection(self):
        record = {
            "id": 22,
            "host": "db.example.test",
            "port": 5432,
            "databaseName": "demo",
            "environment": "TEST",
        }
        health = {
            "overview": {"database_name": "demo"},
            "storage": {"tables": [], "indexes": [], "unused_indexes": []},
            "performance": {},
            "maintenance": {},
        }
        with patch.object(self.app_module, "_connected_database_record", return_value=record), patch.object(
            self.app_module, "_payload_config", return_value={"database": "demo"}
        ), patch.object(self.app_module, "inspect_database", return_value=health) as inspect_database:
            response = self.client.get("/api/database-health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["connection"]["id"], 22)
        self.assertEqual(response.json["overview"]["database_name"], "demo")
        inspect_database.assert_called_once_with({"database": "demo"})

    def test_vacuum_analyze_requires_explicit_confirmation(self):
        record = {"id": 22}
        with patch.object(self.app_module, "_connected_database_record", return_value=record), patch.object(
            self.app_module, "_payload_config", return_value={"database": "demo"}
        ), patch.object(self.app_module, "vacuum_analyze") as vacuum_analyze:
            response = self.client.post(
                "/api/database-query",
                json={"operation": "vacuum_analyze", "sql": "VACUUM ANALYZE public.accounts"},
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 400)
        vacuum_analyze.assert_not_called()


if __name__ == "__main__":
    unittest.main()
