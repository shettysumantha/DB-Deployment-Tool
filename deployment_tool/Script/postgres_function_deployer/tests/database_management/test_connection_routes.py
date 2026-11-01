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

    def test_active_database_list_is_per_session(self):
        record = {
            "id": 8,
            "host": "db.example.test",
            "databaseName": "demo",
        }
        with patch.object(
            self.app_module, "list_databases", return_value=[record]
        ), patch.object(self.app_module, "_active_database_record", return_value=record):
            response = self.client.get("/api/active-database")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["connections"], [record])
        self.assertEqual(response.json["active_connection"], record)
        self.app_module.require_any_permission.assert_called_with(
            "DATABASE_MANAGEMENT",
            "DEPLOYMENT_MANAGER",
            "COMPARISON_RESULTS",
            permission="can_execute",
        )

    def test_switching_active_database_tests_then_sets_new_session_selection(self):
        record = {
            "id": 22,
            "host": "db.example.test",
            "databaseName": "test_db",
        }
        with self.client.session_transaction() as user_session:
            user_session["active_database_id"] = 17
        with patch.object(self.app_module, "get_database", return_value=record), patch.object(
            self.app_module, "_payload_config", return_value={"database": "test_db"}
        ), patch.object(
            self.app_module, "test_connection", return_value={"database": "test_db"}
        ) as test_connection:
            response = self.client.put(
                "/api/active-database",
                json={"database_id": 22},
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["active_connection"], record)
        test_connection.assert_called_once_with({"database": "test_db"})
        with self.client.session_transaction() as user_session:
            self.assertEqual(user_session["active_database_id"], 22)

    def test_failed_switch_clears_previous_active_database(self):
        with self.client.session_transaction() as user_session:
            user_session["active_database_id"] = 17
        with patch.object(
            self.app_module, "get_database", side_effect=ValueError("not found")
        ):
            response = self.client.put(
                "/api/active-database",
                json={"database_id": 999},
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(response.json["active_connection"])
        with self.client.session_transaction() as user_session:
            self.assertNotIn("active_database_id", user_session)

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

    def test_delete_removes_only_selected_saved_connection_and_clears_active_state(self):
        with self.client.session_transaction() as user_session:
            user_session["active_database_id"] = 17
        with patch.object(self.app_module, "delete_database") as delete_database:
            response = self.client.delete(
                "/api/admin/database-connections/17",
                headers=self._headers(),
            )

        self.assertEqual(response.status_code, 200)
        delete_database.assert_called_once_with(17)
        with self.client.session_transaction() as user_session:
            self.assertNotIn("active_database_id", user_session)

    def test_database_health_requires_an_active_connection(self):
        with patch.object(self.app_module, "_active_database_record", return_value=None), patch.object(
            self.app_module, "inspect_database"
        ) as inspect_database:
            response = self.client.get("/api/database-health")

        self.assertEqual(response.status_code, 409)
        inspect_database.assert_not_called()

    def test_database_tools_page_renders_for_authorized_users(self):
        response = self.client.get("/database-tools")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PostgreSQL health", response.data)
        self.assertIn(b"Restricted SQL query", response.data)

    def test_database_health_uses_only_the_active_saved_connection(self):
        record = {
            "id": 22,
            "host": "db.example.test",
            "port": 5432,
            "databaseName": "demo",
            "environment": "TEST",
        }
        health = {"database": {"database_name": "demo"}, "statistics": {}, "tables": []}
        with patch.object(self.app_module, "_active_database_record", return_value=record), patch.object(
            self.app_module, "_payload_config", return_value={"database": "demo"}
        ), patch.object(self.app_module, "inspect_database", return_value=health) as inspect_database:
            response = self.client.get("/api/database-health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["connection"]["id"], 22)
        self.assertEqual(response.json["database"]["database_name"], "demo")
        inspect_database.assert_called_once_with({"database": "demo"})

    def test_vacuum_analyze_requires_explicit_confirmation(self):
        record = {"id": 22}
        with patch.object(self.app_module, "_active_database_record", return_value=record), patch.object(
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
