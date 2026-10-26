import unittest
from io import BytesIO
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psycopg2
from PIL import Image
from werkzeug.exceptions import Forbidden

from core.security import security_service


class FakeCursor:
    def __init__(self, rows=(), first_row=("app_security.users",)):
        self.rows = rows
        self.first_row = first_row
        self.description = [SimpleNamespace(name="user_id")]
        self.executed = []

    def execute(self, query, parameters):
        self.executed.append((query, parameters))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.first_row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor

    def cursor(self):
        return self.cursor_instance

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeSearchCursor(FakeCursor):
    def __init__(self):
        super().__init__(rows=[("122,456",)], first_row=(13,))
        self.description = [SimpleNamespace(name="module_ids")]

    def fetchone(self):
        return (13,) if "COUNT(*)" in self.executed[-1][0] else self.first_row


class SecurityPaginationTests(unittest.TestCase):
    def test_user_module_assignments_use_registry_module_ids(self):
        cursor = FakeAssignmentCursor()
        security_service._save_user_modules(cursor, 7, ["12", "8", "12"])

        statements = cursor.executed
        self.assertEqual(
            next(parameters for query, parameters in statements if "SELECT module_id" in query),
            ([8, 12],),
        )
        inserts = [item for item in statements if "INSERT INTO app_security.user_module_access" in item[0]]
        self.assertEqual([item[1] for item in inserts], [(7, 8), (7, 12)])
        self.assertTrue(any("module_access_configured = TRUE" in query for query, _ in statements))

    def test_search_uses_escaped_parameter_and_server_pagination(self):
        cursor = FakeSearchCursor()
        rows, total = security_service._fetch_searched_users(
            cursor, 11, 20, "Ann%_!"
        )

        self.assertEqual(rows, [{"module_ids": [122, 456]}])
        self.assertEqual(total, 13)
        self.assertEqual(cursor.executed[0][1], ("%Ann!%!_!!%",) * 3)
        self.assertEqual(cursor.executed[1][1], ("%Ann!%!_!!%",) * 3 + (11, 20))
        self.assertIn("ILIKE", cursor.executed[1][0])

    def test_user_list_calls_paged_function_with_bounded_limit(self):
        cursor = FakeCursor(rows=[(42,)])
        with patch.object(security_service, "security_connection", return_value=FakeConnection(cursor)):
            users = security_service.list_users(limit=500, offset=-5)

        self.assertEqual(users, [{"user_id": 42, "module_ids": []}])
        self.assertEqual(cursor.executed[0][1], (101, 0, None))
        self.assertIn("app_security.fn_get_users", cursor.executed[0][0])

    def test_user_list_normalizes_database_module_ids_to_integer_list(self):
        cursor = FakeCursor(rows=[("122, 456,789",)])
        cursor.description = [SimpleNamespace(name="module_ids")]
        with patch.object(security_service, "security_connection", return_value=FakeConnection(cursor)):
            users = security_service.list_users(limit=1)

        self.assertEqual(users, [{"module_ids": [122, 456, 789]}])

    def test_user_management_page_reuses_one_connection(self):
        connection = MagicMock()
        cursor = MagicMock()
        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor

        with patch.object(security_service, "security_connection", return_value=connection) as connect, patch.object(
            security_service, "_fetch_users", return_value=[{"user_id": 42}]
        ) as fetch_users, patch.object(
            security_service, "_fetch_roles", return_value=[{"role_id": 3}]
        ) as fetch_roles, patch.object(
            security_service, "_fetch_modules", return_value=[{"menu_id": 8}]
        ) as fetch_modules:
            result = security_service.list_user_management_data(26, 0)

        self.assertEqual(
            result,
            ([{"user_id": 42}], [{"role_id": 3}], [{"menu_id": 8}]),
        )
        connect.assert_called_once_with()
        fetch_users.assert_called_once_with(cursor, 26, 0)
        fetch_roles.assert_called_once_with(cursor)
        fetch_modules.assert_called_once_with(cursor)

    def test_user_active_boolean_parsing_is_strict(self):
        self.assertFalse(security_service._parse_user_boolean("false", "is_active"))
        self.assertTrue(security_service._parse_user_boolean("true", "is_active"))
        self.assertFalse(security_service._parse_user_boolean(False, "is_active"))
        with self.assertRaisesRegex(ValueError, "is_active must be true or false"):
            security_service._parse_user_boolean("perhaps", "is_active")

    def test_create_user_preserves_false_active_flag(self):
        cursor = FakeMutationCursor()
        connection = FakeMutationConnection(cursor)
        data = {
            "username": "test-user",
            "password": "long-enough-password",
            "confirm_password": "long-enough-password",
            "role_id": 4,
            "is_active": "false",
        }

        with patch.object(security_service, "security_connection", return_value=connection), patch.object(
            security_service, "password_hash", return_value="hash"
        ), patch.object(security_service, "_save_user_modules"), patch.object(
            security_service, "_audit"
        ):
            user_id = security_service.create_user(data)

        insert = next(item for item in cursor.executed if "INSERT INTO app_security.users" in item[0])
        self.assertEqual(user_id, 42)
        self.assertFalse(insert[1][4])
        self.assertTrue(connection.committed)

    def test_update_user_preserves_false_active_flag(self):
        cursor = FakeMutationCursor(update_mode=True)
        connection = FakeMutationConnection(cursor)

        with patch.object(security_service, "security_connection", return_value=connection), patch.object(
            security_service, "_audit"
        ):
            security_service.update_user(
                42,
                {"username": "test-user", "role_id": 4, "is_active": "false"},
            )

        update = next(item for item in cursor.executed if item[0].lstrip().startswith("UPDATE app_security.users"))
        self.assertFalse(update[1][3])
        self.assertTrue(connection.committed)

    def test_update_missing_user_raises_not_found(self):
        cursor = FakeMutationCursor(rowcount=0)
        with patch.object(
            security_service,
            "security_connection",
            return_value=FakeMutationConnection(cursor),
        ):
            with self.assertRaises(security_service.UserNotFoundError):
                security_service.update_user(99, {"username": "missing-user"})

    def test_create_user_rejects_overlong_username_before_connecting(self):
        with patch.object(security_service, "security_connection") as connect:
            with self.assertRaisesRegex(ValueError, "100 characters or fewer"):
                security_service.create_user(
                    {
                        "username": "u" * 101,
                        "password": "long-enough-password",
                        "confirm_password": "long-enough-password",
                        "role_id": 4,
                    }
                )
        connect.assert_not_called()

    def test_initialization_only_checks_existing_schema_objects(self):
        cursor = FakeCursor()
        with patch.object(security_service, "_schema_initialized", False), patch.object(
            security_service, "security_connection", return_value=FakeConnection(cursor)
        ):
            self.assertTrue(security_service.initialize_security())

        self.assertEqual(cursor.executed, [("SELECT to_regclass(%s)", ("app_security.users",))])


class UserManagementRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(security_service, "initialize_security", return_value=True):
            import app as app_module
        cls.app_module = app_module

    def setUp(self):
        self.patches = [
            patch.object(self.app_module, "ensure_security_initialized", return_value=True),
            patch.object(
                self.app_module,
                "user_session_state",
                return_value={"is_active": True, "session_version": 1, "must_change_password": False},
            ),
            patch.object(self.app_module, "require_permission", return_value=None),
        ]
        for active_patch in self.patches:
            active_patch.start()
        self.addCleanup(self._stop_patches)
        self.client = self.app_module.app.test_client()
        with self.client.session_transaction() as user_session:
            user_session["user_id"] = 7
            user_session["session_version"] = 1
            user_session["_csrf_token"] = "test-csrf"

    def _stop_patches(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def _post_json(self, path, data):
        return self.client.post(
            path,
            json=data,
            headers={"X-CSRFToken": "test-csrf"},
        )

    def test_create_api_rejects_non_object_json(self):
        response = self.client.post(
            "/api/admin/users",
            data="[]",
            content_type="application/json",
            headers={"X-CSRFToken": "test-csrf"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"JSON object is required", response.data)

    def test_user_list_api_defaults_to_ten_and_preserves_search(self):
        page_rows = [{"user_id": user_id} for user_id in range(1, 12)]
        with patch.object(
            self.app_module, "list_user_management_page", return_value=(page_rows, [], [], 11)
        ) as list_page:
            response = self.client.get("/api/admin/users?q=partial")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["users"]), 10)
        self.assertEqual(response.get_json()["page_size"], 10)
        self.assertEqual(response.get_json()["total"], 11)
        list_page.assert_called_once_with(11, 0, "partial")

    def test_user_detail_api_returns_selected_user(self):
        detail = {"username": "sample", "roles": ["VIEWER"], "modules": []}
        with patch.object(self.app_module, "get_user_management_detail", return_value=detail):
            response = self.client.get("/api/admin/users/42")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user"], detail)

    def test_user_edit_data_requires_can_edit_permission(self):
        edit_data = {"username": "sample", "role_id": "9223372036854775800", "module_ids": ["9223372036854775801"]}
        with patch.object(self.app_module, "require_permission") as permission, patch.object(
            self.app_module, "get_user_management_edit_data", return_value=edit_data
        ):
            response = self.client.get("/api/admin/users/42/edit")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user"], edit_data)
        permission.assert_called_once_with("USER_MANAGEMENT", "can_edit")

    def test_password_change_failure_keeps_password_form(self):
        with patch.object(self.app_module, "change_password", return_value=False):
            response = self.client.post(
                "/profile/password",
                data={
                    "current_password": "wrong",
                    "new_password": "new-password",
                    "confirm_password": "new-password",
                    "csrf_token": "test-csrf",
                },
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Current password is incorrect", response.data)
        self.assertIn(b"name=\"current_password\"", response.data)

    def test_password_change_success_clears_session(self):
        with patch.object(self.app_module, "change_password", return_value=True):
            response = self.client.post(
                "/profile/password",
                data={
                    "current_password": "correct",
                    "new_password": "new-password",
                    "confirm_password": "new-password",
                    "csrf_token": "test-csrf",
                },
            )
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as user_session:
            self.assertNotIn("user_id", user_session)

    def test_update_api_returns_404_for_missing_user(self):
        with patch.object(
            self.app_module,
            "update_user",
            side_effect=security_service.UserNotFoundError("missing"),
        ):
            response = self._post_json(
                "/api/admin/users/99", {"username": "missing-user"}
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json(), {"error": "User not found."})

    def test_update_api_targets_requested_user_and_authenticated_actor(self):
        with patch.object(self.app_module, "update_user") as update:
            response = self._post_json(
                "/api/admin/users/42",
                {"username": "target-user", "role_id": "4", "module_ids": ["9"]},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(update.call_args.args[0], 42)
        self.assertEqual(update.call_args.args[1]["actor_id"], 7)
        self.assertEqual(update.call_args.args[1]["module_ids"], ["9"])

    def test_update_api_returns_safe_503_for_database_outage(self):
        with patch.object(
            self.app_module,
            "update_user",
            side_effect=psycopg2.OperationalError("private connection detail"),
        ):
            response = self._post_json(
                "/api/admin/users/42", {"username": "existing-user"}
            )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private connection detail", response.data)

    def test_user_api_permission_denial_is_403(self):
        with patch.object(
            self.app_module, "require_permission", side_effect=Forbidden()
        ):
            response = self._post_json(
                "/api/admin/users/42", {"username": "existing-user"}
            )
        self.assertEqual(response.status_code, 403)

    def test_profile_api_updates_only_the_authenticated_user(self):
        profile = {
            "username": "signed-in-user",
            "full_name": "Updated Name",
            "email": "person@example.com",
            "mobile_number": None,
            "avatar_key": None,
        }
        with patch.object(self.app_module, "get_profile", return_value=profile), patch.object(
            self.app_module, "update_profile", return_value=profile
        ) as update:
            response = self.client.post(
                "/api/profile",
                data={"full_name": "Updated Name", "email": "person@example.com"},
                headers={"X-CSRFToken": "test-csrf"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(update.call_args.args[0], 7)

    def test_avatar_upload_reencodes_valid_image_and_rejects_invalid_bytes(self):
        image = Image.new("RGB", (8, 8), "red")
        content = BytesIO()
        image.save(content, format="PNG")
        content.seek(0)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            self.app_module, "AVATAR_DIR", Path(directory)
        ):
            key = self.app_module._store_profile_avatar(content)
            with self.assertRaisesRegex(ValueError, "valid supported image"):
                self.app_module._store_profile_avatar(BytesIO(b"not an image"))
            self.assertRegex(key, r"^[a-f0-9]{40}\.webp$")
            with Image.open(Path(directory) / key) as saved:
                self.assertEqual(saved.format, "WEBP")

    def test_profile_api_stores_avatar_and_updates_only_current_user(self):
        image = Image.new("RGB", (8, 8), "blue")
        upload = BytesIO()
        image.save(upload, format="PNG")
        upload.seek(0)
        profile = {
            "username": "signed-in-user",
            "full_name": "Updated Name",
            "email": "person@example.com",
            "mobile_number": None,
            "avatar_key": None,
        }
        with tempfile.TemporaryDirectory() as directory, patch.object(
            self.app_module, "AVATAR_DIR", Path(directory)
        ), patch.object(self.app_module, "get_profile", return_value=profile), patch.object(
            self.app_module, "update_profile", return_value={**profile, "avatar_key": "unused"}
        ) as update:
            response = self.client.post(
                "/api/profile",
                data={
                    "full_name": "Updated Name",
                    "email": "person@example.com",
                    "mobile_number": "12345678",
                    "avatar": (upload, "avatar.png"),
                },
                headers={"X-CSRFToken": "test-csrf"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(update.call_args.args[0], 7)
        self.assertRegex(update.call_args.kwargs["avatar_key"], r"^[a-f0-9]{40}\.webp$")
        self.assertEqual(response.get_json()["profile"]["username"], "signed-in-user")


class FakeMutationCursor:
    def __init__(self, update_mode=False, rowcount=1):
        self.executed = []
        self.update_mode = update_mode
        self.rowcount = rowcount
        self.query = ""

    def execute(self, query, parameters=()):
        self.query = query
        self.executed.append((query, parameters))

    def fetchone(self):
        if "SELECT EXISTS" in self.query:
            return (False, True)
        if "SELECT role_name" in self.query:
            return ("EDITOR",)
        if "INSERT INTO app_security.users" in self.query:
            return (42,)
        return None

    def fetchall(self):
        if "SELECT role_id" in self.query:
            return [(4,)] if self.update_mode else []
        return []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeMutationConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor
        self.committed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeAssignmentCursor(FakeMutationCursor):
    def fetchall(self):
        if "SELECT module_id" in self.query:
            return [(8,), (12,)]
        return []


if __name__ == "__main__":
    unittest.main()