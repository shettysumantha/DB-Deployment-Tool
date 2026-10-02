import unittest
from types import SimpleNamespace
from unittest.mock import patch

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


class SecurityPaginationTests(unittest.TestCase):
    def test_user_list_calls_paged_function_with_bounded_limit(self):
        cursor = FakeCursor(rows=[(42,)])
        with patch.object(security_service, "security_connection", return_value=FakeConnection(cursor)):
            users = security_service.list_users(limit=500, offset=-5)

        self.assertEqual(users, [{"user_id": 42}])
        self.assertEqual(cursor.executed[0][1], (101, 0, None))
        self.assertIn("app_security.fn_get_users", cursor.executed[0][0])

    def test_initialization_only_checks_existing_schema_objects(self):
        cursor = FakeCursor()
        with patch.object(security_service, "_schema_initialized", False), patch.object(
            security_service, "security_connection", return_value=FakeConnection(cursor)
        ):
            self.assertTrue(security_service.initialize_security())

        self.assertEqual(cursor.executed, [("SELECT to_regclass(%s)", ("app_security.users",))])


if __name__ == "__main__":
    unittest.main()