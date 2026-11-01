import unittest
from types import SimpleNamespace
from unittest.mock import patch

from modules.database_management import operations_service


class DatabaseOperationsServiceTests(unittest.TestCase):
    def test_select_and_read_only_cte_queries_are_allowed(self):
        self.assertEqual(
            operations_service.validate_read_query(
                "SELECT 'update; delete', current_database();"
            ),
            "SELECT 'update; delete', current_database()",
        )
        self.assertEqual(
            operations_service.validate_read_query(
                "WITH counts AS (SELECT count(*) AS total FROM app.users) "
                "SELECT total FROM counts"
            ),
            "WITH counts AS (SELECT count(*) AS total FROM app.users) "
            "SELECT total FROM counts",
        )

    def test_mutations_multiple_statements_and_side_effect_functions_are_rejected(self):
        rejected = (
            "UPDATE accounts SET active = false",
            "SELECT 1; DELETE FROM accounts",
            "SELECT 1; SELECT 2;",
            "WITH removed AS (DELETE FROM accounts RETURNING id) SELECT * FROM removed",
            "SELECT nextval('account_id_seq')",
            "SELECT pg_sleep(60)",
            'SELECT pg_catalog."pg_terminate_backend"(123)',
            'SELECT "dblink_exec"("connection", "UPDATE accounts SET active = false")',
            "SELECT * FROM accounts FOR SHARE",
            "SELECT * INTO copied_accounts FROM accounts",
        )
        for sql in rejected:
            with self.subTest(sql=sql), self.assertRaises(ValueError):
                operations_service.validate_read_query(sql)

    def test_invalid_queries_are_rejected_before_opening_a_database_connection(self):
        with patch.object(operations_service.psycopg2, "connect") as connect:
            with self.assertRaisesRegex(ValueError, "Only read-only SELECT"):
                operations_service.execute_read_query({}, "DROP TABLE accounts")
        connect.assert_not_called()

    def test_query_execution_is_read_only_bounded_and_timed(self):
        class FakeCursor:
            description = [SimpleNamespace(name="id")]
            itersize = 0

            def __init__(self):
                self.executed = []
                self.offset = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def execute(self, query):
                self.executed.append(query)

            def fetchmany(self, size):
                self.fetch_size = size
                batch = [(value,) for value in range(self.offset, min(self.offset + size, 501))]
                self.offset += len(batch)
                return batch

        class FakeConnection:
            def __init__(self):
                self.autocommit = False
                self.cursors = []
                self.closed = False

            def set_session(self, **kwargs):
                self.session_options = kwargs

            def cursor(self, **kwargs):
                cursor = FakeCursor()
                self.cursors.append((kwargs, cursor))
                return cursor

            def close(self):
                self.closed = True

        database = FakeConnection()
        with patch.object(operations_service, "clean_config", return_value={"host": "db"}), patch.object(
            operations_service.psycopg2, "connect", return_value=database
        ) as connect:
            result = operations_service.execute_read_query(
                {"host": "db"}, "SELECT id FROM accounts"
            )

        connect.assert_called_once_with(
            host="db",
            connect_timeout=10,
            application_name="postgres-function-deployer",
        )
        self.assertEqual(database.session_options, {"readonly": True, "autocommit": False})
        self.assertIn("5000ms", database.cursors[0][1].executed[0])
        self.assertEqual(database.cursors[1][1].fetch_size, operations_service.QUERY_FETCH_BATCH)
        self.assertEqual(len(result["rows"]), 500)
        self.assertTrue(result["truncated"])
        self.assertTrue(database.closed)

    def test_vacuum_analyze_requires_a_target_table(self):
        with patch.object(operations_service.psycopg2, "connect") as connect:
            with self.assertRaisesRegex(ValueError, "targeted VACUUM ANALYZE"):
                operations_service.vacuum_analyze({}, "VACUUM ANALYZE")
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
