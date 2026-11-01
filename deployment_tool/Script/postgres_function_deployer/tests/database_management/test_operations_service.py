import unittest
from types import SimpleNamespace
from unittest.mock import patch

from modules.database_management import operations_service


class DatabaseOperationsServiceTests(unittest.TestCase):
    def test_connection_maps_saved_credentials_to_psycopg_options(self):
        config = {
            "host": "db.example.com",
            "port": 26257,
            "database": "defaultdb",
            "username": "monitor",
            "password": "secret",
            "sslmode": "require",
        }
        connection = SimpleNamespace(set_session=lambda **_kwargs: None)

        with patch.object(
            operations_service.psycopg2, "connect", return_value=connection
        ) as connect:
            operations_service._connect(config, readonly=True)

        connect.assert_called_once_with(
            host="db.example.com",
            port=26257,
            dbname="defaultdb",
            user="monitor",
            password="secret",
            connect_timeout=10,
            application_name="postgres-function-deployer",
            sslmode="require",
        )

    def test_health_inspection_returns_live_overview_storage_and_performance_metrics(self):
        class FakeCursor:
            def __init__(self):
                self.rows = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def execute(self, query):
                if "SELECT current_database()" in query:
                    self.rows = [{
                        "database_name": "demo",
                        "connected_as": "monitor",
                        "server_version": "PostgreSQL 16",
                    }]
                elif "pg_database_size(current_database())" in query:
                    self.rows = [{"database_size_bytes": 2048}]
                elif "FROM pg_database" in query:
                    self.rows = [{"database_name": "demo", "size_bytes": 2048}]
                elif "current_setting('max_connections')" in query:
                    self.rows = [{"max_connections": 10}]
                elif "count(*) FILTER" in query:
                    self.rows = [{
                        "current_connections": 3,
                        "active_connections": 1,
                        "idle_connections": 2,
                    }]
                elif "FROM pg_stat_database" in query:
                    self.rows = [{
                        "cache_hit_percent": 99,
                        "transactions_committed": 20,
                        "transactions_rolled_back": 1,
                        "deadlocks": 0,
                    }]
                elif "FROM pg_stat_user_tables" in query:
                    self.rows = [{
                        "schema": "public",
                        "table": "events",
                        "live_rows": 12,
                        "dead_rows": 2,
                        "table_size_bytes": 1000,
                        "index_size_bytes": 500,
                        "last_vacuum": None,
                        "last_autovacuum": "2026-11-01",
                        "last_analyze": "2026-11-01",
                        "last_autoanalyze": None,
                        "vacuum_count": 1,
                        "autovacuum_count": 2,
                        "analyze_count": 3,
                        "autoanalyze_count": 4,
                    }]
                elif "FROM pg_stat_user_indexes" in query:
                    self.rows = [{
                        "schema": "public",
                        "table": "events",
                        "index": "events_unused_idx",
                        "size_bytes": 500,
                        "scans": 0,
                        "tuples_read": 0,
                        "tuples_fetched": 0,
                        "potential_unused": True,
                    }]
                elif "FROM pg_stat_activity" in query:
                    self.rows = [{
                        "username": "app",
                        "application_name": "service",
                        "state": "active",
                        "wait_event_type": "Lock",
                        "wait_event": "transactionid",
                        "duration_seconds": 25,
                        "query": "SELECT 1",
                    }]
                elif "FROM pg_stat_statements" in query:
                    self.rows = [{
                        "calls": 2,
                        "mean_execution_ms": 50,
                        "total_execution_ms": 100,
                        "rows_returned": 4,
                        "query": "SELECT 1",
                    }]
                elif "FROM pg_locks" in query:
                    self.rows = [{
                        "username": "app",
                        "application_name": "service",
                        "mode": "AccessShareLock",
                        "locktype": "relation",
                        "relation": "events",
                        "granted": False,
                        "wait_event": "transactionid",
                        "query": "SELECT 1",
                    }]
                elif query.startswith("SAVEPOINT"):
                    self.rows = []
                else:
                    self.rows = []

            def fetchone(self):
                return self.rows[0] if self.rows else None

            def fetchall(self):
                return self.rows

        class FakeConnection:
            def cursor(self, **_kwargs):
                return FakeCursor()

            def set_session(self, **_kwargs):
                pass

            def close(self):
                pass

        valid_config = {
            "host": "db",
            "port": 5432,
            "database": "demo",
            "username": "monitor",
            "password": "secret",
        }
        with patch.object(
            operations_service, "clean_config", return_value=valid_config
        ), patch.object(
            operations_service.psycopg2, "connect", return_value=FakeConnection()
        ):
            result = operations_service.inspect_database({"host": "db"})

        self.assertEqual(result["overview"]["database_name"], "demo")
        self.assertEqual(result["overview"]["connection_utilization_percent"], 30)
        self.assertEqual(result["storage"]["total_table_size_bytes"], 1000)
        self.assertEqual(result["storage"]["total_index_size_bytes"], 500)
        self.assertEqual(result["storage"]["unused_indexes"][0]["index"], "events_unused_idx")
        self.assertEqual(result["performance"]["blocking_queries"][0]["duration_seconds"], 25)
        self.assertTrue(result["availability"]["slow_queries"])

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
        valid_config = {
            "host": "db",
            "port": 5432,
            "database": "demo",
            "username": "monitor",
            "password": "secret",
        }
        with patch.object(
            operations_service, "clean_config", return_value=valid_config
        ), patch.object(
            operations_service.psycopg2, "connect", return_value=database
        ) as connect:
            result = operations_service.execute_read_query(
                {"host": "db"}, "SELECT id FROM accounts"
            )

        connect.assert_called_once_with(
            host="db",
            port=5432,
            dbname="demo",
            user="monitor",
            password="secret",
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
