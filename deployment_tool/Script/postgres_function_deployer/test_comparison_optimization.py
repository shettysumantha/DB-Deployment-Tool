import unittest
from unittest.mock import patch

from services import table_service


class FakeCursor:
    def __init__(self):
        self.executed = []
        self.rows = {
            table_service.TABLE_METADATA_QUERY: [
                (101, "public", "orders", False, None, None,
                 [{"name": "id", "data_type": "integer", "nullable": False,
                   "default": "nextval('public.orders_id_seq'::regclass)",
                   "identity": "", "generated": "", "order": 1}],
                 [{"schema": "public", "name": "orders_id_seq", "data_type": "integer",
                   "start": 1, "increment": 1, "min": 1, "max": 2147483647,
                   "cache": 1, "cycle": False, "column": "id"}],
                 [{"name": "orders_pkey", "type": "p", "definition": "PRIMARY KEY (id)"}],
                 [{"name": "public.orders_name_idx", "unique": False, "primary": False,
                   "definition": "CREATE INDEX orders_name_idx ON public.orders USING btree (name)"}]),
            ],
        }

    def execute(self, query, params):
        self.executed.append((query, params))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def fetchall(self):
        return self.rows[self.executed[-1][0]]


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def cursor(self):
        return self.cursor_instance


def table_record(name, data_type="integer"):
    return {
        "key": f"public.{name}",
        "schema": "public",
        "name": name,
        "columns": [{
            "name": "id", "data_type": data_type, "nullable": False,
            "default": None, "identity": "", "generated": "", "order": 1,
        }],
        "constraints": [],
        "indexes": [],
        "sequences": [],
        "is_partition": False,
        "partition_key": None,
        "description": "",
        "definition": "",
    }


class ComparisonOptimizationTests(unittest.TestCase):
    def test_table_metadata_uses_fixed_bulk_query_count(self):
        cursor = FakeCursor()
        metrics = {}
        with patch("services.table_service.connection", return_value=FakeConnection(cursor)):
            records = table_service.fetch_selected({}, ["orders"], metrics=metrics)

        self.assertEqual(metrics["queries"], 1)
        self.assertEqual(len(cursor.executed), 1)
        self.assertEqual(records["public.orders"]["sequences"][0]["name"], "orders_id_seq")
        self.assertEqual(records["public.orders"]["constraints"][0]["name"], "orders_pkey")
        self.assertEqual(records["public.orders"]["indexes"][0]["name"], "orders_name_idx")

    def test_sequence_metadata_uses_catalog_dependencies(self):
        self.assertIn("pg_depend", table_service.TABLE_METADATA_QUERY)
        self.assertNotIn("pg_get_serial_sequence", table_service.TABLE_METADATA_QUERY)
        self.assertNotIn("to_regclass", table_service.TABLE_METADATA_QUERY)

    def test_table_status_rules_are_unchanged(self):
        source = {
            "public.new_table": table_record("new_table"),
            "public.modified_table": table_record("modified_table", "integer"),
            "public.identical_table": table_record("identical_table"),
        }
        live = {
            "public.missing_table": table_record("missing_table"),
            "public.modified_table": table_record("modified_table", "text"),
            "public.identical_table": table_record("identical_table"),
        }
        with patch("services.table_service.fetch_selected", side_effect=[source, live]):
            results = table_service.compare_tables({}, {}, [])

        statuses = {result["name"]: result["status"] for result in results}
        self.assertEqual(statuses, {
            "new_table": "NEW",
            "modified_table": "MODIFIED",
            "missing_table": "MISSING",
            "identical_table": "IDENTICAL",
        })


if __name__ == "__main__":
    unittest.main()