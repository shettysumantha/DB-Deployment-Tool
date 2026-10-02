import ipaddress
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from core.module_registry import module_service


class FakeResponse:
    def __init__(self, status, content):
        self.status = status
        self.content = content

    def read(self, size):
        return self.content[:size]


class FakeHTTPSConnection:
    def __init__(self, status=200, content=b'{"status":"UP","module_code":"DB_SCHEMA_TRACKER","version":"1.2.3"}'):
        self.response = FakeResponse(status, content)
        self.request_args = None
        self.closed = False

    def request(self, method, target, headers):
        self.request_args = (method, target, headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class FakePermissionCursor:
    def __init__(self, row):
        self.row = row

    def execute(self, _query, _parameters):
        pass

    def fetchone(self):
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakePermissionConnection:
    def __init__(self, row):
        self.cursor_instance = FakePermissionCursor(row)

    def cursor(self):
        return self.cursor_instance

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeRegistryCursor:
    def __init__(self):
        self.executed = []
        self.result = None

    def execute(self, query, parameters=()):
        self.executed.append((query, parameters))
        if query.lstrip().startswith("INSERT INTO app_security.modules"):
            self.result = {
                "module_id": 25, "module_code": "DB_SCHEMA_TRACKER",
                "module_name": "DB Schema Tracker", "is_enabled": False,
            }
        elif "RETURNING module_code" in query:
            self.result = ("DB_SCHEMA_TRACKER",)

    def fetchone(self):
        return self.result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeRegistryConnection:
    def __init__(self):
        self.cursor_instance = FakeRegistryCursor()
        self.committed = False

    def cursor(self, cursor_factory=None):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class ModuleServiceTests(unittest.TestCase):
    def test_private_ip_urls_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "private or non-public"):
            module_service._validate_url("https://127.0.0.1/api/module-manifest", "Manifest URL")

    def test_private_dns_resolution_is_rejected(self):
        resolution = [(None, None, None, None, ("10.20.30.40", 443))]
        with patch.dict("os.environ", {"TRUSTED_MODULE_HOSTS": ""}), patch.object(
            module_service.socket, "getaddrinfo", return_value=resolution
        ):
            with self.assertRaisesRegex(ValueError, "private or non-public"):
                module_service._validate_url("https://module.example/api/module-manifest", "Manifest URL")

    def test_manifest_and_health_identity_are_validated(self):
        manifest = {
            "module_code": "DB_SCHEMA_TRACKER",
            "module_name": "DB Schema Tracker",
            "version": "1.2.3",
            "web_url": "https://module.example/app",
            "api_base_url": "https://module.example/api",
            "health_url": "https://module.example/api/health",
            "entry_path": "/",
            "icon": "database",
            "capabilities": ["schema-read"],
        }
        with patch.object(module_service, "_validate_url", side_effect=lambda value, _field: value), patch.object(
            module_service, "_fetch_json",
            side_effect=[manifest, {"status": "UP", "module_code": "DB_SCHEMA_TRACKER", "version": "1.2.3"}],
        ):
            result = module_service.validate_manifest("https://module.example/api/module-manifest")

        self.assertEqual(result["module_code"], "DB_SCHEMA_TRACKER")
        self.assertEqual(result["capabilities"], ["schema-read"])

    def test_web_only_registration_skips_json_requests(self):
        web_url = "https://db-schema-tracker-1.onrender.com/"
        with patch.object(module_service, "_validate_url", return_value=web_url), patch.object(
            module_service, "_fetch_json"
        ) as fetch_json:
            result = module_service.validate_module_registration({"web_url": web_url})

        fetch_json.assert_not_called()
        self.assertEqual(result["module_code"], "DB_SCHEMA_TRACKER_1")
        self.assertEqual(result["module_name"], "Db Schema Tracker 1")
        self.assertEqual(result["version"], "1.0.0")
        self.assertIsNone(result["api_base_url"])
        self.assertIsNone(result["manifest_url"])
        self.assertIsNone(result["health_url"])
        self.assertEqual(result["health_status"], "UNKNOWN")
        self.assertEqual(result["validation_mode"], "web-only")

    def test_registration_requires_a_web_or_api_endpoint(self):
        with self.assertRaisesRegex(ValueError, "A web URL or API endpoint is required"):
            module_service.validate_module_registration({})

    def test_api_endpoint_html_has_specific_validation_error(self):
        url = "https://module.example/api"
        parsed = urlsplit(url)
        connection = FakeHTTPSConnection(content=b"<!doctype html><title>Not JSON</title>")
        with patch.object(
            module_service, "_resolve_safe_url",
            return_value=(url, parsed, 443, [ipaddress.ip_address("93.184.216.34")]),
        ), patch.object(module_service, "_PinnedHTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "API endpoint validation failed: expected JSON"):
                module_service._fetch_json(url, endpoint_name="API endpoint")

    def test_api_manifest_without_health_endpoint_is_valid(self):
        manifest = {
            "module_code": "DB_SCHEMA_TRACKER", "module_name": "DB Schema Tracker",
            "version": "1.2.3", "web_url": "https://module.example/app",
            "api_base_url": "https://module.example/api",
        }
        with patch.object(module_service, "_validate_url", side_effect=lambda value, _field: value), patch.object(
            module_service, "_fetch_json", return_value=manifest,
        ) as fetch_json:
            result = module_service.validate_module_registration(
                {"manifest_url": "https://module.example/api/module-manifest"}
            )

        fetch_json.assert_called_once_with(
            "https://module.example/api/module-manifest", endpoint_name="Manifest endpoint"
        )
        self.assertIsNone(result["health_url"])
        self.assertEqual(result["health_status"], "UNKNOWN")
        self.assertEqual(result["validation_mode"], "api-enabled")

    def test_api_only_registration_requires_json_and_uses_api_url_as_launch_url(self):
        api_url = "https://module.example/api"
        api_response = {"module_code": "DB_SCHEMA_TRACKER", "version": "1.2.3"}
        with patch.object(module_service, "_validate_url", side_effect=lambda value, _field: value), patch.object(
            module_service, "_fetch_json", return_value=api_response,
        ) as fetch_json:
            result = module_service.validate_module_registration({"api_base_url": api_url})

        fetch_json.assert_called_once_with(api_url, endpoint_name="API endpoint")
        self.assertEqual(result["web_url"], api_url)
        self.assertEqual(result["module_name"], "Module")
        self.assertEqual(result["validation_mode"], "api-enabled")

    def test_external_health_check_without_health_url_is_unknown_not_down(self):
        module = {
            "module_code": "DB_SCHEMA_TRACKER", "version": "1.2.3",
            "module_type": "EXTERNAL", "health_url": None,
        }
        read_connection = MagicMock()
        read_cursor = read_connection.__enter__.return_value.cursor.return_value.__enter__.return_value
        read_cursor.fetchone.return_value = module
        write_connection = MagicMock()
        with patch.object(
            module_service, "security_connection", side_effect=[read_connection, write_connection]
        ), patch.object(module_service, "_fetch_json") as fetch_json:
            result = module_service.check_module_health(module_id=25, actor_id=8)

        fetch_json.assert_not_called()
        self.assertEqual(result["health_status"], "UNKNOWN")
        self.assertIn("No health endpoint", result["detail"])

    def test_manifest_health_must_match_code_and_version(self):
        manifest = {
            "module_code": "DB_SCHEMA_TRACKER", "module_name": "DB Schema Tracker",
            "version": "1.2.3", "web_url": "https://module.example/app",
            "health_url": "https://module.example/api/health",
        }
        with patch.object(module_service, "_validate_url", side_effect=lambda value, _field: value), patch.object(
            module_service, "_fetch_json",
            side_effect=[manifest, {"status": "UP", "module_code": "OTHER", "version": "1.2.3"}],
        ):
            with self.assertRaisesRegex(ValueError, "wrong module_code"):
                module_service.validate_manifest("https://module.example/api/module-manifest")

    def test_entry_path_rejects_protocol_relative_and_encoded_traversal(self):
        for path in ("//attacker.example", "/%2e%2e/admin"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                module_service._validate_entry_path(path)

    def test_external_json_request_is_pinned_to_validated_address(self):
        address = ipaddress.ip_address("93.184.216.34")
        parsed = urlsplit("https://module.example/api/health")
        connection = FakeHTTPSConnection()
        with patch.object(
            module_service, "_resolve_safe_url",
            return_value=("https://module.example/api/health", parsed, 443, [address]),
        ), patch.object(module_service, "_PinnedHTTPSConnection", return_value=connection) as factory:
            payload = module_service._fetch_json("https://module.example/api/health", expected_code="DB_SCHEMA_TRACKER")

        factory.assert_called_once_with("module.example", 443, "93.184.216.34", timeout=5)
        self.assertEqual(connection.request_args[0:2], ("GET", "/api/health"))
        self.assertEqual(payload["module_code"], "DB_SCHEMA_TRACKER")
        self.assertTrue(connection.closed)

    def test_redirect_responses_are_rejected(self):
        parsed = urlsplit("https://module.example/api/health")
        connection = FakeHTTPSConnection(status=302, content=json.dumps({"url": "https://attacker.example"}).encode())
        with patch.object(
            module_service, "_resolve_safe_url",
            return_value=("https://module.example/api/health", parsed, 443, [ipaddress.ip_address("93.184.216.34")]),
        ), patch.object(module_service, "_PinnedHTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "without redirects"):
                module_service._fetch_json("https://module.example/api/health")
        self.assertTrue(connection.closed)

    def test_explicit_db_compare_assignment_remains_authoritative(self):
        row = (False, True, 12, True, False)
        with patch.object(module_service, "security_connection", return_value=FakePermissionConnection(row)):
            self.assertFalse(module_service.module_permission(7, "DB_COMPARE", "can_view"))

    def test_role_grants_apply_to_modules_without_legacy_menu_mappings(self):
        row = (False, True, None, True, False)
        with patch.object(module_service, "security_connection", return_value=FakePermissionConnection(row)):
            self.assertTrue(module_service.module_permission(7, "DB_SCHEMA_TRACKER", "can_view"))

    def test_admin_access_is_module_enabled_and_permission_scoped(self):
        row = (True, True, None, False, False)
        with patch.object(module_service, "security_connection", return_value=FakePermissionConnection(row)):
            self.assertTrue(module_service.module_permission(1, "DB_SCHEMA_TRACKER", "can_execute"))

    def test_module_permission_updates_require_boolean_values(self):
        with self.assertRaisesRegex(ValueError, "boolean"):
            module_service.save_module_permissions(25, 3, {"can_view": "false"}, actor_id=8)

    def test_external_registration_starts_disabled_and_writes_role_grants(self):
        connection = FakeRegistryConnection()
        manifest = {
            "module_code": "DB_SCHEMA_TRACKER", "module_name": "DB Schema Tracker",
            "description": "Schema tracking", "version": "1.2.3",
            "web_url": "https://module.example/app", "api_base_url": "https://module.example/api",
            "manifest_url": "https://module.example/api/module-manifest",
            "health_url": "https://module.example/api/health", "entry_path": "/",
            "icon": "database", "capabilities": ["schema-read"],
        }
        with patch.object(module_service, "security_connection", return_value=connection):
            record = module_service.register_module(manifest, actor_id=8, parent_menu_id=4, display_order=9)

        self.assertFalse(record["is_enabled"])
        statements = [query for query, _parameters in connection.cursor_instance.executed]
        self.assertIn("INSERT INTO app_security.role_module_permissions", statements[1])
        self.assertIn("MODULE_REGISTERED", statements[2])
        self.assertTrue(connection.committed)

    def test_web_only_registration_stores_null_api_urls_and_can_be_enabled(self):
        web_url = "https://db-schema-tracker-1.onrender.com/"
        connection = FakeRegistryConnection()
        with patch.object(module_service, "_validate_url", return_value=web_url):
            module = module_service.validate_module_registration({"web_url": web_url})
        with patch.object(module_service, "security_connection", return_value=connection):
            record = module_service.register_module(module, actor_id=8, parent_menu_id=4, display_order=10)
            enabled = module_service.set_module_enabled(record["module_id"], True, actor_id=8)

        insert_parameters = connection.cursor_instance.executed[0][1]
        insert_query = connection.cursor_instance.executed[0][0]
        self.assertEqual(insert_parameters[4:8], (web_url, None, None, None))
        self.assertEqual(insert_parameters[12:14], ("UNKNOWN", "UNKNOWN"))
        self.assertEqual(insert_query.count("%s"), len(insert_parameters))
        self.assertTrue(enabled)
        self.assertTrue(connection.committed)

    def test_deregistration_disables_without_deleting_registry_data(self):
        connection = FakeRegistryConnection()
        with patch.object(module_service, "security_connection", return_value=connection):
            module_service.deregister_module(25, actor_id=8)

        sql = connection.cursor_instance.executed[0][0]
        self.assertIn("is_enabled = FALSE, is_active = FALSE", sql)
        self.assertNotIn("DELETE FROM app_security.modules", sql)

    def test_db_compare_seed_does_not_reset_admin_lifecycle_state(self):
        script = (Path(__file__).resolve().parents[2] / "database" / "database_security.sql").read_text(encoding="utf-8")
        seed = script.split("ON CONFLICT (module_code) DO UPDATE SET", 1)[1].split(";", 1)[0]
        self.assertNotIn("is_enabled =", seed)
        self.assertNotIn("is_active =", seed)

    def test_external_module_schema_allows_missing_manifest_and_health_urls(self):
        script = (Path(__file__).resolve().parents[2] / "database" / "database_security.sql").read_text(encoding="utf-8")
        table = script.split("CREATE TABLE IF NOT EXISTS app_security.modules (", 1)[1].split(
            "CREATE TABLE IF NOT EXISTS app_security.role_module_permissions", 1
        )[0]
        self.assertIn("modules_optional_external_api_urls_check", table)
        self.assertIn("manifest_url IS NULL OR manifest_url ~ '^https://'", table)
        self.assertIn("health_url IS NULL OR health_url ~ '^https://'", table)
        self.assertIn("pg_get_constraintdef(oid) LIKE '%manifest_url IS NOT NULL%'", script)

    def test_web_only_module_routes_validate_register_enable_and_launch(self):
        import socket

        import app as app_module

        app = app_module.app
        web_url = "https://db-schema-tracker-1.onrender.com/"
        registered = {}

        def save_module(module, _actor_id, parent_menu_id, display_order):
            registered.update(module)
            registered.update(module_id=65, parent_menu_id=parent_menu_id, display_order=display_order)
            return registered

        with patch.object(app_module, "ensure_security_initialized", return_value=True), patch.object(
            app_module, "user_session_state",
            return_value={"is_active": True, "session_version": "test", "must_change_password": False},
        ), patch.object(app_module, "user_menus", return_value=[]), patch.object(
            app_module, "user_roles", return_value=["ADMIN"],
        ), patch.object(app_module, "require_permission"), patch.object(
            app_module, "list_parent_menus", return_value=[{"menu_id": 44, "menu_name": "Database Operation Module"}],
        ), patch.object(app_module, "register_module", side_effect=save_module), patch.object(
            app_module, "set_module_enabled", return_value=True,
        ), patch.object(app_module, "module_permission", return_value=True), patch.object(
            app_module, "get_launch_target",
            return_value={"module_type": "EXTERNAL", "web_url": web_url, "entry_path": "/"},
        ), patch.object(
            module_service.socket, "getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
        ), patch.object(module_service, "_allowed_hosts", return_value=set()):
            with app.test_client() as client:
                with client.session_transaction() as user_session:
                    user_session.update(
                        user_id=7, username="admin", session_version="test", _csrf_token="csrf-test",
                    )
                headers = {"X-CSRFToken": "csrf-test"}
                payload = {
                    "web_url": web_url, "api_base_url": "",
                    "manifest_url": "", "health_url": "",
                }

                validated = client.post("/api/admin/modules/validate", json=payload, headers=headers)
                self.assertEqual(validated.status_code, 200)
                self.assertEqual(validated.json["validation_mode"], "web-only")

                registered_response = client.post(
                    "/api/admin/modules",
                    json={**payload, "parent_menu_id": 44, "display_order": 10},
                    headers=headers,
                )
                self.assertEqual(registered_response.status_code, 201)
                self.assertEqual(
                    (registered["api_base_url"], registered["manifest_url"], registered["health_url"]),
                    (None, None, None),
                )

                enabled = client.put(
                    "/api/admin/modules/65/enabled", json={"enabled": True}, headers=headers,
                )
                self.assertEqual(enabled.status_code, 200)
                self.assertTrue(enabled.json["is_enabled"])

                launched = client.get("/modules/DB_SCHEMA_TRACKER_1/launch")
                self.assertEqual(launched.status_code, 302)
                self.assertEqual(launched.headers["Location"], web_url)


if __name__ == "__main__":
    unittest.main()