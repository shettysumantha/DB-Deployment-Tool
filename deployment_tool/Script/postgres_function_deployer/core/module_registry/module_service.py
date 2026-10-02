import ipaddress
import http.client
import json
import os
import re
import socket
import ssl
from urllib.parse import unquote, urlsplit

from psycopg2.extras import Json, RealDictCursor

from core.security.security_service import security_connection


MODULE_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,99}$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
ICON_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")
MODULE_COLUMNS = """
    module_id, module_code, module_name, description, version, module_type,
    is_enabled, is_active, web_url, api_base_url, manifest_url, health_url,
    entry_path, icon, parent_menu_id, display_order, health_status,
    last_health_check_at, capabilities, created_by, created_at, updated_at
"""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, port, address, timeout):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._validated_address = address

    def connect(self):
        sock = socket.create_connection((self._validated_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _allowed_hosts():
    return {
        value.strip().lower().rstrip(".")
        for value in os.getenv("TRUSTED_MODULE_HOSTS", "").split(",")
        if value.strip()
    }


def _resolve_safe_url(value, field_name):
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must be an HTTPS URL without embedded credentials.")
    host = parsed.hostname.lower().rstrip(".")
    trusted = host in _allowed_hosts()
    if _allowed_hosts() and not trusted:
        raise ValueError(f"{field_name} host is not in TRUSTED_MODULE_HOSTS.")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError(f"{field_name} has an invalid port.") from exc
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError(f"{field_name} cannot target a local or internal host.")
        try:
            addresses = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise ValueError(f"{field_name} host could not be resolved.") from exc
    if not addresses or (not trusted and any(not address.is_global for address in addresses)):
        raise ValueError(f"{field_name} cannot target a private or non-public address.")
    return url, parsed, port, sorted(addresses, key=lambda address: (address.version, int(address)))


def _validate_url(value, field_name):
    return _resolve_safe_url(value, field_name)[0]


def _validate_entry_path(value):
    entry_path = str(value or "").strip()
    parsed = urlsplit(entry_path)
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
        or not decoded_path.startswith("/") or decoded_path.startswith("//")
        or "\\" in decoded_path or any(part == ".." for part in decoded_path.split("/"))
        or any(ord(char) < 32 for char in decoded_path)
    ):
        raise ValueError("Entry path must be a local absolute path without URL or traversal segments.")
    return entry_path


def _validate_internal_path(value, field_name, allow_empty=False):
    path = str(value or "").strip()
    if allow_empty and not path:
        return None
    parsed = urlsplit(path)
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
        or not decoded_path.startswith("/") or decoded_path.startswith("//")
        or "\\" in decoded_path or any(part == ".." for part in decoded_path.split("/"))
        or any(ord(char) < 32 for char in decoded_path)
    ):
        raise ValueError(f"{field_name} must be a local absolute path without URL or traversal segments.")
    return path


def _fetch_json(url, *, expected_code=None):
    _, parsed, port, addresses = _resolve_safe_url(url, "URL")
    connection = _PinnedHTTPSConnection(parsed.hostname, port, str(addresses[0]), timeout=5)
    request_target = parsed.path or "/"
    hostname_header = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    host_header = hostname_header if port == 443 else f"{hostname_header}:{port}"
    try:
        connection.request(
            "GET", request_target,
            headers={"Host": host_header, "Accept": "application/json", "User-Agent": "DBA-Operations-Platform/1.0"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Module endpoint must return HTTP 200 without redirects.")
        raw = response.read(65537)
    except (http.client.HTTPException, TimeoutError, OSError, ssl.SSLError) as exc:
        raise ValueError("Module endpoint is unavailable or attempted a redirect.") from exc
    finally:
        connection.close()
    if len(raw) > 65536:
        raise ValueError("Module response exceeds the 64 KB limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Module endpoint must return a JSON object.") from exc
    if not isinstance(data, dict):
        raise ValueError("Module endpoint must return a JSON object.")
    if expected_code and data.get("module_code") != expected_code:
        raise ValueError("Module health response has the wrong module_code.")
    return data


def validate_manifest(manifest_url):
    manifest_url = _validate_url(manifest_url, "Manifest URL")
    manifest = _fetch_json(manifest_url)
    code = str(manifest.get("module_code", "")).strip()
    name = str(manifest.get("module_name", "")).strip()
    version = str(manifest.get("version", "")).strip()
    if not MODULE_CODE_PATTERN.fullmatch(code):
        raise ValueError("Manifest module_code must use uppercase letters, digits, and underscores.")
    if not name or len(name) > 150:
        raise ValueError("Manifest module_name is required and must be 150 characters or fewer.")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Manifest version must use semantic version format, such as 1.0.0.")
    web_url = _validate_url(manifest.get("web_url"), "Module web_url")
    api_base_url = manifest.get("api_base_url")
    if api_base_url:
        api_base_url = _validate_url(api_base_url, "Module api_base_url")
    health_url = _validate_url(manifest.get("health_url"), "Module health_url")
    health = _fetch_json(health_url, expected_code=code)
    if health.get("module_code") != code:
        raise ValueError("Module health response has the wrong module_code.")
    if health.get("status") != "UP" or health.get("version") != version:
        raise ValueError("Module health endpoint must report status UP and the manifest version.")
    entry_path = _validate_entry_path(manifest.get("entry_path", "/"))
    icon = str(manifest.get("icon", "database")).strip()
    if not ICON_PATTERN.fullmatch(icon):
        raise ValueError("Manifest icon contains unsupported characters.")
    capabilities = manifest.get("capabilities", [])
    if not isinstance(capabilities, list) or len(capabilities) > 32 or any(not isinstance(item, str) or len(item) > 80 for item in capabilities):
        raise ValueError("Manifest capabilities must be a list of at most 32 short strings.")
    return {
        "module_code": code,
        "module_name": name,
        "description": str(manifest.get("description", ""))[:2000],
        "version": version,
        "web_url": web_url,
        "api_base_url": api_base_url,
        "manifest_url": manifest_url,
        "health_url": health_url,
        "entry_path": entry_path,
        "icon": icon,
        "capabilities": capabilities,
    }


def register_module(manifest, actor_id, parent_menu_id, display_order=0):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""INSERT INTO app_security.modules
                    (module_code, module_name, description, version, module_type,
                     is_enabled, web_url, api_base_url, manifest_url, health_url,
                        entry_path, icon, parent_menu_id, display_order,
                        health_status, last_health_check_at, capabilities, created_by)
                        VALUES (%s, %s, %s, %s, 'EXTERNAL', FALSE, %s, %s, %s, %s,
                            %s, %s, %s, %s, 'UP', CURRENT_TIMESTAMP, %s, %s)
                    RETURNING {MODULE_COLUMNS}""",
                (
                    manifest["module_code"], manifest["module_name"], manifest["description"],
                    manifest["version"], manifest["web_url"], manifest["api_base_url"],
                    manifest["manifest_url"], manifest["health_url"], manifest["entry_path"],
                    manifest["icon"], parent_menu_id, max(0, int(display_order)),
                    Json(manifest["capabilities"]), actor_id,
                ),
            )
            module = dict(cur.fetchone())
            cur.execute(
                """INSERT INTO app_security.role_module_permissions
                    (role_id, module_id, can_view, can_create, can_edit, can_delete, can_execute)
                    SELECT role_id, %s, role_name = 'ADMIN', FALSE, FALSE, FALSE, FALSE
                    FROM app_security.roles ON CONFLICT (role_id, module_id) DO NOTHING""",
                (module["module_id"],),
            )
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, 'MODULE_REGISTERED', %s)""",
                (actor_id, Json({"module_code": module["module_code"], "module_id": module["module_id"]})),
            )
        conn.commit()
    return module


def list_modules(limit=100, offset=0, include_inactive=False):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM app_security.fn_get_modules(%s, %s, %s)",
                (max(1, min(int(limit), 101)), max(0, int(offset)), bool(include_inactive)),
            )
            return [dict(row) for row in cur.fetchall()]


def list_available_modules(user_id, limit=100, offset=0):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM app_security.fn_get_available_modules(%s, %s, %s)",
                (user_id, max(1, min(int(limit), 101)), max(0, int(offset))),
            )
            return [dict(row) for row in cur.fetchall()]


def list_parent_menus():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT menu_id, menu_name, menu_code
                   FROM app_security.menus
                   WHERE is_active AND menu_type = 'GROUP'
                   ORDER BY display_order, menu_name"""
            )
            return [dict(row) for row in cur.fetchall()]


def get_module(module_id):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT {MODULE_COLUMNS} FROM app_security.modules WHERE module_id = %s AND is_active",
                (module_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def get_module_by_code(module_code, include_inactive=False):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""SELECT {MODULE_COLUMNS} FROM app_security.modules
                    WHERE module_code = %s AND (%s OR is_active)""",
                (module_code, bool(include_inactive)),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def list_module_permissions(module_id):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT r.role_id, r.role_name,
                          COALESCE(p.can_view, FALSE) AS can_view,
                          COALESCE(p.can_create, FALSE) AS can_create,
                          COALESCE(p.can_edit, FALSE) AS can_edit,
                          COALESCE(p.can_delete, FALSE) AS can_delete,
                          COALESCE(p.can_execute, FALSE) AS can_execute
                   FROM app_security.roles AS r
                   LEFT JOIN app_security.role_module_permissions AS p
                     ON p.role_id = r.role_id AND p.module_id = %s
                   WHERE r.is_active ORDER BY r.role_name""",
                (module_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def get_launch_target(module_code):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""SELECT {MODULE_COLUMNS} FROM app_security.modules
                    WHERE module_code = %s AND is_active AND is_enabled""",
                (module_code,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def module_permission(user_id, module_code, permission="can_view"):
    if permission not in {"can_view", "can_create", "can_edit", "can_delete", "can_execute"}:
        return False
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT
                    (u.is_admin AND EXISTS (
                        SELECT 1 FROM app_security.user_roles ur
                        JOIN app_security.roles r ON r.role_id = ur.role_id
                        WHERE ur.user_id = u.user_id AND r.is_active AND r.role_name = 'ADMIN'
                    )) AS is_admin,
                    u.module_access_configured,
                    m.navigation_menu_id,
                    EXISTS (
                        SELECT 1 FROM app_security.user_roles ur
                        JOIN app_security.roles r ON r.role_id = ur.role_id AND r.is_active
                        JOIN app_security.role_module_permissions p ON p.role_id = r.role_id
                            AND p.module_id = m.module_id AND p.{permission}
                        WHERE ur.user_id = u.user_id
                    ) AS role_granted,
                    EXISTS (
                        SELECT 1 FROM app_security.user_menu_access uma
                        WHERE uma.user_id = u.user_id AND uma.menu_id = m.navigation_menu_id
                    ) AS explicitly_assigned
                    FROM app_security.users u
                    JOIN app_security.modules m ON m.module_code = %s
                        AND m.is_active AND m.is_enabled
                    WHERE u.user_id = %s AND u.is_active""",
                (module_code, user_id),
            )
            state = cur.fetchone()
    if not state:
        return False
    is_admin, configured, _nav_menu_id, role_granted, explicitly_assigned = state
    if is_admin:
        return True
    if permission == "can_view" and configured:
        return explicitly_assigned if _nav_menu_id is not None else role_granted
    return role_granted and (not configured or _nav_menu_id is None or explicitly_assigned)


def update_module(module_id, payload, actor_id):
    module_name = str(payload.get("module_name", "")).strip()
    if not module_name or len(module_name) > 150:
        raise ValueError("Module name is required and must be 150 characters or fewer.")
    icon = str(payload.get("icon", "database"))
    if not ICON_PATTERN.fullmatch(icon):
        raise ValueError("Icon contains unsupported characters.")
    current = get_module(module_id)
    if not current:
        raise ValueError("Module was not found or has been de-registered.")
    old_version = current["version"]
    old_urls = {
        key: current[key]
        for key in ("web_url", "api_base_url", "manifest_url", "health_url")
    }
    web_url = str(payload.get("web_url", "")).strip()
    api_base_url = str(payload.get("api_base_url", "")).strip()
    manifest_url = str(payload.get("manifest_url", "")).strip()
    health_url = str(payload.get("health_url", "")).strip()
    if current["module_type"] == "INTERNAL":
        web_url = _validate_internal_path(web_url, "Module web_url")
        api_base_url = _validate_internal_path(api_base_url, "Module api_base_url", allow_empty=True)
        manifest_url = _validate_internal_path(manifest_url, "Manifest URL")
        health_url = _validate_internal_path(health_url, "Module health_url")
    else:
        web_url = _validate_url(web_url, "Module web_url")
        api_base_url = _validate_url(api_base_url, "Module api_base_url") if api_base_url else None
        manifest_url = _validate_url(manifest_url, "Manifest URL")
        health_url = _validate_url(health_url, "Module health_url")
    entry_path = _validate_entry_path(payload.get("entry_path", "/"))
    version = str(payload.get("version", "")).strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Version must use semantic version format, such as 1.0.0.")
    capabilities = payload.get("capabilities", current["capabilities"] or [])
    if not isinstance(capabilities, list) or len(capabilities) > 32 or any(not isinstance(item, str) or len(item) > 80 for item in capabilities):
        raise ValueError("Capabilities must be a list of at most 32 short strings.")
    parent_menu_id = int(payload.get("parent_menu_id", 0))
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT 1 FROM app_security.menus WHERE menu_id = %s AND is_active AND menu_type = 'GROUP'",
                (parent_menu_id,),
            )
            if not cur.fetchone():
                raise ValueError("Choose an active navigation group.")
            cur.execute(
                f"""UPDATE app_security.modules SET
                    module_name = %s, description = %s, version = %s,
                    web_url = %s, api_base_url = %s, manifest_url = %s,
                    health_url = %s, entry_path = %s, icon = %s,
                    capabilities = %s,
                    parent_menu_id = %s, display_order = %s,
                    updated_at = CURRENT_TIMESTAMP
                    WHERE module_id = %s AND is_active
                    RETURNING {MODULE_COLUMNS}""",
                (
                    module_name,
                    str(payload.get("description", ""))[:2000], version,
                    web_url, api_base_url, manifest_url, health_url,
                    entry_path, icon, Json(capabilities),
                    parent_menu_id, max(0, int(payload.get("display_order", 0))),
                    module_id,
                ),
            )
            module = cur.fetchone()
            if not module:
                raise ValueError("Module was not found or has been de-registered.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, 'MODULE_UPDATED', %s)""",
                (actor_id, Json({"module_id": module_id, "module_code": module["module_code"]})),
            )
            new_urls = {
                "web_url": web_url, "api_base_url": api_base_url,
                "manifest_url": manifest_url, "health_url": health_url,
            }
            if new_urls != old_urls:
                cur.execute(
                    """INSERT INTO app_security.audit_logs (user_id, action, details)
                       VALUES (%s, 'MODULE_URL_CHANGED', %s)""",
                    (actor_id, Json({"module_id": module_id, "module_code": module["module_code"]})),
                )
            if version != old_version:
                cur.execute(
                    """INSERT INTO app_security.audit_logs (user_id, action, details)
                       VALUES (%s, 'MODULE_VERSION_UPDATED', %s)""",
                    (actor_id, Json({
                        "module_id": module_id, "module_code": module["module_code"],
                        "old_version": old_version, "new_version": version,
                    })),
                )
        conn.commit()
    return dict(module)


def set_module_enabled(module_id, enabled, actor_id):
    action = "MODULE_ENABLED" if enabled else "MODULE_DISABLED"
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE app_security.modules SET is_enabled = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE module_id = %s AND is_active RETURNING module_code""",
                (bool(enabled), module_id),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("Module was not found or has been de-registered.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, %s, %s)""",
                (actor_id, action, Json({"module_id": module_id, "module_code": row[0]})),
            )
        conn.commit()
    return bool(enabled)


def deregister_module(module_id, actor_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE app_security.modules SET is_enabled = FALSE, is_active = FALSE,
                       updated_at = CURRENT_TIMESTAMP WHERE module_id = %s AND is_active
                       RETURNING module_code""",
                (module_id,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("Module was not found or is already de-registered.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, 'MODULE_DEREGISTERED', %s)""",
                (actor_id, Json({"module_id": module_id, "module_code": row[0]})),
            )
        conn.commit()


def check_module_health(module_id, actor_id):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT module_code, version, module_type, health_url FROM app_security.modules WHERE module_id = %s AND is_active",
                (module_id,),
            )
            module = cur.fetchone()
    if not module:
        raise ValueError("Module was not found or has been de-registered.")
    status = "DOWN"
    detail = "Health endpoint is unavailable."
    if module["module_type"] == "INTERNAL":
        status, detail = "UP", "Platform-hosted module is responding to the health-check request."
    else:
        try:
            health = _fetch_json(module["health_url"], expected_code=module["module_code"])
            if health.get("status") == "UP" and health.get("version") == module["version"]:
                status, detail = "UP", "Module is healthy and reports the registered version."
            elif health.get("version") != module["version"]:
                status, detail = "UNKNOWN", "Module is responding but its published version differs from the registered version."
            else:
                status, detail = "UNKNOWN", "Health endpoint returned an unexpected status."
        except ValueError as exc:
            detail = str(exc)
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE app_security.modules SET health_status = %s,
                       last_health_check_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                   WHERE module_id = %s AND is_active""",
                (status, module_id),
            )
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, 'MODULE_HEALTH_CHECKED', %s)""",
                (actor_id, Json({"module_id": module_id, "health_status": status})),
            )
        conn.commit()
    return {"health_status": status, "detail": detail}


def save_module_permissions(module_id, role_id, permissions, actor_id):
    allowed = {"can_view", "can_create", "can_edit", "can_delete", "can_execute"}
    if not isinstance(permissions, dict):
        raise ValueError("Module permissions must be an object of boolean values.")
    if set(permissions) - allowed:
        raise ValueError("Unsupported module permission.")
    if any(key in permissions and not isinstance(permissions[key], bool) for key in allowed):
        raise ValueError("Module permissions must be boolean values.")
    values = {key: permissions.get(key, False) for key in allowed}
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO app_security.role_module_permissions
                    (role_id, module_id, can_view, can_create, can_edit, can_delete, can_execute)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (role_id, module_id) DO UPDATE SET
                    can_view = EXCLUDED.can_view, can_create = EXCLUDED.can_create,
                    can_edit = EXCLUDED.can_edit, can_delete = EXCLUDED.can_delete,
                    can_execute = EXCLUDED.can_execute""",
                (role_id, module_id, values["can_view"], values["can_create"], values["can_edit"], values["can_delete"], values["can_execute"]),
            )
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, 'MODULE_PERMISSIONS_CHANGED', %s)""",
                (actor_id, Json({"module_id": module_id, "role_id": role_id, "permissions": values})),
            )
        conn.commit()