import ipaddress
import http.client
import json
import os
import re
import secrets
import socket
import ssl
from urllib.parse import unquote, urlsplit

from psycopg2.extras import Json, RealDictCursor

from core.security.security_service import security_connection


MODULE_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,99}$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
ICON_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")
MODULE_COLUMNS = """
    module_id, module_code, module_name, description, version, module_type, module_classification,
    is_enabled, is_active, web_url, api_base_url, manifest_url, health_url,
    entry_path, icon, parent_menu_id, navigation_menu_id, display_order, health_status,
    last_health_check_at, capabilities, created_by, created_at, updated_at
"""


class ModuleCodeConflictError(ValueError):
    def __init__(self, module_code):
        self.module_code = module_code
        super().__init__(
            f"Module code {module_code} is already registered for another external application."
        )


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


def _validate_api_endpoint(payload):
    endpoint_name = str(payload.get("endpoint_name") or "").strip()
    endpoint_path = str(payload.get("endpoint_path") or "").strip()
    if not endpoint_name and not endpoint_path:
        return None
    if not endpoint_name or len(endpoint_name) > 150:
        raise ValueError("Endpoint name is required and must be 150 characters or fewer.")
    if not endpoint_path:
        raise ValueError("Endpoint path is required when an endpoint name is provided.")
    endpoint_path = _validate_internal_path(endpoint_path, "Endpoint path")
    if not endpoint_path.startswith("/api/"):
        raise ValueError("Endpoint path must start with /api/.")
    return {"endpoint_name": endpoint_name, "endpoint_path": endpoint_path}


def _normalized_external_url(value):
    parsed = urlsplit(str(value or "").strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or 443
    path = parsed.path.rstrip("/") or "/"
    return parsed.scheme.lower(), host, port, path


def _fetch_json(url, *, expected_code=None, endpoint_name="Module endpoint"):
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
        if endpoint_name == "API endpoint":
            raise ValueError("API endpoint validation failed: expected JSON.") from exc
        raise ValueError(f"{endpoint_name} must return a JSON object.") from exc
    if not isinstance(data, dict):
        if endpoint_name == "API endpoint":
            raise ValueError("API endpoint validation failed: expected JSON.")
        raise ValueError(f"{endpoint_name} must return a JSON object.")
    if expected_code and data.get("module_code") != expected_code:
        raise ValueError("Module health response has the wrong module_code.")
    return data


def _default_module_identity(source_url):
    host_label = (urlsplit(source_url).hostname or "external-module").split(".")[0]
    code = re.sub(r"[^A-Z0-9]+", "_", host_label.upper()).strip("_")
    if not code or not code[0].isalpha():
        code = f"MODULE_{code}"
    if len(code) < 2:
        code = f"{code}_MODULE"
    code = code[:100].rstrip("_")
    name = re.sub(r"[-_]+", " ", host_label).strip().title() or "External Module"
    return code, name[:150]


def validate_module_registration(payload):
    payload = payload or {}
    web_url = str(payload.get("web_url", "")).strip()
    api_base_url = str(payload.get("api_base_url", "")).strip()
    manifest_url = str(payload.get("manifest_url", "")).strip()
    health_url = str(payload.get("health_url", "")).strip()
    endpoint = _validate_api_endpoint(payload)
    if not any((web_url, api_base_url, manifest_url)):
        raise ValueError("A web URL or API endpoint is required.")

    web_url = _validate_url(web_url, "Module web_url") if web_url else None
    api_base_url = _validate_url(api_base_url, "Module api_base_url") if api_base_url else None
    manifest_url = _validate_url(manifest_url, "Manifest URL") if manifest_url else None
    health_url = _validate_url(health_url, "Module health_url") if health_url else None

    has_manifest = bool(manifest_url)
    if has_manifest:
        manifest = _fetch_json(manifest_url, endpoint_name="Manifest endpoint")
    elif api_base_url:
        manifest = _fetch_json(api_base_url, endpoint_name="API endpoint")
    else:
        manifest = {}

    api_base_url = api_base_url or manifest.get("api_base_url")
    if api_base_url:
        api_base_url = _validate_url(api_base_url, "Module api_base_url")
    health_url = health_url or manifest.get("health_url")
    if health_url:
        health_url = _validate_url(health_url, "Module health_url")

    candidate_web_url = web_url or manifest.get("web_url") or api_base_url or manifest_url
    if not candidate_web_url:
        raise ValueError("A web URL or API endpoint is required.")
    web_url = web_url or _validate_url(candidate_web_url, "Module web_url")

    default_code, default_name = _default_module_identity(web_url)
    code = str(manifest.get("module_code") or ("" if has_manifest else default_code)).strip()
    name = str(manifest.get("module_name") or ("" if has_manifest else default_name)).strip()
    version = str(manifest.get("version") or ("" if has_manifest else "1.0.0")).strip()
    if not MODULE_CODE_PATTERN.fullmatch(code):
        raise ValueError("Manifest module_code must use uppercase letters, digits, and underscores.")
    if not name or len(name) > 150:
        raise ValueError("Manifest module_name is required and must be 150 characters or fewer.")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Manifest version must use semantic version format, such as 1.0.0.")

    health = None
    if health_url:
        health = _fetch_json(health_url, expected_code=code, endpoint_name="Health endpoint")
        if health.get("module_code") != code:
            raise ValueError("Module health response has the wrong module_code.")
        if health.get("status") != "UP" or health.get("version") != version:
            raise ValueError("Module health endpoint must report status UP and the registered version.")

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
        "health_status": "UP" if health else "UNKNOWN",
        "validation_mode": "api-enabled" if api_base_url or manifest_url or health_url else "web-only",
        "endpoint_name": endpoint["endpoint_name"] if endpoint else None,
        "endpoint_path": endpoint["endpoint_path"] if endpoint else None,
    }


def validate_manifest(manifest_url):
    return validate_module_registration({"manifest_url": manifest_url})


def register_module(
    manifest, actor_id, parent_menu_id=None, display_order=0, endpoint_id=None, api_id=None,
    module_classification="NON_CONFIGURATION",
):
    health_status = manifest.get("health_status", "UNKNOWN")
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _validate_module_parent(cur, parent_menu_id)
            if parent_menu_id not in (None, ""):
                cur.execute(
                    "SELECT menu_classification FROM app_security.menus WHERE menu_id = %s",
                    (int(parent_menu_id),),
                )
                parent = cur.fetchone()
                if not parent:
                    raise ValueError("Choose a valid parent menu.")
                module_classification = parent["menu_classification"]
            module_classification = str(module_classification or "NON_CONFIGURATION").upper()
            if module_classification not in {"CONFIGURATION", "NON_CONFIGURATION"}:
                raise ValueError("Module classification must be CONFIGURATION or NON_CONFIGURATION.")
            cur.execute(
                f"""INSERT INTO app_security.modules
                    (module_code, module_name, description, version, module_type, module_classification,
                     is_enabled, web_url, api_base_url, manifest_url, health_url,
                        entry_path, icon, parent_menu_id, display_order,
                        health_status, last_health_check_at, capabilities, created_by)
                           VALUES (%s, %s, %s, %s, 'EXTERNAL', %s, FALSE, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            CASE WHEN %s = 'UP' THEN CURRENT_TIMESTAMP ELSE NULL END,
                            %s, %s)
                    ON CONFLICT (module_code) DO NOTHING
                    RETURNING {MODULE_COLUMNS}""",
                (
                    manifest["module_code"], manifest["module_name"], manifest["description"],
                    manifest["version"], module_classification, manifest["web_url"], manifest["api_base_url"],
                    manifest["manifest_url"], manifest["health_url"], manifest["entry_path"],
                    manifest["icon"], parent_menu_id, max(0, int(display_order)),
                    manifest.get("health_status", "UNKNOWN"), manifest.get("health_status", "UNKNOWN"),
                    Json(manifest["capabilities"]), actor_id,
                ),
            )
            module_row = cur.fetchone()
            registration_reused = module_row is None
            if registration_reused:
                cur.execute(
                    f"""SELECT {MODULE_COLUMNS} FROM app_security.modules
                        WHERE module_code = %s FOR UPDATE""",
                    (manifest["module_code"],),
                )
                existing = cur.fetchone()
                if not existing:
                    raise ValueError("The module registry changed during registration. Please retry.")
                existing = dict(existing)
                if (
                    existing["module_type"] != "EXTERNAL"
                    or _normalized_external_url(existing["web_url"])
                    != _normalized_external_url(manifest["web_url"])
                ):
                    raise ModuleCodeConflictError(manifest["module_code"])
                cur.execute(
                    f"""UPDATE app_security.modules SET
                            module_name = %s, description = %s, version = %s,
                            web_url = %s, api_base_url = %s, manifest_url = %s,
                            health_url = %s, entry_path = %s, icon = %s,
                            parent_menu_id = %s, display_order = %s,
                            module_classification = %s,
                            health_status = %s,
                            last_health_check_at = CASE
                                WHEN %s = 'UP' THEN CURRENT_TIMESTAMP
                                WHEN %s IS NULL THEN NULL
                                ELSE last_health_check_at
                            END,
                            capabilities = %s, is_active = TRUE,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE module_id = %s
                        RETURNING {MODULE_COLUMNS}""",
                    (
                        manifest["module_name"], manifest["description"], manifest["version"],
                        manifest["web_url"], manifest["api_base_url"], manifest["manifest_url"],
                        manifest["health_url"], manifest["entry_path"], manifest["icon"],
                        parent_menu_id, max(0, int(display_order)), module_classification, health_status,
                        health_status, manifest["health_url"],
                        Json(manifest["capabilities"]), existing["module_id"],
                    ),
                )
                module_row = cur.fetchone()
                if not module_row:
                    raise ValueError("The existing module could not be updated. Please retry.")
            module = dict(module_row)
            endpoint = _validate_api_endpoint(manifest)
            if endpoint_id not in (None, ""):
                try:
                    endpoint_id = int(endpoint_id)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Choose a valid internal API endpoint.") from exc
                cur.execute(
                    """SELECT endpoint_id FROM app_security.api_endpoints
                       WHERE endpoint_id = %s AND is_active
                         AND endpoint_source = 'INTERNAL'
                       FOR UPDATE""",
                    (endpoint_id,),
                )
                if not cur.fetchone():
                    raise ValueError("The selected internal API endpoint is not available.")
                cur.execute(
                    """INSERT INTO app_security.module_api_endpoints
                        (module_id, endpoint_id, assigned_by)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (module_id) DO UPDATE
                         SET endpoint_id = EXCLUDED.endpoint_id,
                             assigned_by = EXCLUDED.assigned_by,
                             assigned_at = CURRENT_TIMESTAMP""",
                    (module["module_id"], endpoint_id, actor_id),
                )
            if api_id not in (None, ""):
                _assign_api_catalog(cur, module["module_id"], api_id, actor_id)
            elif endpoint:
                cur.execute(
                    """INSERT INTO app_security.api_endpoints
                        (endpoint_name, endpoint_path, created_by)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (endpoint_path) DO NOTHING
                       RETURNING endpoint_id, endpoint_name, endpoint_path""",
                    (
                        endpoint["endpoint_name"],
                        endpoint["endpoint_path"],
                        actor_id,
                    ),
                )
                endpoint_row = cur.fetchone()
                if not endpoint_row:
                    cur.execute(
                        """SELECT endpoint_id, endpoint_name, endpoint_path
                           FROM app_security.api_endpoints
                           WHERE endpoint_path = %s AND is_active
                           FOR UPDATE""",
                        (endpoint["endpoint_path"],),
                    )
                    endpoint_row = cur.fetchone()
                    if not endpoint_row:
                        raise ValueError("The endpoint catalog changed during registration. Please retry.")
                    if endpoint_row["endpoint_name"] != endpoint["endpoint_name"]:
                        raise ValueError("This endpoint path is already registered with a different name.")
                cur.execute(
                    """INSERT INTO app_security.module_api_endpoints
                        (module_id, endpoint_id, assigned_by)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (module_id) DO UPDATE
                         SET endpoint_id = EXCLUDED.endpoint_id,
                             assigned_by = EXCLUDED.assigned_by,
                             assigned_at = CURRENT_TIMESTAMP""",
                    (module["module_id"], endpoint_row["endpoint_id"], actor_id),
                )
            cur.execute(
                """INSERT INTO app_security.role_module_permissions
                    (role_id, module_id, can_view, can_create, can_edit, can_delete, can_execute)
                    SELECT role_id, %s, role_name = 'ADMIN', FALSE, FALSE, FALSE, FALSE
                    FROM app_security.roles ON CONFLICT (role_id, module_id) DO NOTHING""",
                (module["module_id"],),
            )
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, %s, %s)""",
                (
                    actor_id,
                    "MODULE_REGISTRATION_REUSED" if registration_reused else "MODULE_REGISTERED",
                    Json({"module_code": module["module_code"], "module_id": module["module_id"]}),
                ),
            )
        conn.commit()
    module["registration_reused"] = registration_reused
    return module


def list_api_endpoints():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT endpoint_id, endpoint_name, endpoint_path
                   FROM app_security.api_endpoints
                   WHERE is_active AND endpoint_source = 'INTERNAL'
                   ORDER BY LOWER(endpoint_name), endpoint_path"""
            )
            return [dict(row) for row in cur.fetchall()]


def _api_display_name(slug):
    known_names = {
        "database-health": "Database Health",
        "health": "Database Health",
        "database-tools": "SQL Query",
        "database-query": "SQL Query",
        "db-compare": "DB Compare",
        "compare": "DB Compare",
        "schema-tracker": "DB Schema Tracker",
    }
    if slug.lower() in known_names:
        return f"{known_names[slug.lower()]} API"
    words = re.sub(r"[-_]+", " ", slug).split()
    acronyms = {"db": "DB", "sql": "SQL"}
    return " ".join(acronyms.get(word.lower(), word.title()) for word in words) + " API"


def sync_internal_api_catalog(endpoints, actor_id=None):
    paths = {endpoint["endpoint_path"]: endpoint for endpoint in endpoints}
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT DISTINCT api.api_id, api.api_base_url, api.endpoint_id,
                          api.manifest_url, api.health_url, api.sql_url
                   FROM app_security.api_catalog AS api
                   WHERE api.api_type = 'INTERNAL' AND api.is_active
                     AND (
                         EXISTS (
                             SELECT 1
                             FROM app_security.module_api_catalog AS assignment
                             JOIN app_security.modules AS module
                               ON module.module_id = assignment.module_id
                              AND module.is_active
                              AND module.module_type = 'INTERNAL'
                             WHERE assignment.api_id = api.api_id
                         )
                         OR EXISTS (
                             SELECT 1
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                         )
                     )"""
            )
            configured_apis = cur.fetchall()
            for api in configured_apis:
                base_url = api["api_base_url"].rstrip("/")
                related = {
                    kind: paths.get(f"{base_url}/{kind}")
                    for kind in ("manifest", "health", "sql")
                }
                cur.execute(
                    """UPDATE app_security.api_catalog
                       SET endpoint_id = COALESCE(%s, endpoint_id),
                         manifest_url = COALESCE(%s, manifest_url),
                         health_url = COALESCE(%s, health_url),
                         sql_url = COALESCE(%s, sql_url),
                         updated_at = CURRENT_TIMESTAMP
                       WHERE api_id = %s""",
                    (
                        paths.get(base_url, {}).get("endpoint_id"),
                        related["manifest"]["endpoint_path"] if related["manifest"] else None,
                        related["health"]["endpoint_path"] if related["health"] else None,
                        related["sql"]["endpoint_path"] if related["sql"] else None,
                        api["api_id"],
                    ),
                )
        conn.commit()
    return list_assignable_api_catalog()


def list_api_catalog(include_inactive=False):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT api.api_id, api.api_name, api.api_type,
                          api.api_base_url, api.web_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.manifest_url,
                            (SELECT module.manifest_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.manifest_url END AS manifest_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.health_url,
                            (SELECT module.health_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.health_url END AS health_url,
                          api.sql_url, api.endpoint_id, endpoint.endpoint_path,
                          api.is_active
                   FROM app_security.api_catalog AS api
                   LEFT JOIN app_security.api_endpoints AS endpoint
                     ON endpoint.endpoint_id = api.endpoint_id
                   WHERE %s OR api.is_active
                   ORDER BY api.api_type, LOWER(api.api_name), api.api_id""",
                (bool(include_inactive),),
            )
            apis = [dict(row) for row in cur.fetchall()]
            for api in apis:
                   api["api_id"] = str(api["api_id"])
                   if api["endpoint_id"] is not None:
                       api["endpoint_id"] = str(api["endpoint_id"])
            return apis


def list_assignable_api_catalog():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT api.api_id, api.api_name, api.api_type,
                          api.api_base_url, api.web_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.manifest_url,
                            (SELECT module.manifest_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.manifest_url END AS manifest_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.health_url,
                            (SELECT module.health_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.health_url END AS health_url,
                          api.sql_url, api.endpoint_id,
                          endpoint.endpoint_path, api.is_active
                   FROM app_security.api_catalog AS api
                   LEFT JOIN app_security.api_endpoints AS endpoint
                     ON endpoint.endpoint_id = api.endpoint_id
                   WHERE api.is_active
                     AND (
                         api.api_type = 'EXTERNAL'
                         OR api.source_key LIKE 'INTERNAL:MANUAL:%'
                         OR EXISTS (
                             SELECT 1
                             FROM app_security.module_api_catalog AS assignment
                             JOIN app_security.modules AS module
                               ON module.module_id = assignment.module_id
                              AND module.is_active
                              AND module.module_type = 'INTERNAL'
                             WHERE assignment.api_id = api.api_id
                         )
                         OR EXISTS (
                             SELECT 1
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                         )
                     )
                   ORDER BY api.api_type, LOWER(api.api_name), api.api_id"""
            )
            apis = [dict(row) for row in cur.fetchall()]
            for api in apis:
                api["api_id"] = str(api["api_id"])
                if api["endpoint_id"] is not None:
                    api["endpoint_id"] = str(api["endpoint_id"])
            return apis


def save_external_api(payload, actor_id, api_id=None):
    payload = payload or {}
    api_name = str(payload.get("api_name") or "").strip()
    if not api_name or len(api_name) > 150:
        raise ValueError("API name is required and must be 150 characters or fewer.")
    api_base_url = _validate_url(payload.get("api_base_url"), "API Base URL")
    web_url = str(payload.get("web_url") or "").strip()
    web_url = _validate_url(web_url, "Web URL") if web_url else None
    related = {}
    for field, label in (
        ("manifest_url", "Manifest URL"),
        ("health_url", "Health URL"),
        ("sql_url", "SQL URL"),
    ):
        value = str(payload.get(field) or "").strip()
        related[field] = _validate_url(value, label) if value else None

    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if api_id is None:
                cur.execute(
                    """INSERT INTO app_security.api_catalog
                        (api_name, api_type, source_key, api_base_url, web_url, manifest_url,
                         health_url, sql_url, created_by)
                       VALUES (%s, 'EXTERNAL', %s, %s, %s, %s, %s, %s, %s)
                       RETURNING api_id""",
                    (
                        api_name, f"EXTERNAL:{secrets.token_urlsafe(24)}",
                        api_base_url, web_url, related["manifest_url"], related["health_url"],
                        related["sql_url"], actor_id,
                    ),
                )
            else:
                cur.execute(
                    """UPDATE app_security.api_catalog SET
                           api_name = %s, api_base_url = %s, web_url = %s, manifest_url = %s,
                           health_url = %s, sql_url = %s,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE api_id = %s AND api_type = 'EXTERNAL'
                         AND is_active
                       RETURNING api_id""",
                    (
                        api_name, api_base_url, web_url, related["manifest_url"],
                        related["health_url"], related["sql_url"], api_id,
                    ),
                )
            row = cur.fetchone()
            if not row:
                raise ValueError("External API was not found or is disabled.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, %s, %s)""",
                (
                    actor_id,
                    "API_REGISTERED" if api_id is None else "API_UPDATED",
                    Json({"api_id": row["api_id"], "api_name": api_name}),
                ),
            )
        conn.commit()
    return row["api_id"]


def set_api_enabled(api_id, enabled, actor_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE app_security.api_catalog SET is_active = %s,
                       updated_at = CURRENT_TIMESTAMP
                   WHERE api_id = %s AND api_type = 'EXTERNAL'
                   RETURNING api_name""",
                (bool(enabled), api_id),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("External API was not found.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, %s, %s)""",
                (
                    actor_id, "API_ENABLED" if enabled else "API_DISABLED",
                    Json({"api_id": api_id, "api_name": row[0]}),
                ),
            )
        conn.commit()


def sync_internal_api_endpoints(routes, actor_id=None):
    endpoints = {}
    for path, endpoint_name in routes:
        if not isinstance(path, str) or not path.startswith("/api/") or path.startswith("//"):
            continue
        endpoint_name = re.sub(r"[^A-Za-z0-9 _.-]", " ", str(endpoint_name))
        endpoint_name = re.sub(r"\s+", " ", endpoint_name).strip()[:150]
        if endpoint_name:
            endpoints[path] = endpoint_name

    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            path_parameters = tuple(endpoints)
            if path_parameters:
                placeholders = ", ".join(["%s"] * len(path_parameters))
                cur.execute(
                    f"""UPDATE app_security.api_endpoints
                        SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                        WHERE endpoint_source = 'INTERNAL' AND is_active
                          AND endpoint_path NOT IN ({placeholders})""",
                    path_parameters,
                )
            else:
                cur.execute(
                    """UPDATE app_security.api_endpoints
                       SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                       WHERE endpoint_source = 'INTERNAL' AND is_active"""
                )
            if endpoints:
                value_placeholders = ", ".join(
                    ["(%s, %s, 'INTERNAL', %s)"] * len(endpoints)
                )
                parameters = tuple(
                    value
                    for path, endpoint_name in endpoints.items()
                    for value in (endpoint_name, path, actor_id)
                )
                cur.execute(
                    f"""INSERT INTO app_security.api_endpoints
                        (endpoint_name, endpoint_path, endpoint_source, created_by)
                       VALUES {value_placeholders}
                       ON CONFLICT (endpoint_path) DO UPDATE SET
                         endpoint_name = EXCLUDED.endpoint_name,
                         endpoint_source = 'INTERNAL',
                         is_active = TRUE,
                         updated_at = CURRENT_TIMESTAMP
                       WHERE app_security.api_endpoints.endpoint_name
                                 <> EXCLUDED.endpoint_name
                          OR app_security.api_endpoints.endpoint_source
                                 <> 'INTERNAL'
                          OR NOT app_security.api_endpoints.is_active""",
                    parameters,
                )
            cur.execute(
                """SELECT endpoint_id, endpoint_name, endpoint_path
                   FROM app_security.api_endpoints
                   WHERE is_active AND endpoint_source = 'INTERNAL'
                   ORDER BY LOWER(endpoint_name), endpoint_path"""
            )
            registered = [dict(row) for row in cur.fetchall()]
        conn.commit()
    return registered


def list_module_api_endpoint_assignments():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT assignment.module_id, assignment.endpoint_id
                   FROM app_security.module_api_endpoints AS assignment
                   JOIN app_security.api_endpoints AS endpoint
                     ON endpoint.endpoint_id = assignment.endpoint_id
                   WHERE endpoint.is_active"""
            )
            return {
                row["module_id"]: row["endpoint_id"]
                for row in cur.fetchall()
            }


def list_module_api_catalog_assignments():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT module.module_id,
                          COALESCE(catalog.api_id, legacy_api.api_id) AS api_id
                   FROM app_security.modules AS module
                   LEFT JOIN app_security.module_api_catalog AS assignment
                     ON assignment.module_id = module.module_id
                   LEFT JOIN app_security.api_catalog AS catalog
                     ON catalog.api_id = assignment.api_id AND catalog.is_active
                   LEFT JOIN app_security.module_api_endpoints AS old_assignment
                     ON old_assignment.module_id = module.module_id
                   LEFT JOIN app_security.api_catalog AS legacy_api
                     ON legacy_api.endpoint_id = old_assignment.endpoint_id
                        AND legacy_api.api_type = 'INTERNAL'
                        AND legacy_api.is_active
                   WHERE catalog.api_id IS NOT NULL OR legacy_api.api_id IS NOT NULL"""
            )
            return {row["module_id"]: row["api_id"] for row in cur.fetchall()}


def list_module_api_catalog():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT module.module_id, module.module_code, module.module_name,
                          module.module_type,
                          COALESCE(assigned_api.api_id, legacy_api.api_id) AS api_id,
                          COALESCE(assigned_api.api_name, legacy_api.api_name,
                                   module.module_name || ' API') AS api_name,
                          COALESCE(assigned_api.api_type, legacy_api.api_type,
                                   module.module_type) AS api_type,
                          COALESCE(assigned_api.api_base_url, legacy_api.api_base_url,
                                   module.api_base_url) AS api_base_url,
                          COALESCE(assigned_api.manifest_url, legacy_api.manifest_url,
                                   module.manifest_url) AS manifest_url,
                          COALESCE(assigned_api.health_url, legacy_api.health_url,
                                   module.health_url) AS health_url,
                          COALESCE(assigned_api.sql_url, legacy_api.sql_url) AS sql_url,
                          COALESCE(assigned_api.is_active, legacy_api.is_active, TRUE)
                              AS is_active
                   FROM app_security.modules AS module
                   LEFT JOIN app_security.module_api_catalog AS assignment
                     ON assignment.module_id = module.module_id
                   LEFT JOIN app_security.api_catalog AS assigned_api
                     ON assigned_api.api_id = assignment.api_id
                   LEFT JOIN app_security.module_api_endpoints AS old_assignment
                     ON old_assignment.module_id = module.module_id
                   LEFT JOIN app_security.api_catalog AS legacy_api
                     ON legacy_api.endpoint_id = old_assignment.endpoint_id
                        AND legacy_api.api_type = 'INTERNAL'
                   WHERE module.is_active
                     AND (assigned_api.api_id IS NOT NULL
                          OR legacy_api.api_id IS NOT NULL
                          OR module.api_base_url IS NOT NULL)
                   ORDER BY module.display_order, LOWER(module.module_name),
                            module.module_id"""
            )
            modules = [dict(row) for row in cur.fetchall()]
            for module in modules:
                if module["api_id"] is not None:
                    module["api_id"] = str(module["api_id"])
            return modules


def list_configured_api_catalog():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT api.api_id, api.api_name, api.api_type,
                          api.api_base_url, api.web_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.manifest_url,
                            (SELECT module.manifest_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.manifest_url END AS manifest_url,
                          CASE WHEN api.api_type = 'INTERNAL' THEN COALESCE(
                            api.health_url,
                            (SELECT module.health_url
                             FROM app_security.modules AS module
                             WHERE module.is_active
                               AND module.module_type = 'INTERNAL'
                               AND module.api_base_url = api.api_base_url
                             ORDER BY module.module_id
                             LIMIT 1)
                          ) ELSE api.health_url END AS health_url,
                          api.sql_url, api.endpoint_id, endpoint.endpoint_path,
                          api.is_active
                   FROM app_security.api_catalog AS api
                   LEFT JOIN app_security.api_endpoints AS endpoint
                     ON endpoint.endpoint_id = api.endpoint_id
                   WHERE api.source_key LIKE 'INTERNAL:MANUAL:%'
                      OR EXISTS (
                          SELECT 1
                          FROM app_security.module_api_catalog AS assignment
                          JOIN app_security.modules AS module
                            ON module.module_id = assignment.module_id
                           AND module.is_active
                          WHERE assignment.api_id = api.api_id
                      )
                      OR (
                          api.api_type = 'INTERNAL'
                          AND EXISTS (
                              SELECT 1
                              FROM app_security.modules AS module
                              WHERE module.is_active
                                AND module.module_type = 'INTERNAL'
                                AND module.api_base_url = api.api_base_url
                          )
                      )
                   ORDER BY api.api_type, LOWER(api.api_name), api.api_id"""
            )
            apis = [dict(row) for row in cur.fetchall()]
            for api in apis:
                api["api_id"] = str(api["api_id"])
                if api["endpoint_id"] is not None:
                    api["endpoint_id"] = str(api["endpoint_id"])
            return apis


def save_internal_api(payload, actor_id, api_id=None):
    payload = payload or {}
    api_name = str(payload.get("api_name") or "").strip()
    if not api_name or len(api_name) > 150:
        raise ValueError("API name is required and must be 150 characters or fewer.")
    api_base_url = _validate_internal_path(payload.get("api_base_url"), "API Base URL")

    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT endpoint_id
                   FROM app_security.api_endpoints
                   WHERE endpoint_path = %s AND is_active
                     AND endpoint_source = 'INTERNAL'""",
                (api_base_url,),
            )
            endpoint = cur.fetchone()
            if not endpoint:
                raise ValueError("API Base URL must match an active internal API route.")
            if api_id is None:
                source_key = f"INTERNAL:MANUAL:{api_base_url}"
                cur.execute(
                    """INSERT INTO app_security.api_catalog
                        (api_name, api_type, source_key, api_base_url, endpoint_id, created_by)
                       VALUES (%s, 'INTERNAL', %s, %s, %s, %s)
                       RETURNING api_id""",
                    (api_name, source_key, api_base_url, endpoint["endpoint_id"], actor_id),
                )
            else:
                cur.execute(
                    """UPDATE app_security.api_catalog SET
                           api_name = %s, source_key = %s, api_base_url = %s,
                           endpoint_id = %s, updated_at = CURRENT_TIMESTAMP
                       WHERE api_id = %s AND api_type = 'INTERNAL'
                         AND source_key LIKE 'INTERNAL:MANUAL:%'
                       RETURNING api_id""",
                    (
                        api_name, f"INTERNAL:MANUAL:{api_base_url}",
                        api_base_url, endpoint["endpoint_id"], api_id,
                    ),
                )
            row = cur.fetchone()
            if not row:
                raise ValueError("Internal API was not found or is not administrator-managed.")
            cur.execute(
                """INSERT INTO app_security.audit_logs (user_id, action, details)
                   VALUES (%s, %s, %s)""",
                (
                    actor_id,
                    "API_REGISTERED" if api_id is None else "API_UPDATED",
                    Json({"api_id": row["api_id"], "api_name": api_name}),
                ),
            )
        conn.commit()
    return row["api_id"]


def _assign_api_catalog(cursor, module_id, api_id, actor_id):
    if api_id in (None, ""):
        cursor.execute(
            "DELETE FROM app_security.module_api_catalog WHERE module_id = %s",
            (module_id,),
        )
        cursor.execute(
            """DELETE FROM app_security.module_api_endpoints
               WHERE module_id = %s AND endpoint_id IN (
                   SELECT endpoint_id FROM app_security.api_endpoints
                   WHERE endpoint_source = 'INTERNAL'
               )""",
            (module_id,),
        )
        return
    try:
        api_id = int(api_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose a valid API.") from exc
    cursor.execute(
        """SELECT api_id, api_type, api_base_url, endpoint_id,
                  manifest_url, health_url, sql_url
           FROM app_security.api_catalog
           WHERE api_id = %s AND is_active
           FOR UPDATE""",
        (api_id,),
    )
    api = cursor.fetchone()
    if not api:
        raise ValueError("The selected API is not available.")
    if api["api_type"] == "INTERNAL":
        cursor.execute(
            """SELECT 1
               FROM app_security.module_api_catalog AS assignment
               JOIN app_security.modules AS module
                 ON module.module_id = assignment.module_id
               WHERE assignment.api_id = %s
                 AND assignment.module_id <> %s
                 AND module.module_type = 'INTERNAL'
                 AND module.is_active
               LIMIT 1""",
            (api_id, module_id),
        )
        if cursor.fetchone():
            raise ValueError("This internal API is already assigned to another active module.")
    cursor.execute(
        """INSERT INTO app_security.module_api_catalog
            (module_id, api_id, assigned_by)
           VALUES (%s, %s, %s)
           ON CONFLICT (module_id) DO UPDATE SET
             api_id = EXCLUDED.api_id, assigned_by = EXCLUDED.assigned_by,
             assigned_at = CURRENT_TIMESTAMP""",
        (module_id, api_id, actor_id),
    )
    cursor.execute(
        """UPDATE app_security.modules SET
               api_base_url = %s, manifest_url = %s, health_url = %s,
               updated_at = CURRENT_TIMESTAMP
           WHERE module_id = %s""",
        (api["api_base_url"], api["manifest_url"], api["health_url"], module_id),
    )
    if api["api_type"] == "INTERNAL" and api["endpoint_id"] is not None:
        cursor.execute(
            """INSERT INTO app_security.module_api_endpoints
                (module_id, endpoint_id, assigned_by)
               VALUES (%s, %s, %s)
               ON CONFLICT (module_id) DO UPDATE SET
                 endpoint_id = EXCLUDED.endpoint_id,
                 assigned_by = EXCLUDED.assigned_by,
                 assigned_at = CURRENT_TIMESTAMP""",
            (module_id, api["endpoint_id"], actor_id),
        )
    else:
        cursor.execute(
            "DELETE FROM app_security.module_api_endpoints WHERE module_id = %s",
            (module_id,),
        )


def list_navigation_menus():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT menu_id, parent_menu_id, menu_name, menu_code,
                          menu_type, menu_classification, route_path
                   FROM app_security.menus
                   WHERE is_active
                   ORDER BY COALESCE(parent_menu_id, menu_id), display_order, menu_name"""
            )
            return [dict(row) for row in cur.fetchall()]


def _module_code_from_name(value):
    code = re.sub(r"[^A-Z0-9]+", "_", str(value or "").strip().upper()).strip("_")
    if not code or not code[0].isalpha():
        code = f"MODULE_{code}"
    if len(code) < 2:
        code = f"{code}_MODULE"
    code = code[:100].rstrip("_")
    if not MODULE_CODE_PATTERN.fullmatch(code):
        raise ValueError("Module name cannot be converted to a valid module code.")
    return code


def _create_internal_module(
    cursor, *, module_name, route_path, actor_id, parent_menu_id=None,
    navigation_menu_id=None, api_id=None, display_order=0, module_code=None,
    module_classification="NON_CONFIGURATION",
):
    module_name = str(module_name or "").strip()
    if not module_name or len(module_name) > 150:
        raise ValueError("Module name is required and must be 150 characters or fewer.")
    module_code = module_code or _module_code_from_name(module_name)
    if not MODULE_CODE_PATTERN.fullmatch(module_code):
        raise ValueError("Module code must use uppercase letters, digits, and underscores.")
    parent_menu_id = int(parent_menu_id) if parent_menu_id not in (None, "") else None
    _validate_module_parent(cursor, parent_menu_id)
    menu, parent_menu_id = _validated_navigation_menu(
        cursor, navigation_menu_id, parent_menu_id
    )
    route_path = _validate_internal_path(
        menu["route_path"] if menu else route_path,
        "Internal route",
    )
    classification_menu_id = (
        menu["menu_id"] if menu else parent_menu_id
    )
    if classification_menu_id is not None:
        cursor.execute(
            "SELECT menu_classification FROM app_security.menus WHERE menu_id = %s",
            (classification_menu_id,),
        )
        classification_row = cursor.fetchone()
        if not classification_row:
            raise ValueError("Choose a valid menu classification.")
        module_classification = classification_row["menu_classification"]
    module_classification = str(module_classification or "NON_CONFIGURATION").upper()
    if module_classification not in {"CONFIGURATION", "NON_CONFIGURATION"}:
        raise ValueError("Module classification must be CONFIGURATION or NON_CONFIGURATION.")
    cursor.execute(
        f"""SELECT {MODULE_COLUMNS} FROM app_security.modules
            WHERE module_code = %s OR navigation_menu_id = %s
            FOR UPDATE""",
        (module_code, menu["menu_id"] if menu else None),
    )
    existing = cursor.fetchone()
    if existing:
        if existing["module_type"] != "INTERNAL":
            raise ModuleCodeConflictError(module_code)
        cursor.execute(
            """UPDATE app_security.modules SET
                   module_name = %s, web_url = %s, parent_menu_id = %s,
                   navigation_menu_id = %s, display_order = %s,
                   module_classification = %s,
                   updated_at = CURRENT_TIMESTAMP
               WHERE module_id = %s""",
            (
                module_name, route_path, parent_menu_id,
                menu["menu_id"] if menu else None, max(0, int(display_order)),
                module_classification,
                existing["module_id"],
            ),
        )
        module_id = existing["module_id"]
    else:
        cursor.execute(
            f"""INSERT INTO app_security.modules
                (module_code, module_name, version, module_type, is_enabled,
                 module_classification, web_url, entry_path, icon, parent_menu_id, navigation_menu_id,
                 display_order, health_status, created_by)
               VALUES (%s, %s, '1.0.0', 'INTERNAL', FALSE, %s, %s, '/', 'database',
                       %s, %s, %s, 'UP', %s)
               RETURNING {MODULE_COLUMNS}""",
            (
                module_code, module_name, module_classification, route_path, parent_menu_id,
                menu["menu_id"] if menu else None, max(0, int(display_order)), actor_id,
            ),
        )
        existing = cursor.fetchone()
        module_id = existing["module_id"]
        cursor.execute(
            """INSERT INTO app_security.role_module_permissions
                (role_id, module_id, can_view, can_create, can_edit, can_delete, can_execute)
               SELECT role_id, %s, role_name = 'ADMIN', FALSE, FALSE, FALSE, FALSE
               FROM app_security.roles
               ON CONFLICT (role_id, module_id) DO NOTHING""",
            (module_id,),
        )
    _assign_api_catalog(cursor, module_id, api_id, actor_id)
    cursor.execute(
        """INSERT INTO app_security.audit_logs (user_id, action, details)
           VALUES (%s, 'INTERNAL_MODULE_CONFIGURED', %s)""",
        (actor_id, Json({"module_id": module_id, "module_code": module_code})),
    )
    return module_id


def create_internal_module(payload, actor_id):
    payload = payload or {}
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            module_id = _create_internal_module(
                cur,
                module_name=payload.get("module_name"),
                module_code=payload.get("module_code") or None,
                route_path=payload.get("route_path"),
                actor_id=actor_id,
                parent_menu_id=payload.get("parent_menu_id"),
                navigation_menu_id=payload.get("navigation_menu_id"),
                api_id=payload.get("api_id"),
                display_order=payload.get("display_order", 0),
                module_classification=payload.get("module_classification", "NON_CONFIGURATION"),
            )
            cur.execute(f"SELECT {MODULE_COLUMNS} FROM app_security.modules WHERE module_id = %s", (module_id,))
            module = dict(cur.fetchone())
        conn.commit()
    return module


def convert_menu_to_module(menu_id, payload, actor_id):
    payload = payload or {}
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT menu_id, parent_menu_id, menu_name, menu_code,
                          menu_type, menu_classification, route_path
                   FROM app_security.menus
                   WHERE menu_id = %s AND is_active AND menu_type = 'INTERNAL'
                     AND route_path IS NOT NULL
                     AND menu_classification = 'NON_CONFIGURATION'
                   FOR UPDATE""",
                (menu_id,),
            )
            menu = cur.fetchone()
            if not menu:
                raise ValueError("Choose an active internal menu with a route.")
            module_name = payload.get("module_name") or re.sub(
                r"\bDashboard\b", "", menu["menu_name"], flags=re.IGNORECASE
            ).strip()
            module_id = _create_internal_module(
                cur,
                module_name=module_name,
                module_code=payload.get("module_code") or _module_code_from_name(module_name),
                route_path=menu["route_path"],
                actor_id=actor_id,
                parent_menu_id=menu["parent_menu_id"],
                navigation_menu_id=menu["menu_id"],
                api_id=payload.get("api_id"),
                display_order=payload.get("display_order", 0),
                module_classification=menu["menu_classification"],
            )
            cur.execute(f"SELECT {MODULE_COLUMNS} FROM app_security.modules WHERE module_id = %s", (module_id,))
            module = dict(cur.fetchone())
        conn.commit()
    return module


def list_modules(limit=100, offset=0, include_inactive=False):
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""SELECT {', '.join('module.' + column.strip() for column in MODULE_COLUMNS.split(','))},
                           parent.menu_name AS parent_menu_name
                    FROM app_security.modules AS module
                    LEFT JOIN app_security.menus AS parent
                      ON parent.menu_id = module.parent_menu_id
                    WHERE %s OR module.is_active
                    ORDER BY module.display_order, module.module_name, module.module_id
                    LIMIT %s OFFSET %s""",
                (
                    bool(include_inactive),
                    max(1, min(int(limit), 101)),
                    max(0, int(offset)),
                ),
            )
            return [dict(row) for row in cur.fetchall()]


def list_available_modules(user_id, limit=100, offset=0, cursor=None):
    parameters = (user_id, max(1, min(int(limit), 101)), max(0, int(offset)))
    query = "SELECT * FROM app_security.fn_get_available_modules(%s, %s, %s)"
    if cursor is not None:
        cursor.execute(query, parameters)
        columns = [column.name for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, parameters)
            return [dict(row) for row in cur.fetchall()]


def list_parent_menus():
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT menu.menu_id, menu.menu_name, menu.menu_code,
                          menu.parent_menu_id, menu.menu_classification,
                          parent.menu_name AS parent_menu_name
                   FROM app_security.menus AS menu
                   LEFT JOIN app_security.menus AS parent
                     ON parent.menu_id = menu.parent_menu_id
                   WHERE menu.is_active
                     AND menu.menu_type = 'GROUP'
                     AND (
                         menu.parent_menu_id IS NULL
                         OR (
                             parent.is_active
                             AND parent.menu_type = 'GROUP'
                             AND parent.parent_menu_id IS NULL
                         )
                     )
                   ORDER BY COALESCE(parent.display_order, menu.display_order),
                            COALESCE(parent.menu_name, menu.menu_name),
                            menu.display_order, menu.menu_name"""
            )
            return [dict(row) for row in cur.fetchall()]


def _validate_module_parent(cursor, parent_menu_id):
    if parent_menu_id in (None, ""):
        return
    cursor.execute(
        """SELECT 1
           FROM app_security.menus AS menu
           LEFT JOIN app_security.menus AS parent
             ON parent.menu_id = menu.parent_menu_id
           WHERE menu.menu_id = %s
             AND menu.is_active
             AND menu.menu_type = 'GROUP'
             AND (
                 menu.parent_menu_id IS NULL
                 OR (
                     parent.is_active
                     AND parent.menu_type = 'GROUP'
                     AND parent.parent_menu_id IS NULL
                 )
             )""",
        (parent_menu_id,),
    )
    if not cursor.fetchone():
        raise ValueError("Choose an active parent menu.")


def _validated_navigation_menu(cursor, menu_id, parent_menu_id=None):
    if menu_id in (None, ""):
        return None, parent_menu_id
    try:
        menu_id = int(menu_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose a valid navigation menu.") from exc
    cursor.execute(
        """SELECT menu_id, parent_menu_id, route_path, menu_classification
           FROM app_security.menus
           WHERE menu_id = %s AND is_active AND menu_type = 'INTERNAL'
             AND route_path IS NOT NULL
           FOR UPDATE""",
        (menu_id,),
    )
    menu = cursor.fetchone()
    if not menu:
        raise ValueError("The selected menu is not an active internal route.")
    if parent_menu_id not in (None, "", menu["parent_menu_id"]):
        raise ValueError("The selected submenu does not belong to the chosen parent menu.")
    parent_menu_id = menu["parent_menu_id"]
    return menu, parent_menu_id


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
                    m.module_classification,
                    EXISTS (
                        SELECT 1 FROM app_security.user_roles ur
                        JOIN app_security.roles r ON r.role_id = ur.role_id AND r.is_active
                        JOIN app_security.role_module_permissions p ON p.role_id = r.role_id
                            AND p.module_id = m.module_id AND p.{permission}
                        WHERE ur.user_id = u.user_id
                    ) AS role_granted,
                    EXISTS (
                        SELECT 1 FROM app_security.user_module_access uma
                        WHERE uma.user_id = u.user_id AND uma.module_id = m.module_id
                    ) AS module_assigned
                    FROM app_security.users u
                    JOIN app_security.modules m ON m.module_code = %s
                        AND m.is_active AND m.is_enabled
                    WHERE u.user_id = %s AND u.is_active""",
                (module_code, user_id),
            )
            state = cur.fetchone()
    if not state:
        return False
    is_admin, configured, _nav_menu_id, module_classification, role_granted, module_assigned = state
    if is_admin:
        return True
    if module_classification != "NON_CONFIGURATION":
        return False
    if permission == "can_view" and configured:
        return module_assigned
    return role_granted and (not configured or _nav_menu_id is None or module_assigned)


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
        web_url = _validate_url(web_url, "Module web_url") if web_url else None
        api_base_url = _validate_url(api_base_url, "Module api_base_url") if api_base_url else None
        manifest_url = _validate_url(manifest_url, "Manifest URL") if manifest_url else None
        health_url = _validate_url(health_url, "Module health_url") if health_url else None
        if not web_url:
            web_url = api_base_url or manifest_url
        if not web_url:
            raise ValueError("A web URL or API endpoint is required.")
    entry_path = _validate_entry_path(payload.get("entry_path", "/"))
    version = str(payload.get("version", "")).strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Version must use semantic version format, such as 1.0.0.")
    capabilities = payload.get("capabilities", current["capabilities"] or [])
    if not isinstance(capabilities, list) or len(capabilities) > 32 or any(not isinstance(item, str) or len(item) > 80 for item in capabilities):
        raise ValueError("Capabilities must be a list of at most 32 short strings.")
    try:
        parent_value = payload.get("parent_menu_id", current["parent_menu_id"])
        parent_menu_id = int(parent_value) if parent_value not in (None, "") else None
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose an active parent menu.") from exc
    with security_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _validate_module_parent(cur, parent_menu_id)
            navigation_menu_value = payload.get(
                "navigation_menu_id", current.get("navigation_menu_id")
            )
            navigation_menu, parent_menu_id = _validated_navigation_menu(
                cur, navigation_menu_value, parent_menu_id
            )
            classification_menu_id = (
                navigation_menu["menu_id"] if navigation_menu else parent_menu_id
            )
            if classification_menu_id is not None:
                cur.execute(
                    "SELECT menu_classification FROM app_security.menus WHERE menu_id = %s",
                    (classification_menu_id,),
                )
                classification_row = cur.fetchone()
                if not classification_row:
                    raise ValueError("Choose a valid menu classification.")
                module_classification = classification_row["menu_classification"]
            else:
                module_classification = str(
                    payload.get("module_classification", current.get("module_classification", "NON_CONFIGURATION"))
                ).upper()
                if module_classification not in {"CONFIGURATION", "NON_CONFIGURATION"}:
                    raise ValueError(
                        "Module classification must be CONFIGURATION or NON_CONFIGURATION."
                    )
            cur.execute(
                f"""UPDATE app_security.modules SET
                    module_name = %s, description = %s, version = %s,
                    web_url = %s, api_base_url = %s, manifest_url = %s,
                    health_url = %s, entry_path = %s, icon = %s,
                    capabilities = %s,
                    parent_menu_id = %s, navigation_menu_id = %s,
                    module_classification = %s,
                    display_order = %s,
                    updated_at = CURRENT_TIMESTAMP
                    WHERE module_id = %s AND is_active
                    RETURNING {MODULE_COLUMNS}""",
                (
                    module_name,
                    str(payload.get("description", ""))[:2000], version,
                    web_url, api_base_url, manifest_url, health_url,
                    entry_path, icon, Json(capabilities),
                    parent_menu_id, navigation_menu["menu_id"] if navigation_menu else None,
                    module_classification,
                    max(0, int(payload.get("display_order", 0))),
                    module_id,
                ),
            )
            module = cur.fetchone()
            if not module:
                raise ValueError("Module was not found or has been de-registered.")
            if module_classification == "CONFIGURATION":
                cur.execute(
                    """DELETE FROM app_security.user_module_access
                       WHERE module_id = %s""",
                    (module_id,),
                )
            has_api_assignment = "api_id" in payload
            if has_api_assignment:
                cur.execute("SELECT to_regclass('app_security.api_catalog') AS relation")
                api_catalog_available = cur.fetchone()["relation"] is not None
                if not api_catalog_available and payload.get("api_id") not in (None, ""):
                    raise ValueError(
                        "Apply the module API catalog migration before assigning an API."
                    )
                if api_catalog_available:
                    _assign_api_catalog(cur, module_id, payload.get("api_id"), actor_id)
            endpoint_id = None if has_api_assignment else payload.get("endpoint_id")
            cur.execute(
                "SELECT to_regclass('app_security.module_api_endpoints') AS relation"
            )
            endpoint_mapping_available = cur.fetchone()["relation"] is not None
            if not endpoint_mapping_available and endpoint_id not in (None, ""):
                raise ValueError(
                    "Apply the module endpoint catalog migration before assigning an API endpoint."
                )
            if endpoint_mapping_available and endpoint_id in (None, ""):
                cur.execute(
                    """DELETE FROM app_security.module_api_endpoints AS assignment
                       USING app_security.api_endpoints AS endpoint
                       WHERE assignment.module_id = %s
                         AND endpoint.endpoint_id = assignment.endpoint_id
                         AND endpoint.endpoint_source = 'INTERNAL'""",
                    (module_id,),
                )
            elif endpoint_mapping_available:
                try:
                    endpoint_id = int(endpoint_id)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Choose a valid API endpoint.") from exc
                cur.execute(
                    """SELECT 1 FROM app_security.api_endpoints
                       WHERE endpoint_id = %s AND is_active
                         AND endpoint_source = 'INTERNAL'""",
                    (endpoint_id,),
                )
                if not cur.fetchone():
                    raise ValueError("The selected API endpoint is not available.")
                cur.execute(
                    """INSERT INTO app_security.module_api_endpoints
                        (module_id, endpoint_id, assigned_by)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (module_id) DO UPDATE
                         SET endpoint_id = EXCLUDED.endpoint_id,
                             assigned_by = EXCLUDED.assigned_by,
                             assigned_at = CURRENT_TIMESTAMP""",
                    (module_id, endpoint_id, actor_id),
                )
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
    status = "UNKNOWN"
    detail = "No health endpoint is configured."
    if module["module_type"] == "INTERNAL":
        status, detail = "UP", "Platform-hosted module is responding to the health-check request."
    elif module["health_url"]:
        status, detail = "DOWN", "Health endpoint is unavailable."
        try:
            health = _fetch_json(
                module["health_url"], expected_code=module["module_code"],
                endpoint_name="Health endpoint",
            )
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