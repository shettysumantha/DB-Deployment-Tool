import os
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

from werkzeug.security import check_password_hash, generate_password_hash

from .db_service import connection


SCHEMA = "app_security"


def _config_from_url():
    value = os.getenv("APP_DATABASE_URL", "").strip()
    if not value:
        raise ValueError("APP_DATABASE_URL must be configured for authentication.")
    parsed = urlparse(value)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        raise ValueError("APP_DATABASE_URL must be a PostgreSQL connection URL.")
    query = parse_qs(parsed.query)
    return {
        "host": parsed.hostname,
        "port": parsed.port or 5432,
        "database": (parsed.path or "").lstrip("/"),
        "username": parsed.username or "",
        "password": parsed.password or "",
        "sslmode": query.get("sslmode", ["require"])[0],
    }


@contextmanager
def security_connection():
    with connection(_config_from_url()) as conn:
        yield conn


def authenticate(identifier, password):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, username, email, full_name, password_hash
                FROM app_security.users
                WHERE is_active AND (username = %s OR lower(email) = lower(%s))
                """,
                (identifier, identifier),
            )
            user = cur.fetchone()
            if not user or not check_password_hash(user[4], password):
                return None
            cur.execute(
                """
                SELECT r.role_name FROM app_security.roles r
                JOIN app_security.user_roles ur ON ur.role_id = r.role_id
                WHERE ur.user_id = %s AND r.is_active
                ORDER BY r.role_name
                """,
                (user[0],),
            )
            roles = [row[0] for row in cur.fetchall()]
            cur.execute(
                "UPDATE app_security.users SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                (user[0],),
            )
            cur.execute(
                """
                INSERT INTO app_security.login_audit
                    (user_id, username, ip_address, user_agent, login_status)
                VALUES (%s, %s, %s, %s, 'SUCCESS')
                """,
                (user[0], user[1], _request_ip(), _request_agent()),
            )
        conn.commit()
    return {"user_id": user[0], "username": user[1], "email": user[2], "full_name": user[3], "roles": roles}


def record_failed_login(identifier):
    try:
        with security_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO app_security.login_audit (username, ip_address, user_agent, login_status) VALUES (%s, %s, %s, 'FAILED')",
                    (identifier, _request_ip(), _request_agent()),
                )
            conn.commit()
    except Exception:
        pass


def logout(user_id, username):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO app_security.login_audit (user_id, username, ip_address, user_agent, login_status) VALUES (%s, %s, %s, %s, 'LOGOUT')",
                (user_id, username, _request_ip(), _request_agent()),
            )
        conn.commit()


def user_menus(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT m.menu_id, m.parent_menu_id, m.menu_name, m.menu_code,
                    m.menu_type, m.route_path, m.external_url, m.icon, m.display_order,
                    m.open_in_new_tab
                FROM app_security.menus m
                JOIN app_security.role_menu_permissions p ON p.menu_id = m.menu_id AND p.can_view
                JOIN app_security.user_roles ur ON ur.role_id = p.role_id
                JOIN app_security.roles r ON r.role_id = ur.role_id AND r.is_active
                WHERE ur.user_id = %s AND m.is_active
                ORDER BY COALESCE(m.parent_menu_id, 0), m.display_order, m.menu_name
                """,
                (user_id,),
            )
            rows = [dict(zip(("menu_id", "parent_menu_id", "menu_name", "menu_code", "menu_type", "route_path", "external_url", "icon", "display_order", "open_in_new_tab"), row)) for row in cur.fetchall()]
    by_id = {row["menu_id"]: {**row, "children": []} for row in rows}
    roots = []
    for menu in by_id.values():
        parent = by_id.get(menu["parent_menu_id"])
        (parent["children"] if parent else roots).append(menu)
    return roots


def has_permission(user_id, menu_code, permission="can_view"):
    if permission not in {"can_view", "can_create", "can_edit", "can_delete", "can_execute"}:
        return False
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT EXISTS (
                    SELECT 1 FROM app_security.user_roles ur
                    JOIN app_security.role_menu_permissions p ON p.role_id = ur.role_id AND p.{permission}
                    JOIN app_security.menus m ON m.menu_id = p.menu_id AND m.is_active
                    WHERE ur.user_id = %s AND m.menu_code = %s
                )""",
                (user_id, menu_code),
            )
            return cur.fetchone()[0]


def list_menus():
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT menu_id, parent_menu_id, menu_name, menu_code, menu_type, route_path, external_url, icon, display_order, is_active, open_in_new_tab FROM app_security.menus ORDER BY COALESCE(parent_menu_id, 0), display_order, menu_name")
            columns = [item.name for item in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def save_menu(data, menu_id=None):
    menu_type = str(data.get("menu_type", "INTERNAL")).upper()
    if menu_type not in {"INTERNAL", "EXTERNAL", "GROUP"}:
        raise ValueError("Menu type must be INTERNAL, EXTERNAL, or GROUP.")
    if menu_type == "INTERNAL" and not data.get("route_path"):
        raise ValueError("Internal menus require a route path.")
    if menu_type == "EXTERNAL" and not data.get("external_url"):
        raise ValueError("External menus require an external URL.")
    values = (data.get("parent_menu_id") or None, data["menu_name"].strip(), data["menu_code"].strip().upper(), menu_type, data.get("route_path") or None, data.get("external_url") or None, data.get("icon") or "menu", int(data.get("display_order", 0)), bool(data.get("is_active", True)), bool(data.get("open_in_new_tab", False)))
    with security_connection() as conn:
        with conn.cursor() as cur:
            if menu_id:
                cur.execute("""UPDATE app_security.menus SET parent_menu_id=%s, menu_name=%s, menu_code=%s, menu_type=%s, route_path=%s, external_url=%s, icon=%s, display_order=%s, is_active=%s, open_in_new_tab=%s, updated_at=CURRENT_TIMESTAMP WHERE menu_id=%s RETURNING menu_id""", (*values, menu_id))
            else:
                cur.execute("""INSERT INTO app_security.menus (parent_menu_id, menu_name, menu_code, menu_type, route_path, external_url, icon, display_order, is_active, open_in_new_tab) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING menu_id""", values)
            result = cur.fetchone()[0]
        conn.commit()
    return result


def delete_menu(menu_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM app_security.menus WHERE menu_id = %s", (menu_id,))
        conn.commit()


def list_users():
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT u.user_id, u.username, u.email, u.full_name, u.is_active, COALESCE(string_agg(r.role_name, ', ' ORDER BY r.role_name), '') FROM app_security.users u LEFT JOIN app_security.user_roles ur ON ur.user_id = u.user_id LEFT JOIN app_security.roles r ON r.role_id = ur.role_id GROUP BY u.user_id ORDER BY u.username""")
            return [dict(zip(("user_id", "username", "email", "full_name", "is_active", "roles"), row)) for row in cur.fetchall()]


def create_user(data):
    password = data.get("password", "")
    if not data.get("username") or not password:
        raise ValueError("Username and password are required.")
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO app_security.users (username, email, full_name, password_hash, is_active) VALUES (%s,%s,%s,%s,%s) RETURNING user_id", (data["username"].strip(), data.get("email") or None, data.get("full_name") or data["username"], password_hash(password), bool(data.get("is_active", True))))
            user_id = cur.fetchone()[0]
            if data.get("role_id"):
                cur.execute("INSERT INTO app_security.user_roles (user_id, role_id) VALUES (%s,%s)", (user_id, data["role_id"]))
        conn.commit()
    return user_id


def list_roles():
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT role_id, role_name, role_description, is_active FROM app_security.roles ORDER BY role_name")
            return [dict(zip(("role_id", "role_name", "role_description", "is_active"), row)) for row in cur.fetchall()]


def save_role(data, role_id=None):
    with security_connection() as conn:
        with conn.cursor() as cur:
            if role_id:
                cur.execute("UPDATE app_security.roles SET role_name=%s, role_description=%s, is_active=%s WHERE role_id=%s", (data["role_name"].strip().upper(), data.get("role_description"), bool(data.get("is_active", True)), role_id))
            else:
                cur.execute("INSERT INTO app_security.roles (role_name, role_description, is_active) VALUES (%s,%s,%s)", (data["role_name"].strip().upper(), data.get("role_description"), bool(data.get("is_active", True))))
        conn.commit()


def save_permissions(role_id, permissions):
    with security_connection() as conn:
        with conn.cursor() as cur:
            for item in permissions:
                cur.execute("""INSERT INTO app_security.role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete, can_execute) VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (role_id, menu_id) DO UPDATE SET can_view=EXCLUDED.can_view, can_create=EXCLUDED.can_create, can_edit=EXCLUDED.can_edit, can_delete=EXCLUDED.can_delete, can_execute=EXCLUDED.can_execute""", (role_id, item["menu_id"], bool(item.get("can_view")), bool(item.get("can_create")), bool(item.get("can_edit")), bool(item.get("can_delete")), bool(item.get("can_execute"))))
        conn.commit()


def _request_ip():
    from flask import request
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _request_agent():
    from flask import request
    return request.headers.get("User-Agent", "")


def password_hash(password):
    return generate_password_hash(password)
