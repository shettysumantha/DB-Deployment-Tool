import hashlib
import hmac
import re
import secrets
import threading
from contextlib import contextmanager
from urllib.parse import parse_qs, unquote, urlparse

from psycopg2.errors import UniqueViolation
from psycopg2.extras import Json
from werkzeug.security import check_password_hash, generate_password_hash

from core.config.config import APP_DATABASE_URL
from core.database.db_service import connection


SCHEMA = "app_security"
_schema_initialized = False
_schema_init_lock = threading.Lock()


class UserNotFoundError(LookupError):
    pass


def _config_from_url():
    value = APP_DATABASE_URL.strip()

    if not value:
        raise ValueError(
            "Configure APP_DATABASE_URL or PG_HOST, PG_DATABASE, and PG_USER "
            "for the application database."
        )

    parsed = urlparse(value)

    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        raise ValueError(
            "APP_DATABASE_URL must be a PostgreSQL connection URL."
        )

    query = parse_qs(parsed.query)

    return {
        "host": parsed.hostname,
        "port": parsed.port or 5432,
        "database": unquote((parsed.path or "").lstrip("/")),
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "sslmode": query.get("sslmode", ["require"])[0],
        "sslrootcert": query.get("sslrootcert", ["system"])[0],
    }


@contextmanager
def security_connection():
    with connection(_config_from_url()) as conn:
        yield conn


def initialize_security():
    global _schema_initialized

    if _schema_initialized:
        return True

    with _schema_init_lock:
        if _schema_initialized:
            return True

        with security_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass(%s)",
                    ("app_security.users",),
                )

                if cur.fetchone()[0] is None:
                    raise RuntimeError(
                        "Required security database objects are unavailable. "
                        "A DBA must manually execute database_security.sql."
                    )

        _schema_initialized = True

    return True


def authenticate(identifier, password, admin_required=False):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, username, email, full_name, password_hash,
                       session_version, must_change_password, is_admin
                FROM app_security.users
                WHERE is_active
                  AND (username = %s OR lower(email) = lower(%s))
                """,
                (identifier, identifier),
            )

            user = cur.fetchone()

            if not user or not check_password_hash(user[4], password):
                return None

            cur.execute(
                """
                SELECT r.role_name
                FROM app_security.roles r
                JOIN app_security.user_roles ur
                  ON ur.role_id = r.role_id
                WHERE ur.user_id = %s
                  AND r.is_active
                ORDER BY r.role_name
                """,
                (user[0],),
            )

            roles = [row[0] for row in cur.fetchall()]

            if admin_required and (not user[7] or "ADMIN" not in roles):
                return {"admin_access_denied": True}

            cur.execute(
                """
                UPDATE app_security.users
                SET last_login_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                """,
                (user[0],),
            )

            cur.execute(
                """
                INSERT INTO app_security.login_audit
                    (user_id, username, ip_address, user_agent, login_status)
                VALUES (%s, %s, %s, %s, 'SUCCESS')
                """,
                (
                    user[0],
                    user[1],
                    _request_ip(),
                    _request_agent(),
                ),
            )

            _audit(
                cur,
                user[0],
                "LOGIN_SUCCESS",
                user[0],
            )

        conn.commit()

    return {
        "user_id": user[0],
        "username": user[1],
        "email": user[2],
        "full_name": user[3],
        "roles": roles,
        "session_version": user[5],
        "must_change_password": user[6],
        "is_admin": user[7],
    }


def user_is_active(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT is_active
                FROM app_security.users
                WHERE user_id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()

    return bool(row and row[0])


def user_is_admin(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.is_admin AND EXISTS (
                    SELECT 1
                    FROM app_security.user_roles ur
                    JOIN app_security.roles r
                      ON r.role_id = ur.role_id
                    WHERE ur.user_id = u.user_id
                      AND r.role_name = 'ADMIN'
                      AND r.is_active
                )
                FROM app_security.users u
                WHERE u.user_id = %s
                  AND u.is_active
                """,
                (user_id,),
            )

            row = cur.fetchone()

    return bool(row and row[0])


def user_session_state(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT is_active, session_version, must_change_password
                FROM app_security.users
                WHERE user_id = %s
                """,
                (user_id,),
            )

            row = cur.fetchone()

    if not row:
        return None

    return {
        "is_active": row[0],
        "session_version": row[1],
        "must_change_password": row[2],
    }


def user_roles(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.role_name
                FROM app_security.roles r
                JOIN app_security.user_roles ur
                  ON ur.role_id = r.role_id
                WHERE ur.user_id = %s
                  AND r.is_active
                ORDER BY r.role_name
                """,
                (user_id,),
            )

            return [row[0] for row in cur.fetchall()]


def user_has_role(user_id, role_name):
    role_name = role_name.upper()

    if role_name == "ADMIN":
        return user_is_admin(user_id)

    return role_name in user_roles(user_id)


def _fetch_modules(cursor):
    cursor.execute(
        """
                SELECT m.module_id,
                             m.module_name,
                             m.module_type,
                             m.is_enabled,
                             m.parent_menu_id,
                             CASE WHEN assigned_parent.parent_menu_id IS NULL
                                        THEN NULL ELSE assigned_parent.menu_name END AS submenu_name,
                             CASE WHEN assigned_parent.parent_menu_id IS NULL
                                        THEN assigned_parent.menu_name ELSE main_menu.menu_name END AS parent_menu_name
                FROM app_security.modules AS m
                LEFT JOIN app_security.menus AS assigned_parent
                    ON assigned_parent.menu_id = m.parent_menu_id
                LEFT JOIN app_security.menus AS main_menu
                    ON main_menu.menu_id = COALESCE(
                            assigned_parent.parent_menu_id, assigned_parent.menu_id
                    )
                WHERE m.is_active
                ORDER BY COALESCE(main_menu.display_order, 0), main_menu.menu_name,
                                 COALESCE(assigned_parent.display_order, 0), assigned_parent.menu_name,
                                 m.display_order, m.module_name
        """
    )

    columns = (
                "module_id",
                "module_name",
                "module_type",
                "is_enabled",
                "parent_menu_id",
                "submenu_name",
                "parent_menu_name",
    )

    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def list_modules():
    with security_connection() as conn:
        with conn.cursor() as cur:
            return _fetch_modules(cur)


def user_module_ids(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT menu_id
                FROM app_security.user_menu_access
                WHERE user_id = %s
                ORDER BY menu_id
                """,
                (user_id,),
            )

            return [row[0] for row in cur.fetchall()]


def _audit(
    cursor,
    actor_id,
    action,
    target_user_id=None,
    details=None,
):
    cursor.execute(
        """
        INSERT INTO app_security.audit_logs
            (user_id, action, target_user_id, details)
        VALUES (%s, %s, %s, %s)
        """,
        (
            actor_id,
            action,
            target_user_id,
            Json(details or {}),
        ),
    )


def audit_event(
    action,
    actor_id=None,
    target_user_id=None,
    details=None,
):
    with security_connection() as conn:
        with conn.cursor() as cur:
            _audit(
                cur,
                actor_id,
                action,
                target_user_id,
                details,
            )

        conn.commit()


def admin_exists():
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM app_security.users u
                    LEFT JOIN app_security.user_roles ur
                      ON ur.user_id = u.user_id
                    LEFT JOIN app_security.roles r
                      ON r.role_id = ur.role_id
                    WHERE u.is_admin
                       OR r.role_name = 'ADMIN'
                )
                """
            )

            return cur.fetchone()[0]


def create_bootstrap_admin(data, configured_passkey):
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    passkey = data.get("passkey", "")

    if not configured_passkey or not hmac.compare_digest(
        str(passkey),
        str(configured_passkey),
    ):
        try:
            audit_event(
                "ADMIN_BOOTSTRAP_FAILED",
                details={"reason": "invalid_passkey"},
            )
        except Exception:
            pass

        raise ValueError("Passkey is wrong.")

    if not username or not email:
        try:
            audit_event(
                "ADMIN_BOOTSTRAP_FAILED",
                details={"reason": "missing_identity"},
            )
        except Exception:
            pass

        raise ValueError(
            "Admin username and email are required."
        )

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        raise ValueError(
            "Enter a valid email address."
        )

    try:
        validate_password(password)
    except ValueError:
        try:
            audit_event(
                "ADMIN_BOOTSTRAP_FAILED",
                details={"reason": "password_policy"},
            )
        except Exception:
            pass

        raise

    try:
        with security_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO app_security.roles
                        (role_name, role_description, is_active)
                    VALUES
                        (
                            'ADMIN',
                            'Full application administration',
                            TRUE
                        )
                    ON CONFLICT (role_name)
                    DO UPDATE SET is_active = TRUE
                    RETURNING role_id
                    """
                )

                admin_role_id = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO app_security.users
                        (
                            username,
                            email,
                            full_name,
                            password_hash,
                            is_active,
                            module_access_configured,
                            is_admin
                        )
                    VALUES
                        (%s, %s, %s, %s, TRUE, FALSE, TRUE)
                    RETURNING user_id
                    """,
                    (
                        username,
                        email,
                        data.get("full_name") or username,
                        password_hash(password),
                    ),
                )

                user_id = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO app_security.user_roles
                        (user_id, role_id)
                    VALUES (%s, %s)
                    """,
                    (
                        user_id,
                        admin_role_id,
                    ),
                )

                cur.execute(
                    """
                    INSERT INTO app_security.role_menu_permissions
                        (
                            role_id,
                            menu_id,
                            can_view,
                            can_create,
                            can_edit,
                            can_delete,
                            can_execute
                        )
                    SELECT
                        %s,
                        menu_id,
                        TRUE,
                        TRUE,
                        TRUE,
                        TRUE,
                        menu_code = 'DEPLOYMENT_MANAGER'
                    FROM app_security.menus
                    WHERE is_active
                    ON CONFLICT (role_id, menu_id)
                    DO UPDATE SET
                        can_view = TRUE,
                        can_create = TRUE,
                        can_edit = TRUE,
                        can_delete = TRUE,
                        can_execute = EXCLUDED.can_execute
                    """,
                    (admin_role_id,),
                )

                _audit(
                    cur,
                    user_id,
                    "ADMIN_BOOTSTRAP_SUCCESS",
                    user_id,
                )

            conn.commit()

    except UniqueViolation as exc:
        constraint = (
            getattr(
                getattr(exc, "diag", None),
                "constraint_name",
                "",
            )
            or ""
        ).lower()

        reason = (
            "username_exists"
            if "username" in constraint
            else "email_exists"
            if "email" in constraint
            else "duplicate_identity"
        )

        try:
            audit_event(
                "ADMIN_BOOTSTRAP_FAILED",
                details={"reason": reason},
            )
        except Exception:
            pass

        message = (
            "Username already exists."
            if reason == "username_exists"
            else "Email already exists."
            if reason == "email_exists"
            else "Username or email already exists."
        )

        raise ValueError(message) from exc

    return user_id


def request_password_reset(identifier):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, email
                FROM app_security.users
                WHERE is_active
                  AND (
                      username = %s
                      OR lower(email) = lower(%s)
                  )
                """,
                (
                    identifier.strip(),
                    identifier.strip(),
                ),
            )

            user = cur.fetchone()
            token = None

            if user:
                cur.execute(
                    """
                    UPDATE app_security.password_reset_tokens
                    SET used_at = CURRENT_TIMESTAMP
                    WHERE user_id = %s
                      AND used_at IS NULL
                    """,
                    (user[0],),
                )

                token = secrets.token_urlsafe(32)

                cur.execute(
                    """
                    INSERT INTO app_security.password_reset_tokens
                        (
                            user_id,
                            token_hash,
                            expires_at
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            CURRENT_TIMESTAMP + INTERVAL '20 minutes'
                        )
                    """,
                    (
                        user[0],
                        hashlib.sha256(
                            token.encode("utf-8")
                        ).hexdigest(),
                    ),
                )

            _audit(
                cur,
                user[0] if user else None,
                "PASSWORD_RESET_REQUESTED",
                user[0] if user else None,
                {"account_match": bool(user)},
            )

        conn.commit()

    return (
        {"email": user[1], "token": token}
        if user
        else None
    )


def complete_password_reset(token, new_password):
    validate_password(new_password)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id
                FROM app_security.password_reset_tokens
                WHERE token_hash = %s
                  AND used_at IS NULL
                  AND expires_at > CURRENT_TIMESTAMP
                FOR UPDATE
                """,
                (token_hash,),
            )

            row = cur.fetchone()

            if not row:
                return False

            user_id = row[0]

            cur.execute(
                """
                UPDATE app_security.users
                SET password_hash = %s,
                    session_version = session_version + 1,
                    must_change_password = FALSE,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                  AND is_active
                """,
                (
                    password_hash(new_password),
                    user_id,
                ),
            )

            if cur.rowcount != 1:
                return False

            cur.execute(
                """
                UPDATE app_security.password_reset_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                  AND used_at IS NULL
                """,
                (user_id,),
            )

            _audit(
                cur,
                user_id,
                "PASSWORD_RESET_COMPLETED",
                user_id,
            )

        conn.commit()

    return True


def change_password(
    user_id,
    current_password,
    new_password,
):
    validate_password(new_password)

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT password_hash
                FROM app_security.users
                WHERE user_id = %s
                  AND is_active
                FOR UPDATE
                """,
                (user_id,),
            )

            row = cur.fetchone()

            if not row or not check_password_hash(
                row[0],
                current_password,
            ):
                return False

            cur.execute(
                """
                UPDATE app_security.users
                SET password_hash = %s,
                    session_version = session_version + 1,
                    must_change_password = FALSE,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                """,
                (
                    password_hash(new_password),
                    user_id,
                ),
            )

            cur.execute(
                """
                UPDATE app_security.password_reset_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                  AND used_at IS NULL
                """,
                (user_id,),
            )

            _audit(
                cur,
                user_id,
                "PASSWORD_CHANGED",
                user_id,
            )

        conn.commit()

    return True


def record_failed_login(identifier):
    try:
        with security_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO app_security.login_audit
                        (
                            username,
                            ip_address,
                            user_agent,
                            login_status
                        )
                    VALUES (%s, %s, %s, 'FAILED')
                    """,
                    (
                        identifier,
                        _request_ip(),
                        _request_agent(),
                    ),
                )

                _audit(
                    cur,
                    None,
                    "LOGIN_FAILED",
                    details={
                        "identifier_supplied": bool(identifier)
                    },
                )

            conn.commit()

    except Exception:
        pass


def logout(user_id, username):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_security.login_audit
                    (
                        user_id,
                        username,
                        ip_address,
                        user_agent,
                        login_status
                    )
                VALUES (%s, %s, %s, %s, 'LOGOUT')
                """,
                (
                    user_id,
                    username,
                    _request_ip(),
                    _request_agent(),
                ),
            )

            _audit(
                cur,
                user_id,
                "LOGOUT",
                user_id,
            )

        conn.commit()


def user_menus(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    u.module_access_configured,
                    u.is_admin AND EXISTS (
                        SELECT 1
                        FROM app_security.user_roles ur
                        JOIN app_security.roles r
                          ON r.role_id = ur.role_id
                        WHERE ur.user_id = u.user_id
                          AND r.is_active
                          AND r.role_name = 'ADMIN'
                    )
                FROM app_security.users u
                WHERE u.user_id = %s
                """,
                (user_id,),
            )

            access_configured, is_admin = cur.fetchone()

            if is_admin or not access_configured:
                cur.execute(
                    """
                    SELECT
                        menu_id,
                        parent_menu_id,
                        menu_name,
                        menu_code,
                        menu_type,
                        route_path,
                        external_url,
                        icon,
                        display_order,
                        open_in_new_tab
                    FROM (
                        SELECT DISTINCT
                            m.menu_id,
                            m.parent_menu_id,
                            m.menu_name,
                            m.menu_code,
                            m.menu_type,
                            m.route_path,
                            m.external_url,
                            m.icon,
                            m.display_order,
                            m.open_in_new_tab
                        FROM app_security.menus m
                        JOIN app_security.role_menu_permissions p
                          ON p.menu_id = m.menu_id
                         AND p.can_view
                        JOIN app_security.user_roles ur
                          ON ur.role_id = p.role_id
                        JOIN app_security.roles r
                          ON r.role_id = ur.role_id
                         AND r.is_active
                        WHERE ur.user_id = %s
                          AND m.is_active
                    ) AS visible_menus
                    ORDER BY COALESCE(parent_menu_id, 0),
                             display_order,
                             menu_name
                    """,
                    (user_id,),
                )

            else:
                cur.execute(
                    """
                    SELECT
                        menu_id,
                        parent_menu_id,
                        menu_name,
                        menu_code,
                        menu_type,
                        route_path,
                        external_url,
                        icon,
                        display_order,
                        open_in_new_tab
                    FROM (
                        SELECT DISTINCT
                            m.menu_id,
                            m.parent_menu_id,
                            m.menu_name,
                            m.menu_code,
                            m.menu_type,
                            m.route_path,
                            m.external_url,
                            m.icon,
                            m.display_order,
                            m.open_in_new_tab
                        FROM app_security.menus m
                        WHERE m.is_active
                          AND (
                              EXISTS (
                                  SELECT 1
                                  FROM app_security.user_menu_access a
                                  WHERE a.user_id = %s
                                    AND a.menu_id = m.menu_id
                              )
                              OR EXISTS (
                                  SELECT 1
                                  FROM app_security.user_menu_access a
                                  WHERE a.user_id = %s
                                    AND a.menu_id = m.parent_menu_id
                              )
                          )
                    ) AS visible_menus
                    ORDER BY COALESCE(parent_menu_id, 0),
                             display_order,
                             menu_name
                    """,
                    (
                        user_id,
                        user_id,
                    ),
                )

            columns = (
                "menu_id",
                "parent_menu_id",
                "menu_name",
                "menu_code",
                "menu_type",
                "route_path",
                "external_url",
                "icon",
                "display_order",
                "open_in_new_tab",
            )

            rows = [
                dict(zip(columns, row))
                for row in cur.fetchall()
            ]

            if is_admin:
                cur.execute(
                    """SELECT menu_id, parent_menu_id, menu_name, menu_code,
                              menu_type, route_path, external_url, icon,
                              display_order, open_in_new_tab
                       FROM app_security.menus
                       WHERE is_active AND menu_type = 'GROUP'"""
                )
                rows.extend(
                    dict(zip(columns, row))
                    for row in cur.fetchall()
                )

            from core.module_registry.module_service import list_available_modules

            available_modules = list_available_modules(user_id, cursor=cur)
            module_parent_ids = sorted(
                {module["parent_menu_id"] for module in available_modules}
            )
            if module_parent_ids:
                cur.execute(
                    """SELECT menu_id, parent_menu_id, menu_name, menu_code,
                              menu_type, route_path, external_url, icon,
                              display_order, open_in_new_tab
                       FROM app_security.menus
                       WHERE menu_id = ANY(%s)
                          OR menu_id IN (
                              SELECT parent_menu_id
                              FROM app_security.menus
                              WHERE menu_id = ANY(%s)
                                AND parent_menu_id IS NOT NULL
                          )""",
                    (module_parent_ids, module_parent_ids),
                )
                rows.extend(
                    dict(zip(columns, row))
                    for row in cur.fetchall()
                )

    by_id = {
        row["menu_id"]: {
            **row,
            "children": [],
        }
        for row in rows
    }

    roots = []

    for menu in by_id.values():
        parent = by_id.get(menu["parent_menu_id"])

        if parent:
            parent["children"].append(menu)
        else:
            roots.append(menu)

    for module in available_modules:
        parent_id = module["parent_menu_id"]
        parent = by_id.get(parent_id)

        if parent is None:
            parent = {
                "menu_id": parent_id,
                "parent_menu_id": None,
                "menu_name": module["parent_menu_name"],
                "menu_code": "MODULE_PARENT",
                "menu_type": "GROUP",
                "route_path": None,
                "external_url": None,
                "icon": "database",
                "display_order": 0,
                "open_in_new_tab": False,
                "children": [],
            }

            roots.append(parent)
            by_id[parent_id] = parent

        parent["children"].append(
            {
                "menu_id": -module["module_id"],
                "parent_menu_id": parent_id,
                "menu_name": module["module_name"],
                "menu_code": module["module_code"],
                "menu_type": module["module_type"],
                "route_path": f"/modules/{module['module_code']}/launch",
                "external_url": f"/modules/{module['module_code']}/launch"
                if module["module_type"] == "EXTERNAL"
                else None,
                "icon": module["icon"],
                "display_order": module["display_order"],
                "open_in_new_tab": module["module_type"] == "EXTERNAL",
                "children": [],
            }
        )

        parent["children"].sort(
            key=lambda item: (
                item["display_order"],
                item["menu_name"],
            )
        )

    roots.sort(
        key=lambda item: (
            item["display_order"],
            item["menu_name"],
        )
    )

    return roots


def has_permission(
    user_id,
    menu_code,
    permission="can_view",
):
    allowed_permissions = {
        "can_view",
        "can_create",
        "can_edit",
        "can_delete",
        "can_execute",
    }

    if permission not in allowed_permissions:
        return False

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    u.module_access_configured,
                    u.is_admin AND EXISTS (
                        SELECT 1
                        FROM app_security.user_roles ur
                        JOIN app_security.roles r
                          ON r.role_id = ur.role_id
                        WHERE ur.user_id = u.user_id
                          AND r.is_active
                          AND r.role_name = 'ADMIN'
                    )
                FROM app_security.users u
                WHERE u.user_id = %s
                  AND u.is_active
                """,
                (user_id,),
            )

            access_state = cur.fetchone()

            if not access_state:
                return False

            access_configured, is_admin = access_state

            if permission == "can_view" and access_configured and not is_admin:
                cur.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1
                        FROM app_security.user_menu_access a
                        JOIN app_security.menus m
                          ON m.menu_id = a.menu_id
                         AND m.is_active
                        WHERE a.user_id = %s
                          AND m.menu_code = %s
                    )
                    """,
                    (
                        user_id,
                        menu_code,
                    ),
                )

                return cur.fetchone()[0]

            if (
                permission != "can_view"
                and access_configured
                and not is_admin
            ):
                query = f"""
                    SELECT EXISTS (
                        SELECT 1
                        FROM app_security.user_menu_access a
                        JOIN app_security.menus m
                          ON m.menu_id = a.menu_id
                         AND m.is_active
                        JOIN app_security.role_menu_permissions p
                          ON p.menu_id = m.menu_id
                        JOIN app_security.user_roles ur
                          ON ur.role_id = p.role_id
                         AND ur.user_id = a.user_id
                        JOIN app_security.roles r
                          ON r.role_id = ur.role_id
                         AND r.is_active
                        WHERE a.user_id = %s
                          AND m.menu_code = %s
                          AND p.{permission}
                    )
                """

                cur.execute(
                    query,
                    (
                        user_id,
                        menu_code,
                    ),
                )

                return cur.fetchone()[0]

            query = f"""
                SELECT EXISTS (
                    SELECT 1
                    FROM app_security.user_roles ur
                    JOIN app_security.role_menu_permissions p
                      ON p.role_id = ur.role_id
                     AND p.{permission}
                    JOIN app_security.menus m
                      ON m.menu_id = p.menu_id
                     AND m.is_active
                    WHERE ur.user_id = %s
                      AND m.menu_code = %s
                )
            """

            cur.execute(
                query,
                (
                    user_id,
                    menu_code,
                ),
            )

            return cur.fetchone()[0]


def list_menus():
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    menu_id,
                    parent_menu_id,
                    menu_name,
                    menu_code,
                    menu_type,
                    route_path,
                    external_url,
                    icon,
                    display_order,
                    is_active,
                    open_in_new_tab
                FROM app_security.menus
                ORDER BY COALESCE(parent_menu_id, 0),
                         display_order,
                         menu_name
                """
            )

            columns = [
                item.name
                for item in cur.description
            ]

            return [
                dict(zip(columns, row))
                for row in cur.fetchall()
            ]


def save_menu(data, menu_id=None):
    menu_type = str(
        data.get("menu_type", "INTERNAL")
    ).upper()

    if menu_type not in {
        "INTERNAL",
        "EXTERNAL",
        "GROUP",
    }:
        raise ValueError(
            "Menu type must be INTERNAL, EXTERNAL, or GROUP."
        )

    if menu_type == "INTERNAL" and not data.get("route_path"):
        raise ValueError(
            "Internal menus require a route path."
        )

    if menu_type == "EXTERNAL" and not data.get("external_url"):
        raise ValueError(
            "External menus require an external URL."
        )

    external_url = str(data.get("external_url") or "").strip() or None
    if external_url:
        parsed_external_url = urlparse(external_url)
        if (
            parsed_external_url.scheme not in {"http", "https"}
            or not parsed_external_url.hostname
            or parsed_external_url.username
            or parsed_external_url.password
        ):
            raise ValueError("External menu URLs must use HTTP or HTTPS.")

    parent_value = data.get("parent_menu_id")
    try:
        parent_menu_id = int(parent_value) if parent_value not in (None, "") else None
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose a valid parent menu.") from exc
    if parent_menu_id is not None and parent_menu_id == menu_id:
        raise ValueError("A menu cannot be its own parent.")

    values = (
        parent_menu_id,
        data["menu_name"].strip(),
        data["menu_code"].strip().upper(),
        menu_type,
        data.get("route_path") or None,
        external_url,
        data.get("icon") or "menu",
        int(data.get("display_order", 0)),
        bool(data.get("is_active", True)),
        bool(data.get("open_in_new_tab", False)),
    )

    with security_connection() as conn:
        with conn.cursor() as cur:
            if parent_menu_id is not None:
                parent_query = """SELECT 1 FROM app_security.menus
                                  WHERE menu_id = %s AND is_active
                                    AND menu_type = 'GROUP'"""
                if menu_type == "GROUP":
                    parent_query += " AND parent_menu_id IS NULL"
                cur.execute(parent_query, (parent_menu_id,))
                if not cur.fetchone():
                    raise ValueError("Choose an active main menu or submenu as the parent.")

            if menu_id:
                cur.execute(
                    """
                    UPDATE app_security.menus
                    SET parent_menu_id = %s,
                        menu_name = %s,
                        menu_code = %s,
                        menu_type = %s,
                        route_path = %s,
                        external_url = %s,
                        icon = %s,
                        display_order = %s,
                        is_active = %s,
                        open_in_new_tab = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE menu_id = %s
                    RETURNING menu_id
                    """,
                    (
                        *values,
                        menu_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO app_security.menus
                        (
                            parent_menu_id,
                            menu_name,
                            menu_code,
                            menu_type,
                            route_path,
                            external_url,
                            icon,
                            display_order,
                            is_active,
                            open_in_new_tab
                        )
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING menu_id
                    """,
                    values,
                )

            result = cur.fetchone()[0]

        conn.commit()

    return result


def delete_menu(menu_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM app_security.menus
                WHERE menu_id = %s
                """,
                (menu_id,),
            )

        conn.commit()


def list_users(limit=50, offset=0, user_id=None):
    limit = max(1, min(int(limit), 101))
    offset = max(0, int(offset))

    with security_connection() as conn:
        with conn.cursor() as cur:
            return _fetch_users(cur, limit, offset, user_id)


def _fetch_users(cursor, limit, offset, user_id=None):
    cursor.execute(
        """
        SELECT *
        FROM app_security.fn_get_users(%s, %s, %s)
        """,
        (limit, offset, user_id),
    )

    columns = [column.name for column in cursor.description]
    users = [dict(zip(columns, row)) for row in cursor.fetchall()]
    for user in users:
        user["module_ids"] = _normalize_module_ids(user.get("module_ids"))
    return users


def _fetch_searched_users(cursor, limit, offset, search):
    escaped_search = (
        search.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    )
    pattern = f"%{escaped_search}%"
    cursor.execute(
        """SELECT COUNT(*)
           FROM app_security.users
           WHERE username ILIKE %s ESCAPE '!'
              OR COALESCE(full_name, '') ILIKE %s ESCAPE '!'
              OR COALESCE(email, '') ILIKE %s ESCAPE '!'""",
        (pattern, pattern, pattern),
    )
    total = cursor.fetchone()[0]
    cursor.execute(
        """WITH page_users AS (
               SELECT u.user_id, u.username, u.email, u.full_name, u.is_active,
                      u.is_admin, u.created_at, u.last_login_at,
                      u.module_access_configured
               FROM app_security.users AS u
               WHERE u.username ILIKE %s ESCAPE '!'
                  OR COALESCE(u.full_name, '') ILIKE %s ESCAPE '!'
                  OR COALESCE(u.email, '') ILIKE %s ESCAPE '!'
               ORDER BY LOWER(u.username), u.user_id
               LIMIT %s OFFSET %s
           )
           SELECT u.user_id, u.username, u.email, u.full_name, u.is_active,
                  u.is_admin, u.created_at, u.last_login_at,
                  COALESCE(role_data.roles, ''),
                  CASE WHEN u.module_access_configured
                       THEN COALESCE(assigned_modules.module_names, '')
                       ELSE COALESCE(inherited_modules.module_names, '') END,
                  CASE WHEN u.module_access_configured
                       THEN COALESCE(assigned_modules.module_ids, '')
                       ELSE COALESCE(inherited_modules.module_ids, '') END
           FROM page_users AS u
           LEFT JOIN LATERAL (
               SELECT string_agg(r.role_name, ', ') AS roles
               FROM app_security.user_roles AS ur
               JOIN app_security.roles AS r ON r.role_id = ur.role_id
               WHERE ur.user_id = u.user_id
           ) AS role_data ON TRUE
           LEFT JOIN LATERAL (
                             SELECT string_agg(assigned.module_name, ', ') AS module_names,
                                            string_agg(assigned.module_id::STRING, ',') AS module_ids
                             FROM (
                                     SELECT m.module_id, m.module_name
                                     FROM app_security.user_module_access AS a
                                     JOIN app_security.modules AS m ON m.module_id = a.module_id AND m.is_active
                                     WHERE a.user_id = u.user_id
                                     ORDER BY m.module_name, m.module_id
                             ) AS assigned
           ) AS assigned_modules ON TRUE
           LEFT JOIN LATERAL (
                             SELECT string_agg(inherited.module_name, ', ') AS module_names,
                                            string_agg(inherited.module_id::STRING, ',') AS module_ids
                             FROM (
                                     SELECT DISTINCT m.module_id, m.module_name
                                     FROM app_security.user_roles AS ur
                                     JOIN app_security.roles AS r ON r.role_id = ur.role_id AND r.is_active
                                     JOIN app_security.role_module_permissions AS p
                                         ON p.role_id = r.role_id AND p.can_view
                                     JOIN app_security.modules AS m ON m.module_id = p.module_id AND m.is_active
                                     WHERE ur.user_id = u.user_id
                             ) AS inherited
           ) AS inherited_modules ON TRUE
           ORDER BY LOWER(u.username), u.user_id""",
        (pattern, pattern, pattern, limit, offset),
    )
    columns = [column.name for column in cursor.description]
    users = [dict(zip(columns, row)) for row in cursor.fetchall()]
    for user in users:
        user["module_ids"] = _normalize_module_ids(user.get("module_ids"))
    return users, total


def _normalize_module_ids(value):
    if value is None:
        return []
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("{") and value.endswith("}"):
            value = value[1:-1]
        values = value.split(",") if value else []
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        raise TypeError("Database returned an unsupported module ID value.")

    return [int(module_id) for module_id in values if str(module_id).strip()]


def _parse_user_boolean(value, field_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    raise ValueError(f"{field_name} must be true or false.")


def validate_password(password):
    if not isinstance(password, str):
        raise ValueError("Password must be text.")
    if len(password or "") < 8:
        raise ValueError(
            "Password must be at least 8 characters long."
        )


def _validated_user_text(data, field, label, max_length, required=False):
    value = data.get(field, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text.")

    value = value.strip()
    if required and not value:
        raise ValueError(f"{label} is required.")
    if len(value) > max_length:
        raise ValueError(f"{label} must be {max_length} characters or fewer.")
    return value


def _validated_role_id(value, required=False):
    if value in (None, "") and not required:
        return None
    if isinstance(value, bool):
        raise ValueError("A valid role is required.")
    try:
        role_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("A valid role is required.") from exc
    if role_id < 1:
        raise ValueError("A valid role is required.")
    return role_id


def _validated_email(data):
    email = _validated_user_text(data, "email", "Email", 255)
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    return email or None


def _save_user_modules(cursor, user_id, module_ids):
    normalized = sorted(
        {
            int(module_id)
            for module_id in (module_ids or [])
            if str(module_id).strip()
        }
    )

    if normalized:
        cursor.execute(
            """
                        SELECT module_id
                        FROM app_security.modules
                        WHERE is_active AND module_id = ANY(%s)
            """,
            (normalized,),
        )

        valid = {
            row[0]
            for row in cursor.fetchall()
        }

        if valid != set(normalized):
            raise ValueError(
                "One or more selected modules are invalid."
            )

    cursor.execute(
        """
        DELETE FROM app_security.user_module_access
        WHERE user_id = %s
        """,
        (user_id,),
    )

    for module_id in normalized:
        cursor.execute(
            """INSERT INTO app_security.user_module_access (user_id, module_id)
               VALUES (%s, %s)""",
            (user_id, module_id),
        )

    cursor.execute(
        """
        UPDATE app_security.users
        SET module_access_configured = TRUE
        WHERE user_id = %s
        """,
        (user_id,),
    )


def create_user(data):
    password = data.get("password", "")
    username = _validated_user_text(data, "username", "Username", 100, required=True)
    email = _validated_email(data)
    full_name = _validated_user_text(data, "full_name", "Full name", 150) or username
    is_active = _parse_user_boolean(
        data.get("is_active", True), "is_active"
    )

    if not password:
        raise ValueError(
            "Username and password are required."
        )

    if password != data.get("confirm_password"):
        raise ValueError(
            "Passwords do not match."
        )

    validate_password(password)

    role_id = _validated_role_id(data.get("role_id"), required=True)

    if not role_id:
        raise ValueError(
            "A role is required."
        )

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT role_name
                FROM app_security.roles
                WHERE role_id = %s
                  AND is_active
                """,
                (role_id,),
            )

            role = cur.fetchone()

            if not role:
                raise ValueError(
                    "The selected role is inactive or unavailable."
                )

            is_admin = role[0] == "ADMIN"

            cur.execute(
                """
                INSERT INTO app_security.users
                    (
                        username,
                        email,
                        full_name,
                        password_hash,
                        is_active,
                        module_access_configured,
                        is_admin
                    )
                VALUES
                    (%s, %s, %s, %s, %s, TRUE, %s)
                RETURNING user_id
                """,
                (
                    username,
                    email,
                    full_name,
                    password_hash(password),
                    is_active,
                    is_admin,
                ),
            )

            user_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO app_security.user_roles
                    (user_id, role_id)
                VALUES (%s, %s)
                """,
                (
                    user_id,
                    role_id,
                ),
            )

            _save_user_modules(
                cur,
                user_id,
                data.get("module_ids", []),
            )

            _audit(
                cur,
                data.get("actor_id"),
                "USER_CREATED",
                user_id,
                {"role_id": int(role_id)},
            )

            _audit(
                cur,
                data.get("actor_id"),
                "MODULE_ACCESS_CHANGED",
                user_id,
                {
                    "module_ids": [
                        int(module)
                        for module in data.get(
                            "module_ids",
                            [],
                        )
                    ]
                },
            )

        conn.commit()

    return user_id


def update_user(user_id, data):
    username = _validated_user_text(data, "username", "Username", 100, required=True)
    email = _validated_email(data)
    full_name = _validated_user_text(data, "full_name", "Full name", 150) or username
    role_id = _validated_role_id(data.get("role_id"))

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM app_security.users u
                    WHERE u.user_id = %s
                      AND (
                          u.is_admin
                          OR EXISTS (
                              SELECT 1
                              FROM app_security.user_roles ur
                              JOIN app_security.roles r
                                ON r.role_id = ur.role_id
                              WHERE ur.user_id = u.user_id
                                AND r.role_name = 'ADMIN'
                                AND r.is_active
                          )
                      )
                ),
                (
                    SELECT is_active
                    FROM app_security.users
                    WHERE user_id = %s
                )
                """,
                (
                    user_id,
                    user_id,
                ),
            )

            was_admin, was_active = cur.fetchone()

            if role_id:
                cur.execute(
                    """
                    SELECT role_name
                    FROM app_security.roles
                    WHERE role_id = %s
                      AND is_active
                    """,
                    (role_id,),
                )

                selected_role = cur.fetchone()

                if not selected_role:
                    raise ValueError(
                        "The selected role is inactive or unavailable."
                    )

                remains_admin = (
                    selected_role[0] == "ADMIN"
                )
            else:
                remains_admin = was_admin

            will_be_admin = (
                remains_admin
                if role_id
                else bool(was_admin)
            )

            will_be_active = _parse_user_boolean(
                data.get("is_active", True), "is_active"
            )

            if "password" in data and data["password"]:
                raise ValueError(
                    "Use the password reset flow to change a user's password."
                )

            if (
                was_admin
                and was_active
                and (
                    not remains_admin
                    or not will_be_active
                )
            ):
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM app_security.users u
                    WHERE u.is_active
                      AND (
                          u.is_admin
                          OR EXISTS (
                              SELECT 1
                              FROM app_security.user_roles ur
                              JOIN app_security.roles r
                                ON r.role_id = ur.role_id
                              WHERE ur.user_id = u.user_id
                                AND r.is_active
                                AND r.role_name = 'ADMIN'
                          )
                      )
                    """
                )

                if cur.fetchone()[0] <= 1:
                    raise ValueError(
                        "The last active Admin cannot be deactivated or demoted."
                    )

            cur.execute(
                """
                UPDATE app_security.users
                SET username = %s,
                    email = %s,
                    full_name = %s,
                    is_active = %s,
                    updated_at = CURRENT_TIMESTAMP,
                    is_admin =
                        CASE
                            WHEN %s THEN %s
                            ELSE is_admin
                        END,
                    module_access_configured =
                        CASE
                            WHEN %s THEN TRUE
                            ELSE module_access_configured
                        END,
                    session_version =
                        session_version +
                        CASE
                            WHEN is_active <> %s THEN 1
                            ELSE 0
                        END
                WHERE user_id = %s
                """,
                (
                    username,
                    email,
                    full_name,
                    will_be_active,
                    bool(role_id),
                    will_be_admin,
                    "module_ids" in data,
                    will_be_active,
                    user_id,
                ),
            )

            if cur.rowcount != 1:
                raise UserNotFoundError("User was not found.")

            if role_id:
                cur.execute(
                    """
                    SELECT role_id
                    FROM app_security.user_roles
                    WHERE user_id = %s
                    """,
                    (user_id,),
                )

                previous_roles = [
                    row[0]
                    for row in cur.fetchall()
                ]

                cur.execute(
                    """
                    DELETE FROM app_security.user_roles
                    WHERE user_id = %s
                    """,
                    (user_id,),
                )

                cur.execute(
                    """
                    INSERT INTO app_security.user_roles
                        (user_id, role_id)
                    VALUES (%s, %s)
                    """,
                    (
                        user_id,
                        role_id,
                    ),
                )

                if int(role_id) not in previous_roles:
                    _audit(
                        cur,
                        data.get("actor_id"),
                        "ROLE_CHANGED",
                        user_id,
                        {"role_id": int(role_id)},
                    )

            if "module_ids" in data:
                _save_user_modules(
                    cur,
                    user_id,
                    data["module_ids"],
                )

                _audit(
                    cur,
                    data.get("actor_id"),
                    "MODULE_ACCESS_CHANGED",
                    user_id,
                    {
                        "module_ids": [
                            int(module)
                            for module in data["module_ids"]
                        ]
                    },
                )

            _audit(
                cur,
                data.get("actor_id"),
                "USER_UPDATED",
                user_id,
                {
                    "is_active": will_be_active
                },
            )

            if was_active != will_be_active:
                _audit(
                    cur,
                    data.get("actor_id"),
                    (
                        "USER_ACTIVATED"
                        if will_be_active
                        else "USER_DEACTIVATED"
                    ),
                    user_id,
                )

        conn.commit()


def _fetch_roles(cursor):
    cursor.execute(
        """
        SELECT role_id, role_name, role_description, is_active
        FROM app_security.roles
        ORDER BY role_name
        """
    )

    columns = ("role_id", "role_name", "role_description", "is_active")
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def list_roles():
    with security_connection() as conn:
        with conn.cursor() as cur:
            return _fetch_roles(cur)


def list_user_management_data(limit=26, offset=0):
    bounded_limit = max(1, min(int(limit), 101))
    bounded_offset = max(0, int(offset))

    with security_connection() as conn:
        with conn.cursor() as cur:
            return (
                _fetch_users(cur, bounded_limit, bounded_offset),
                _fetch_roles(cur),
                _fetch_modules(cur),
            )


def list_user_management_page(limit=11, offset=0, search=""):
    search = str(search or "").strip()
    if len(search) > 100:
        raise ValueError("Search must be 100 characters or fewer.")
    bounded_limit = max(1, min(int(limit), 101))
    bounded_offset = max(0, int(offset))

    with security_connection() as conn:
        with conn.cursor() as cur:
            if search:
                users, total = _fetch_searched_users(
                    cur, bounded_limit, bounded_offset, search
                )
            else:
                users = _fetch_users(cur, bounded_limit, bounded_offset)
                cur.execute("SELECT COUNT(*) FROM app_security.users")
                total = cur.fetchone()[0]
            return users, _fetch_roles(cur), _fetch_modules(cur), total


def _get_user_management_record(user_id):
    user = next(iter(list_users(limit=1, user_id=user_id)), None)
    if user is None:
        return None

    role_names = [name.strip() for name in (user.get("roles") or "").split(",") if name.strip()]
    if user.get("is_admin") and "ADMIN" not in role_names:
        role_names.append("ADMIN")
    roles = list_roles()
    selected_role = next(
        (role for role in roles if role["role_name"] in role_names), None
    )
    modules_by_id = {module["module_id"]: module for module in list_modules()}
    assigned_modules = []
    for module_id in user.get("module_ids", []):
        module = modules_by_id.get(module_id)
        if module is None:
            continue
        assigned_modules.append(
            {
                "name": module["module_name"],
                "parent_name": module.get("submenu_name"),
                "main_menu_name": module.get("parent_menu_name"),
            }
        )

    return {
        "username": user["username"],
        "full_name": user.get("full_name"),
        "email": user.get("email"),
        "is_active": user["is_active"],
        "roles": role_names,
        "role_id": str(selected_role["role_id"]) if selected_role else None,
        "module_ids": [str(module_id) for module_id in user.get("module_ids", [])],
        "modules": assigned_modules,
    }


def get_user_management_detail(user_id):
    record = _get_user_management_record(user_id)
    if record is None:
        return None
    return {
        key: record[key]
        for key in ("username", "full_name", "email", "is_active", "roles", "modules")
    }


def get_user_management_edit_data(user_id):
    record = _get_user_management_record(user_id)
    if record is None:
        return None
    return {
        key: record[key]
        for key in (
            "username", "full_name", "email", "is_active", "role_id", "module_ids"
        )
    }


def get_profile(user_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT u.username, u.full_name, u.email,
                          p.mobile_number, p.avatar_key
                   FROM app_security.users AS u
                   LEFT JOIN app_security.user_profiles AS p
                     ON p.user_id = u.user_id
                   WHERE u.user_id = %s""",
                (user_id,),
            )
            row = cur.fetchone()

    if row is None:
        return None
    return dict(zip(("username", "full_name", "email", "mobile_number", "avatar_key"), row))


def update_profile(user_id, data, avatar_key=None):
    full_name = _validated_user_text(data, "full_name", "Full name", 150)
    email = _validated_email(data)
    mobile = _validated_user_text(data, "mobile_number", "Mobile number", 32)
    if mobile and not re.fullmatch(r"[+0-9() .-]{5,32}", mobile):
        raise ValueError("Mobile number contains unsupported characters.")
    if avatar_key is not None and not re.fullmatch(r"[a-f0-9]{40}\.webp", avatar_key):
        raise ValueError("Profile image reference is invalid.")

    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE app_security.users
                   SET full_name = %s, email = %s, updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = %s""",
                (full_name or None, email, user_id),
            )
            if cur.rowcount != 1:
                raise UserNotFoundError("User was not found.")

            if avatar_key is None:
                cur.execute(
                    """INSERT INTO app_security.user_profiles (user_id, mobile_number)
                       VALUES (%s, %s)
                       ON CONFLICT (user_id) DO UPDATE SET
                           mobile_number = EXCLUDED.mobile_number,
                           updated_at = CURRENT_TIMESTAMP""",
                    (user_id, mobile or None),
                )
            else:
                cur.execute(
                    """INSERT INTO app_security.user_profiles
                           (user_id, mobile_number, avatar_key)
                       VALUES (%s, %s, %s)
                       ON CONFLICT (user_id) DO UPDATE SET
                           mobile_number = EXCLUDED.mobile_number,
                           avatar_key = EXCLUDED.avatar_key,
                           updated_at = CURRENT_TIMESTAMP""",
                    (user_id, mobile or None, avatar_key),
                )
        conn.commit()

    return {
        "username": str(data.get("username", "")),
        "full_name": full_name or None,
        "email": email,
        "mobile_number": mobile or None,
        "avatar_key": avatar_key,
    }


def list_role_permissions(role_id):
    with security_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    m.menu_id,
                    m.menu_name,
                    m.menu_code,
                    COALESCE(p.can_view, FALSE),
                    COALESCE(p.can_create, FALSE),
                    COALESCE(p.can_edit, FALSE),
                    COALESCE(p.can_delete, FALSE),
                    COALESCE(p.can_execute, FALSE)
                FROM app_security.menus m
                LEFT JOIN app_security.role_menu_permissions p
                  ON p.menu_id = m.menu_id
                 AND p.role_id = %s
                WHERE m.is_active
                ORDER BY COALESCE(m.parent_menu_id, 0),
                         m.display_order,
                         m.menu_name
                """,
                (role_id,),
            )

            columns = (
                "menu_id",
                "menu_name",
                "menu_code",
                "can_view",
                "can_create",
                "can_edit",
                "can_delete",
                "can_execute",
            )

            return [
                dict(zip(columns, row))
                for row in cur.fetchall()
            ]


def save_role(
    data,
    role_id=None,
    actor_id=None,
):
    role_name = data["role_name"].strip().upper()
    is_active = bool(
        data.get("is_active", True)
    )

    if role_name == "ADMIN" and not is_active:
        raise ValueError(
            "The ADMIN role cannot be deactivated."
        )

    with security_connection() as conn:
        with conn.cursor() as cur:
            if role_id:
                cur.execute(
                    """
                    UPDATE app_security.roles
                    SET role_name = %s,
                        role_description = %s,
                        is_active = %s
                    WHERE role_id = %s
                    """,
                    (
                        role_name,
                        data.get("role_description"),
                        is_active,
                        role_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO app_security.roles
                        (
                            role_name,
                            role_description,
                            is_active
                        )
                    VALUES (%s, %s, %s)
                    """,
                    (
                        role_name,
                        data.get("role_description"),
                        is_active,
                    ),
                )

            _audit(
                cur,
                actor_id,
                "ROLE_UPDATED"
                if role_id
                else "ROLE_CREATED",
                details={
                    "role_name": role_name
                },
            )

        conn.commit()


def save_permissions(
    role_id,
    permissions,
    actor_id=None,
):
    with security_connection() as conn:
        with conn.cursor() as cur:
            for item in permissions:
                cur.execute(
                    """
                    INSERT INTO app_security.role_menu_permissions
                        (
                            role_id,
                            menu_id,
                            can_view,
                            can_create,
                            can_edit,
                            can_delete,
                            can_execute
                        )
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (role_id, menu_id)
                    DO UPDATE SET
                        can_view = EXCLUDED.can_view,
                        can_create = EXCLUDED.can_create,
                        can_edit = EXCLUDED.can_edit,
                        can_delete = EXCLUDED.can_delete,
                        can_execute = EXCLUDED.can_execute
                    """,
                    (
                        role_id,
                        item["menu_id"],
                        bool(item.get("can_view")),
                        bool(item.get("can_create")),
                        bool(item.get("can_edit")),
                        bool(item.get("can_delete")),
                        bool(item.get("can_execute")),
                    ),
                )

            _audit(
                cur,
                actor_id,
                "ROLE_PERMISSIONS_CHANGED",
                details={
                    "role_id": role_id,
                    "module_count": len(permissions),
                },
            )

        conn.commit()


def _request_ip():
    from flask import request

    return request.headers.get(
        "X-Forwarded-For",
        request.remote_addr,
    )


def _request_agent():
    from flask import request

    return request.headers.get(
        "User-Agent",
        "",
    )


def password_hash(password):
    return generate_password_hash(password)