import os
import hmac
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for

from config import ADMIN_BOOTSTRAP_PASSKEY, DEBUG, EXPECTED_FUNCTIONS, EXPECTED_TABLES, HOST, PG_DEFAULTS, PORT, SECRET_KEY, SESSION_TIMEOUT_MINUTES, TABLE_NAME_PATTERN
from services.comparison_service import compare_functions
from services.db_service import clean_config, safe_error, test_connection
from services.deployment_service import deploy_records
from services.function_service import parse_expected
from services.table_service import _signature as table_signature, compare_tables, fetch_selected as fetch_tables, fetch_table_names, parse_expected as parse_table_names
from services.table_deployment_service import deploy_tables, generate_table_script
from services.backup_service import create_backup, safe_backup_path
from services.registry_service import application_database_configured, ensure_registry, insert_backup, search_backups, update_status
from services.sql_generator import generate_script
from services.credential_service import connection_config, get_database, list_databases, save_database, update_database
from services.notification_service import send_deployment_notification
from services.security_service import admin_exists, audit_event, authenticate, change_password, complete_password_reset, create_bootstrap_admin, create_user, delete_menu, has_permission, initialize_security, list_menus, list_modules, list_role_permissions, list_roles, list_users, logout, record_failed_login, request_password_reset, save_menu, save_permissions, save_role, update_user, user_has_role, user_menus, user_roles, user_session_state

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "generated_scripts"
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=2 * 1024 * 1024)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
)
vault = {}
app.extensions["credential_vault"] = vault
_bootstrap_failures = {}
_bootstrap_failures_lock = threading.Lock()
_security_init_failure_logged = False


def ensure_security_initialized():
    global _security_init_failure_logged
    try:
        initialize_security()
        _security_init_failure_logged = False
        return True
    except Exception:
        if not _security_init_failure_logged:
            app.logger.exception("Application security schema initialization failed; retrying on the next request")
            _security_init_failure_logged = True
        return False


with app.app_context():
    ensure_security_initialized()


def bootstrap_rate_limited(remote_addr):
    now = time.monotonic()
    with _bootstrap_failures_lock:
        failures = [stamp for stamp in _bootstrap_failures.get(remote_addr, []) if now - stamp < 900]
        _bootstrap_failures[remote_addr] = failures
        return len(failures) >= 5


def record_bootstrap_failure(remote_addr):
    now = time.monotonic()
    with _bootstrap_failures_lock:
        failures = [stamp for stamp in _bootstrap_failures.get(remote_addr, []) if now - stamp < 900]
        failures.append(now)
        _bootstrap_failures[remote_addr] = failures


def clear_bootstrap_failures(remote_addr):
    with _bootstrap_failures_lock:
        _bootstrap_failures.pop(remote_addr, None)


@app.errorhandler(403)
def forbidden(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Access denied."}), 403
    return render_template("error.html", code=403, title="Access Denied", message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, title="Page Not Found", message="The requested page could not be found."), 404


# @app.before_request
# def enforce_login():
#     if request.endpoint in {"login", "health", "static"} or request.path.startswith("/static/"):
#         return None
#     if not session.get("user_id"):
#         if request.path.startswith("/api/"):
#             return jsonify({"error": "Authentication required."}), 401
#         return redirect(url_for("login", next=request.full_path))
#     session.permanent = True
#     return None

@app.before_request
def enforce_login():

    if request.path == "/health" or request.path.startswith("/static/"):
        return None

    ensure_security_initialized()

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400)

    if request.path in {"/login", "/admin/bootstrap", "/admin/register", "/forgot-password"} or request.path.startswith("/reset-password/"):
        return None

    if not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login", next=request.full_path))

    try:
        state = user_session_state(session["user_id"])
    except Exception:
        app.logger.exception("Session account status lookup failed")
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication service unavailable."}), 503
        return redirect(url_for("login"))
    if not state or not state["is_active"] or state["session_version"] != session.get("session_version"):
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login"))

    if state["must_change_password"] and request.endpoint not in {"profile_password", "logout_route"}:
        return redirect(url_for("profile_password"))

    session.permanent = True

@app.context_processor
def security_context():
    try:
        menus = user_menus(session["user_id"]) if session.get("user_id") else []
    except Exception:
        menus = []

    csrf_token = session.setdefault("_csrf_token", secrets.token_urlsafe(32))
    try:
        roles = user_roles(session["user_id"]) if session.get("user_id") else []
    except Exception:
        roles = []
    return {"sidebar_menus": menus, "csrf_token": csrf_token, "current_roles": roles}


@app.get("/login")
def login():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    message = "Password changed successfully. Please login." if request.args.get("changed") else None
    return render_template(
        "login.html",
        **login_page_context(
            admin_login_checked=request.args.get("admin") == "1",
            show_admin_access=request.args.get("admin") == "1",
            show_admin_registration=request.args.get("register") == "1",
        ),
        success=message,
    )


def login_page_context(
    *, admin_login_checked=False, show_admin_access=False,
    show_admin_registration=False, login_identifier="", bootstrap_values=None,
    field_errors=None, bootstrap_message=None,
):
    try:
        has_admin = admin_exists()
    except Exception:
        app.logger.exception("Admin setup status check failed")
        has_admin = False
    return {
        "admin_exists": has_admin,
        "show_admin_access": show_admin_access or admin_login_checked,
        "show_admin_registration": show_admin_registration and not has_admin,
        "admin_login_checked": admin_login_checked,
        "login_identifier": login_identifier,
        "bootstrap_values": bootstrap_values or {},
        "field_errors": field_errors or {},
        "bootstrap_message": bootstrap_message,
    }


@app.post("/login")
def login_submit():

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    admin_login = request.form.get("admin_login") == "on"

    try:
        user = authenticate(identifier, password, admin_required=admin_login)
    except Exception:
        app.logger.exception("Authentication database request failed")
        user = None

    if user and user.get("admin_access_denied"):
        record_failed_login(identifier)
        return render_template(
            "login.html",
            error="This account does not have Admin access.",
            **login_page_context(admin_login_checked=True, show_admin_access=True, login_identifier=identifier),
        ), 403

    if user:
        session.clear()
        session.permanent = True
        session.update({
            "user_id": user["user_id"],
            "username": user["username"],
            "session_version": user["session_version"],
        })
        if user["must_change_password"]:
            return redirect(url_for("profile_password"))
        if request.form.get("next", "").rstrip("?") == url_for("profile_password"):
            return redirect(url_for("profile_password"))
        return redirect(url_for("dashboard"))

    record_failed_login(identifier)

    return render_template(
        "login.html",
        error="Invalid username or password.",
        **login_page_context(admin_login_checked=admin_login, show_admin_access=admin_login, login_identifier=identifier),
    ), 401


@app.route("/admin/register", methods=["GET", "POST"], endpoint="admin_register")
@app.route("/admin/bootstrap", methods=["GET", "POST"], endpoint="admin_bootstrap")
def admin_bootstrap():
    if request.method == "GET" and request.path == "/admin/bootstrap":
        return redirect(url_for("admin_register"))

    data = request.form.to_dict() if request.method == "POST" else {}
    values = {"username": data.get("username", "").strip(), "email": data.get("email", "").strip()}

    def registration_response(message=None, field=None, status=400, *, already_exists=False, success=None):
        field_errors = {field: message} if field else {}
        return render_template(
            "admin_register.html",
            error=None if field else message,
            success=success,
            already_exists=already_exists,
            values=values,
            field_errors=field_errors,
        ), status

    try:
        admin_exists()
    except Exception:
        app.logger.exception("Admin registration database check failed for local authentication database")
        return registration_response("Unable to connect to the local authentication database.", status=503)
    if request.method == "GET":
        return render_template("admin_register.html", values={}, field_errors={})

    remote_addr = request.remote_addr or "unknown"
    if bootstrap_rate_limited(remote_addr):
        try:
            audit_event("ADMIN_BOOTSTRAP_FAILED", details={"reason": "rate_limited"})
        except Exception:
            app.logger.exception("Admin bootstrap rate-limit audit write failed")
        return registration_response("Too many failed attempts. Try again in 15 minutes.", "passkey", 429)

    passkey = data.get("passkey", "")
    if not passkey:
        record_bootstrap_failure(remote_addr)
        try:
            audit_event("ADMIN_BOOTSTRAP_FAILED", details={"reason": "missing_passkey"})
        except Exception:
            app.logger.exception("Admin bootstrap failure audit write failed")
        return registration_response("Admin passkey is required.", "passkey")
    if not ADMIN_BOOTSTRAP_PASSKEY or not hmac.compare_digest(passkey, ADMIN_BOOTSTRAP_PASSKEY):
        record_bootstrap_failure(remote_addr)
        try:
            audit_event("ADMIN_BOOTSTRAP_FAILED", details={"reason": "invalid_passkey"})
        except Exception:
            app.logger.exception("Admin bootstrap failure audit write failed")
        return registration_response("Passkey is wrong.", "passkey")

    if not values["username"]:
        return registration_response("Username is required.", "username")
    if not values["email"]:
        return registration_response("Email is required.", "email")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", values["email"]):
        return registration_response("Enter a valid email address.", "email")
    if not data.get("password"):
        return registration_response("Password is required.", "password")
    if not data.get("confirm_password"):
        return registration_response("Confirm password is required.", "confirm_password")
    if data.get("password") != data.get("confirm_password"):
        try:
            audit_event("ADMIN_BOOTSTRAP_FAILED", details={"reason": "password_mismatch"})
        except Exception:
            app.logger.exception("Admin bootstrap failure audit write failed")
        return registration_response("Passwords do not match.", "confirm_password")
    try:
        create_bootstrap_admin(data, ADMIN_BOOTSTRAP_PASSKEY)
        clear_bootstrap_failures(remote_addr)
        return render_template(
            "admin_register.html",
            success="Admin account created successfully. Please login.",
            login_url=url_for("login", admin="1"),
            values=values,
            field_errors={},
        )
    except ValueError as exc:
        message = str(exc)
        field = "username" if "Username already exists" in message else "email" if "Email already exists" in message else None
        return registration_response(message, field)
    except Exception:
        app.logger.exception("Admin registration failed")
        return registration_response("Unable to create Admin account.")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        try:
            reset = request_password_reset(identifier)
            if reset and reset["token"]:
                reset_url = url_for("reset_password", token=reset["token"], _external=True)
                if reset["email"]:
                    from services.notification_service import send_password_reset_email
                    try:
                        send_password_reset_email(reset["email"], reset_url)
                    except Exception:
                        if DEBUG:
                            app.logger.info("Development password reset URL: %s", reset_url)
                        else:
                            app.logger.exception("Password reset email delivery failed")
                elif DEBUG:
                    app.logger.info("Development password reset URL: %s", reset_url)
        except Exception:
            app.logger.exception("Password reset request failed")
        return render_template("forgot_password.html", message="If the account exists, password reset instructions have been provided.")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        password = request.form.get("password", "")
        if password != request.form.get("confirm_password", ""):
            return render_template("reset_password.html", token=token, error="Passwords do not match."), 400
        try:
            if complete_password_reset(token, password):
                return render_template("login.html", success="Password reset successfully. Please login.")
        except ValueError as exc:
            return render_template("reset_password.html", token=token, error=str(exc)), 400
        except Exception:
            app.logger.exception("Password reset completion failed")
        return render_template("reset_password.html", token=token, error="This reset link is invalid or expired."), 400
    return render_template("reset_password.html", token=token)


@app.get("/profile")
def profile():
    return render_template("profile.html")


@app.route("/profile/password", methods=["GET", "POST"])
def profile_password():
    if request.method == "POST":
        password = request.form.get("new_password", "")
        if password != request.form.get("confirm_password", ""):
            return render_template("profile.html", error="New passwords do not match."), 400
        try:
            if not change_password(session["user_id"], request.form.get("current_password", ""), password):
                return render_template("profile.html", error="Current password is incorrect."), 400
            session.clear()
            return redirect(url_for("login", changed="1"))
        except ValueError as exc:
            return render_template("profile.html", error=str(exc)), 400
        except Exception:
            app.logger.exception("Password change failed")
            return render_template("profile.html", error="Unable to change password."), 400
    return render_template("profile.html")

@app.post("/logout")
def logout_route():
    if session.get("user_id"):
        try:
            logout(session["user_id"], session.get("username", ""))
        except Exception:
            pass
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


def require_permission(menu_code, permission="can_view"):
    if menu_code in {"USER_MANAGEMENT", "ROLE_MANAGEMENT", "ROLE_PERMISSIONS", "MENU_MANAGEMENT", "DATABASE_MANAGEMENT"} and not user_has_role(session["user_id"], "ADMIN"):
        abort(403)
    if not has_permission(session["user_id"], menu_code, permission):
        abort(403)


def require_any_permission(*menu_codes, permission="can_view"):
    if not any(has_permission(session["user_id"], code, permission) for code in menu_codes):
        abort(403)


@app.get("/api/menus")
def menus_api():
    return jsonify({"success": True, "menus": user_menus(session["user_id"])})


@app.get("/admin/menus")
def admin_menus():
    require_permission("MENU_MANAGEMENT")
    return render_template("admin_menus.html", menus=list_menus())


@app.get("/api/admin/menus")
def admin_menus_api():
    require_permission("MENU_MANAGEMENT")
    return jsonify({"menus": list_menus()})


@app.post("/api/admin/menus")
def admin_menu_create():
    require_permission("MENU_MANAGEMENT", "can_create")
    try:
        return jsonify({"menu_id": save_menu(request.get_json(silent=True) or {})}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.put("/api/admin/menus/<int:menu_id>")
def admin_menu_update(menu_id):
    require_permission("MENU_MANAGEMENT", "can_edit")
    try:
        return jsonify({"menu_id": save_menu(request.get_json(silent=True) or {}, menu_id)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.delete("/api/admin/menus/<int:menu_id>")
def admin_menu_delete(menu_id):
    require_permission("MENU_MANAGEMENT", "can_delete")
    delete_menu(menu_id)
    return jsonify({"success": True})


@app.get("/admin/users")
def admin_users():
    require_permission("USER_MANAGEMENT")
    return render_template("admin_users.html", users=list_users(), roles=list_roles(), modules=list_modules())


@app.get("/api/admin/users")
def admin_users_api():
    require_permission("USER_MANAGEMENT")
    return jsonify({"users": list_users()})


@app.post("/api/admin/users")
def admin_user_create():
    require_permission("USER_MANAGEMENT", "can_create")
    try:
        data = request.get_json(silent=True) or {}
        data["actor_id"] = session["user_id"]
        return jsonify({"user_id": create_user(data)}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/admin/users/create")
def admin_user_create_form():
    require_permission("USER_MANAGEMENT", "can_create")
    try:
        data = request.form.to_dict()
        if data.get("password") != data.get("confirm_password"):
            raise ValueError("Passwords do not match.")
        data["module_ids"] = request.form.getlist("module_ids")
        data["actor_id"] = session["user_id"]
        create_user(data)
        flash("User created.", "success")
    except Exception:
        app.logger.exception("User creation failed")
        flash("Unable to create user. Check that username and email are unique.", "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/edit")
def admin_user_update_form(user_id):
    require_permission("USER_MANAGEMENT", "can_edit")
    try:
        data = request.form.to_dict()
        data["is_active"] = "is_active" in request.form
        data["module_ids"] = request.form.getlist("module_ids")
        data["actor_id"] = session["user_id"]
        update_user(user_id, data)
        flash("User updated.", "success")
    except Exception:
        app.logger.exception("User update failed")
        flash("Unable to update user. Verify the supplied user and role values.", "error")
    return redirect(url_for("admin_users"))


@app.post("/api/admin/users/<int:user_id>")
def admin_user_update_api(user_id):
    require_permission("USER_MANAGEMENT", "can_edit")
    try:
        data = request.get_json(silent=True) or {}
        data["actor_id"] = session["user_id"]
        update_user(user_id, data)
        return jsonify({"success": True})
    except Exception:
        app.logger.exception("User update failed")
        return jsonify({"error": "Unable to update user."}), 400


@app.post("/admin/users/<int:user_id>/deactivate")
def admin_user_deactivate(user_id):
    require_permission("USER_MANAGEMENT", "can_edit")
    try:
        data = request.form.to_dict()
        data["is_active"] = "is_active" in request.form
        update_user(user_id, data)
        flash("User status updated.", "success")
    except Exception:
        app.logger.exception("User status update failed")
        flash("Unable to update user status.", "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/send-password-reset")
def admin_user_password_reset(user_id):
    require_permission("USER_MANAGEMENT", "can_edit")
    try:
        user = next((item for item in list_users() if item["user_id"] == user_id), None)
        if user:
            reset = request_password_reset(user["username"])
            if reset and reset["token"]:
                reset_url = url_for("reset_password", token=reset["token"], _external=True)
                if reset["email"]:
                    from services.notification_service import send_password_reset_email
                    send_password_reset_email(reset["email"], reset_url)
                elif DEBUG:
                    app.logger.info("Development password reset URL: %s", reset_url)
        flash("If the account is active, password reset instructions have been sent.", "success")
    except Exception:
        app.logger.exception("Admin password reset request failed")
        flash("Unable to send reset instructions.", "error")
    return redirect(url_for("admin_users"))


@app.get("/admin/roles")
def admin_roles():
    require_permission("ROLE_MANAGEMENT")
    return render_template("admin_roles.html", roles=list_roles(), menus=list_menus())


@app.get("/api/admin/roles")
def admin_roles_api():
    require_permission("ROLE_MANAGEMENT")
    return jsonify({"roles": list_roles()})


@app.post("/api/admin/roles")
def admin_role_create():
    require_permission("ROLE_MANAGEMENT", "can_create")
    try:
        save_role(request.get_json(silent=True) or {}, actor_id=session["user_id"])
        return jsonify({"success": True}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/admin/roles/create")
def admin_role_create_form():
    require_permission("ROLE_MANAGEMENT", "can_create")
    try:
        save_role(request.form, actor_id=session["user_id"])
        flash("Role created.", "success")
    except Exception:
        app.logger.exception("Role creation failed")
        flash("Unable to create role. Check that the role name is unique.", "error")
    return redirect(url_for("admin_roles"))


@app.post("/admin/roles/<int:role_id>/edit")
def admin_role_update_form(role_id):
    require_permission("ROLE_MANAGEMENT", "can_edit")
    try:
        data = request.form.to_dict()
        data["is_active"] = "is_active" in request.form
        save_role(data, role_id, actor_id=session["user_id"])
        flash("Role updated.", "success")
    except Exception:
        app.logger.exception("Role update failed")
        flash("Unable to update role.", "error")
    return redirect(url_for("admin_roles"))


@app.get("/admin/databases")
def admin_databases():
    require_permission("DATABASE_MANAGEMENT")
    return render_template("admin_databases.html", databases=list_databases(), defaults=PG_DEFAULTS)


@app.post("/admin/databases/create")
def admin_database_create():
    require_permission("DATABASE_MANAGEMENT", "can_create")
    try:
        payload = request.form.to_dict()
        config = _payload_config(payload)
        test_connection(config)
        save_database(payload.get("database_alias"), config, payload.get("environment"))
        flash("Database connection saved.", "success")
    except Exception:
        app.logger.exception("Database configuration creation failed")
        flash("Unable to save the database. Verify its connection details.", "error")
    return redirect(url_for("admin_databases"))


@app.post("/admin/databases/<int:database_id>/edit")
def admin_database_update(database_id):
    require_permission("DATABASE_MANAGEMENT", "can_edit")
    try:
        payload = request.form.to_dict()
        payload.pop("database_id", None)
        config = _payload_config(payload)
        test_connection(config)
        update_database(database_id, payload.get("database_alias"), config, payload.get("environment"))
        flash("Database connection updated.", "success")
    except Exception:
        app.logger.exception("Database configuration update failed")
        flash("Unable to update the database. Verify its connection details.", "error")
    return redirect(url_for("admin_databases"))


@app.get("/admin/permissions")
def admin_permissions():
    require_permission("ROLE_PERMISSIONS")
    roles = list_roles()
    permissions = {role["role_id"]: list_role_permissions(role["role_id"]) for role in roles}
    return render_template("admin_permissions.html", roles=roles, permissions=permissions)


@app.get("/api/admin/permissions")
def admin_permissions_api():
    require_permission("ROLE_PERMISSIONS")
    roles = list_roles()
    permissions = {role["role_id"]: list_role_permissions(role["role_id"]) for role in roles}
    return jsonify({"roles": roles, "permissions": permissions})


@app.post("/api/admin/permissions/<int:role_id>")
def admin_permissions_save(role_id):
    require_permission("ROLE_PERMISSIONS", "can_edit")
    save_permissions(role_id, request.get_json(silent=True) or [], actor_id=session["user_id"])
    return jsonify({"success": True})


def vault_for_session():
    sid = session.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(24)
        session["sid"] = sid
    return vault.setdefault(sid, {"td": None, "live": None, "results": [], "table_results": [], "history": []})


def public_connection(role, status, details=None, error=None):
    response = {"role": role, "connected": status}
    if details:
        response.update(details)
    if error:
        response["error"] = error
    return response


def public_record(record):
    if not record:
        return None
    return {
        "key": record["key"],
        "name": record["name"],
        "schema": record["schema"],
        "identity_arguments": record["identity_arguments"],
        "arguments": record["arguments"],
        "result": record["result"],
        "definition": record["definition"],
    }


def public_result(item):
    return {
        "key": item["key"],
        "name": item["name"],
        "signature": item["signature"],
        "status": item["status"],
        "source": public_record(item["source"]),
        "live": public_record(item["live"]),
    }


def public_table_result(item):
    return {"key": item["key"], "name": item["name"], "schema": item["schema"],
        "status": item["status"], "changes": item["changes"], "destructive": item["destructive"],
        "source": item["source"], "live": item["live"]}


def require_role(role):
    config = vault_for_session().get(role)
    if not config:
        raise ValueError(f"Connect the {role.upper()} database first.")
    return config


@app.get("/deployment")
def index():
    require_permission("DEPLOYMENT_MANAGER")
    return render_template(
        "index.html",
        database_defaults=PG_DEFAULTS,
        can_deploy=has_permission(session["user_id"], "DEPLOYMENT_MANAGER", "can_execute"),
    )


@app.get("/comparison")
def comparison_page():
    require_permission("COMPARISON_RESULTS")
    return render_template("index.html", database_defaults=PG_DEFAULTS, can_deploy=False)


@app.get("/history")
def history_page():
    require_permission("DEPLOYMENT_HISTORY")
    return render_template("index.html", database_defaults=PG_DEFAULTS, can_deploy=False)


@app.get("/backups")
def backups_page():
    require_permission("BACKUP_REPOSITORY")
    return render_template("index.html", database_defaults=PG_DEFAULTS, can_deploy=False)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/connect-td")
def connect_td():
    return _connect("td")


@app.post("/api/test-live-connection")
def test_live_connection():
    return _connect("live")


def _payload_config(payload):
    if payload.get("database_id"):
        record = get_database(payload["database_id"])
        config = {
            "host": record["host"],
            "port": record["port"],
            "database": record["databaseName"],
            "username": record["username"],
            "sslmode": record.get("sslmode") or "require",
            "password": payload.get("password", ""),
        }
    else:
        config = dict(payload)
    matches_environment = all(
        str(config.get(field, "")).strip() == str(PG_DEFAULTS[field])
        for field in ("host", "port", "database", "username")
    )
    if not config.get("password") and matches_environment:
        config["password"] = PG_PASSWORD
    return clean_config(config)


def _connect(role):
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    payload = request.get_json(silent=True) or {}
    if not payload.get("database_id") and not has_permission(
        session["user_id"], "DEPLOYMENT_MANAGER", "can_execute"
    ):
        abort(403)
    try:
        config = _payload_config(payload)
        details = test_connection(config)
        vault_for_session()[role] = config
        if role == "live":
            ensure_registry(config)
        return jsonify(public_connection(role, True, details))
    except Exception as exc:
        return jsonify(public_connection(role, False, error=safe_error(exc, payload.get("password", "")))), 400


@app.get("/databases")
@app.get("/api/databases")
def databases():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    return jsonify({"databases": list_databases()})


@app.get("/databases/<int:database_id>")
@app.get("/api/databases/<int:database_id>")
def database_detail(database_id):
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    try:
        return jsonify(get_database(database_id))
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 404


@app.post("/databases/test-connection")
@app.post("/api/databases/test-connection")
def test_saved_database():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    payload = request.get_json(silent=True) or {}
    if payload.get("databaseId") and not payload.get("database_id"):
        payload["database_id"] = payload["databaseId"]
    if not payload.get("database_id") and not has_permission(
        session["user_id"], "DEPLOYMENT_MANAGER", "can_execute"
    ):
        abort(403)
    try:
        config = _payload_config(payload)
        details = test_connection(config)
        return jsonify({"success": True, **details})
    except Exception as exc:
        return jsonify({"error": safe_error(exc, (request.get_json(silent=True) or {}).get("password", ""))}), 400


@app.post("/databases")
@app.post("/api/databases")
def add_database():
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    payload = request.get_json(silent=True) or {}
    try:
        config = _payload_config(payload)
        test_connection(config)
        record = save_database(payload.get("database_alias"), config)
        return jsonify({"database": record}), 201
    except Exception as exc:
        return jsonify({"error": safe_error(exc, payload.get("password", ""))}), 400


@app.put("/databases/<int:database_id>")
@app.put("/api/databases/<int:database_id>")
def edit_database(database_id):
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    payload = request.get_json(silent=True) or {}
    try:
        config_payload = dict(payload)
        config_payload.pop("database_id", None)
        config = _payload_config(config_payload)
        test_connection(config)
        record = update_database(database_id, payload.get("database_alias"), config)
        return jsonify({"database": record})
    except Exception as exc:
        return jsonify({"error": safe_error(exc, payload.get("password", ""))}), 400


@app.post("/api/compare")
def compare():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    try:
        state = vault_for_session()
        td = require_role("td")
        live = require_role("live")
        payload = request.get_json(silent=True) or {}
        raw_expected = payload.get("function_search") or payload.get("expected_functions", "")
        names = sorted(set(EXPECTED_FUNCTIONS) | set(parse_expected(raw_expected)))
        state["expected_names"] = names
        state["results"] = compare_functions(td, live, names)
        return jsonify({"results": [public_result(item) for item in state["results"]], "expected_functions": names})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/functions")
def functions():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    return jsonify({"results": [public_result(item) for item in vault_for_session().get("results", [])]})


@app.get("/api/function/<path:key>/diff")
def function_diff(key):
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    item = next((item for item in vault_for_session().get("results", []) if item["key"] == key), None)
    if not item:
        return jsonify({"error": "Function was not found in the comparison."}), 404
    return jsonify(public_result(item))


@app.post("/api/tables/compare")
def compare_table_route():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    try:
        state = vault_for_session()
        payload = request.get_json(silent=True) or {}
        search = str(payload.get("table_search", "")).strip()
        names = sorted(set(EXPECTED_TABLES) | set(parse_table_names(payload.get("expected_tables", ""))))
        if search:
            names = sorted(set(names) | {search})
        state["expected_tables"] = names
        pattern = f"%{search}%" if search else TABLE_NAME_PATTERN
        state["table_results"] = compare_tables(require_role("td"), require_role("live"), names, pattern=pattern)
        return jsonify({"results": [public_table_result(item) for item in state["table_results"]], "expected_tables": names})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/tables")
def tables():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    return jsonify({"results": [public_table_result(item) for item in vault_for_session().get("table_results", [])]})


@app.get("/api/tables/catalog")
def table_catalog():
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    try:
        query = request.args.get("q", "").strip()
        return jsonify({"tables": fetch_table_names(require_role("td"), TABLE_NAME_PATTERN, query)})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/table/<path:key>/diff")
def table_diff(key):
    require_any_permission("DEPLOYMENT_MANAGER", "COMPARISON_RESULTS")
    item = next((item for item in vault_for_session().get("table_results", []) if item["key"] == key), None)
    return jsonify(public_table_result(item)) if item else (jsonify({"error": "Table was not found in the comparison."}), 404)


def selected_tables():
    requested = set((request.get_json(silent=True) or {}).get("keys", []))
    comparison = vault_for_session().get("table_results", [])
    if not comparison:
        raise ValueError("The comparison expired or is not available. Reconnect both databases and compare again.")
    items = [item for item in comparison if item["key"] in requested]
    if len(items) != len(requested) or not items: raise ValueError("Select at least one changed table from the current comparison.")
    if any(item["status"] not in ("NEW", "MODIFIED") or not item["source"] for item in items):
        raise ValueError("Only NEW and MODIFIED tables can be deployed or scripted.")
    return items


def stale_table_keys(items, current):
    stale = []
    for item in items:
        current_item = current.get(item["key"])
        if not current_item:
            current_item = next(
                (
                    record
                    for record in current.values()
                    if record.get("schema") == item.get("schema")
                    and record.get("name") == item.get("name")
                ),
                None,
            )
        if item["status"] == "NEW":
            changed = current_item is not None
        else:
            changed = (
                not item["live"]
                or not current_item
                or table_signature(item["live"]) != table_signature(current_item)
            )
        if changed:
            stale.append(item["key"])
    return stale


@app.post("/api/tables/generate-script")
def generate_tables():
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    try:
        items = selected_tables()
        path = generate_table_script(items, OUTPUT_DIR, bool((request.get_json(silent=True) or {}).get("confirm_destructive")))
        return jsonify({"success": True, "count": len(items), "filename": path.name, "download": f"/downloads/{path.name}", "destructive": any(item["destructive"] for item in items)})
    except Exception as exc: return jsonify({"error": safe_error(exc)}), 400


@app.post("/api/tables/deploy")
@app.post("/api/tables/deploy-selected")
def deploy_table_route():
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    try:
        payload = request.get_json(silent=True) or {}
        items = selected_tables()
        current = fetch_tables(require_role("live"), [item["name"] for item in items], pattern=TABLE_NAME_PATTERN)
        stale = stale_table_keys(items, current)
        if stale:
            raise ValueError("Live changed after comparison. Refresh the comparison before deploying: " + ", ".join(stale))
        if any(item["destructive"] for item in items) and not payload.get("confirm_destructive"):
            return jsonify({"error": "Destructive table changes require explicit confirmation."}), 400
        deployment_id = "DEP_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + secrets.token_hex(2).upper()
        version = (payload.get("version") or datetime.now().strftime("%Y%m%d_%H%M%S")).strip()
        result = deploy_tables(require_role("live"), items, deployment_id, version, bool(payload.get("confirm_destructive")))
        result["notification"] = send_deployment_notification(result)
        for item in items:
            vault_for_session()["history"].insert(0, {"timestamp": result["timestamp"], "key": item["key"], "name": item["name"], "status_before": item["status"], "result": "SUCCESS" if result["success"] else "FAILED", "error": result.get("error", ""), "object_type": "TABLE", "deployment_id": deployment_id, "version": version, "backup_ids": result.get("backup_ids", []), "notification": result.get("notification", {})})
        return jsonify(result), 200 if result["success"] else 400
    except Exception as exc: return jsonify({"error": safe_error(exc)}), 400


def selected_items():
    requested = set((request.get_json(silent=True) or {}).get("keys", []))
    comparison = vault_for_session().get("results", [])
    if not comparison:
        raise ValueError("The comparison expired or is not available. Reconnect both databases and compare again.")
    items = [item for item in comparison if item["key"] in requested]
    invalid = [item["key"] for item in items if item["status"] not in ("NEW", "MODIFIED") or not item["source"]]
    if invalid:
        raise ValueError("Only NEW and MODIFIED functions can be deployed or scripted.")
    if len(items) != len(requested):
        raise ValueError("One or more selected functions are not in the current comparison.")
    if not items:
        raise ValueError("Select at least one changed function.")
    return items


def stale_function_keys(items, current):
    stale = []
    for item in items:
        current_item = current.get(item["key"])
        if item["status"] == "NEW":
            changed = current_item is not None
        else:
            changed = (
                not item["live"]
                or not current_item
                or item["live"]["definition"] != current_item["definition"]
            )
        if changed:
            stale.append(item["key"])
    return stale


@app.post("/api/generate-script")
def generate():
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    try:
        items = selected_items()
        path = generate_script(items, OUTPUT_DIR)
        return jsonify({"success": True, "count": len(items), "filename": path.name,
            "download": f"/downloads/{path.name}", "sql": path.read_text(encoding="utf-8")})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.post("/api/deploy-function")
def deploy_function():
    return _deploy()


@app.post("/api/deploy-selected")
def deploy_selected():
    return _deploy()


def _deploy():
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    try:
        state = vault_for_session()
        live = require_role("live")
        items = selected_items()
        from services.function_service import fetch_matching_keys
        current = fetch_matching_keys(live, {item["key"] for item in items})
        stale = stale_function_keys(items, current)
        if stale:
            raise ValueError("Live changed after comparison. Refresh the comparison before deploying: " + ", ".join(stale))
        result = deploy_records(live, items)
        result["notification"] = send_deployment_notification(result)
        for item in items:
            state["history"].insert(0, {
                "timestamp": result["timestamp"], "key": item["key"], "name": item["name"],
                "status_before": item["status"], "result": "SUCCESS" if result["success"] else "FAILED",
                "error": result.get("error", ""), "object_type": "FUNCTION",
                "deployment_id": result.get("deployment_id", ""), "version": result.get("version", ""),
                "backup_ids": result.get("backup_ids", []), "notification": result.get("notification", {}),
            })
        if result["success"]:
            state["results"] = compare_functions(
                require_role("td"), live, state.get("expected_names", [])
            )
            result["results"] = [public_result(item) for item in state["results"]]
        return jsonify(result), 200 if result["success"] else 400
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/deployment-history")
def deployment_history():
    require_permission("DEPLOYMENT_HISTORY")
    return jsonify({"history": vault_for_session().get("history", [])[:100]})


@app.get("/api/deployments")
def deployments():
    return deployment_history()


@app.get("/api/deployments/<deployment_id>")
def deployment_detail(deployment_id):
    records = [item for item in vault_for_session().get("history", []) if item.get("deployment_id") == deployment_id]
    return jsonify({"deployment_id": deployment_id, "history": records})


@app.get("/api/backups")
@app.get("/api/backups/search")
def backups():
    require_permission("BACKUP_REPOSITORY")
    try:
        live_config = vault_for_session().get("live")
        if not live_config and not application_database_configured():
            raise ValueError("Connect the LIVE database first or configure APP_DATABASE_URL.")
        return jsonify({"backups": search_backups(live_config, request.args.to_dict())})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/backups/<int:backup_id>/view")
@app.get("/api/backups/<int:backup_id>/download")
def backup_file(backup_id):
    require_permission("BACKUP_REPOSITORY")
    try:
        live_config = vault_for_session().get("live")
        if not live_config and not application_database_configured():
            raise ValueError("Connect the LIVE database first or configure APP_DATABASE_URL.")
        records = search_backups(live_config, {"backup_id": str(backup_id)})
        if not records: return jsonify({"error": "Backup metadata was not found."}), 404
        path = safe_backup_path(records[0]["backup_file_path"])
        if not path.exists(): return jsonify({"error": "Backup file metadata exists, but the physical file was not found."}), 404
        return send_file(path, as_attachment=request.path.endswith('/download'), download_name=path.name)
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/downloads/<path:filename>")
def download(filename):
    require_permission("DEPLOYMENT_MANAGER", "can_execute")
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
