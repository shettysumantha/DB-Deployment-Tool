import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for

from config import DEBUG, EXPECTED_FUNCTIONS, EXPECTED_TABLES, HOST, PORT, SECRET_KEY, SESSION_TIMEOUT_MINUTES, TABLE_NAME_PATTERN
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
from services.security_service import authenticate, create_user, delete_menu, has_permission, list_menus, list_roles, list_users, logout, record_failed_login, save_menu, save_permissions, save_role, user_menus

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "generated_scripts"
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=2 * 1024 * 1024)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES))
vault = {}
app.extensions["credential_vault"] = vault


@app.errorhandler(403)
def forbidden(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Access denied."}), 403
    return render_template("error.html", code=403, title="Access Denied", message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, title="Page Not Found", message="The requested page could not be found."), 404


@app.before_request
def enforce_login():
    if request.endpoint in {"login", "health", "static"} or request.path.startswith("/static/"):
        return None
    if not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login", next=request.full_path))
    session.permanent = True
    return None


@app.context_processor
def security_context():
    return {"sidebar_menus": user_menus(session["user_id"]) if session.get("user_id") else []}


@app.get("/login")
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/login")
def login_submit():
    identifier = (request.form.get("identifier") or "").strip()
    password = request.form.get("password") or ""
    try:
        user = authenticate(identifier, password)
    except Exception as exc:
        return render_template("login.html", error=str(exc)), 503
    if not user:
        record_failed_login(identifier)
        return render_template("login.html", error="Invalid username or password."), 401
    session.clear()
    session.permanent = True
    session.update({"user_id": user["user_id"], "username": user["username"], "full_name": user["full_name"], "roles": user["roles"]})
    next_path = request.form.get("next", "")
    return redirect(next_path if next_path.startswith("/") and not next_path.startswith("//") else url_for("index"))


@app.post("/logout")
def logout_route():
    if session.get("user_id"):
        try:
            logout(session["user_id"], session.get("username", ""))
        except Exception:
            pass
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


def require_permission(menu_code, permission="can_view"):
    if not has_permission(session["user_id"], menu_code, permission):
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
    return jsonify({"users": list_users()})


@app.post("/api/admin/users")
def admin_user_create():
    require_permission("USER_MANAGEMENT", "can_create")
    try:
        return jsonify({"user_id": create_user(request.get_json(silent=True) or {})}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/admin/roles")
def admin_roles():
    require_permission("ROLE_MANAGEMENT")
    return jsonify({"roles": list_roles()})


@app.post("/api/admin/roles")
def admin_role_create():
    require_permission("ROLE_MANAGEMENT", "can_create")
    try:
        save_role(request.get_json(silent=True) or {})
        return jsonify({"success": True}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/admin/permissions")
def admin_permissions():
    require_permission("ROLE_PERMISSIONS")
    return jsonify({"roles": list_roles(), "menus": list_menus()})


@app.post("/api/admin/permissions/<int:role_id>")
def admin_permissions_save(role_id):
    require_permission("ROLE_PERMISSIONS", "can_edit")
    save_permissions(role_id, request.get_json(silent=True) or [])
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


@app.get("/")
def index():
    return render_template("index.html")


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
        return connection_config(get_database(payload["database_id"]), payload.get("password"))
    return clean_config(payload)


def _connect(role):
    payload = request.get_json(silent=True) or {}
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
    return jsonify({"databases": list_databases()})


@app.get("/databases/<int:database_id>")
@app.get("/api/databases/<int:database_id>")
def database_detail(database_id):
    try:
        return jsonify(get_database(database_id))
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 404


@app.post("/databases/test-connection")
@app.post("/api/databases/test-connection")
def test_saved_database():
    try:
        payload = request.get_json(silent=True) or {}
        if payload.get("databaseId", payload.get("database_id")):
            record = get_database(payload.get("databaseId", payload.get("database_id")))
            config = connection_config(record, payload.get("password"))
        else:
            config = clean_config(payload)
        details = test_connection(config)
        return jsonify({"success": True, **details})
    except Exception as exc:
        return jsonify({"error": safe_error(exc, (request.get_json(silent=True) or {}).get("password", ""))}), 400


@app.post("/databases")
@app.post("/api/databases")
def add_database():
    payload = request.get_json(silent=True) or {}
    try:
        config = clean_config(payload)
        test_connection(config)
        record = save_database(payload.get("database_alias"), config)
        return jsonify({"database": record}), 201
    except Exception as exc:
        return jsonify({"error": safe_error(exc, payload.get("password", ""))}), 400


@app.put("/databases/<int:database_id>")
@app.put("/api/databases/<int:database_id>")
def edit_database(database_id):
    payload = request.get_json(silent=True) or {}
    try:
        config = clean_config(payload)
        test_connection(config)
        record = update_database(database_id, payload.get("database_alias"), config)
        return jsonify({"database": record})
    except Exception as exc:
        return jsonify({"error": safe_error(exc, payload.get("password", ""))}), 400


@app.post("/api/compare")
def compare():
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
    return jsonify({"results": [public_result(item) for item in vault_for_session().get("results", [])]})


@app.get("/api/function/<path:key>/diff")
def function_diff(key):
    item = next((item for item in vault_for_session().get("results", []) if item["key"] == key), None)
    if not item:
        return jsonify({"error": "Function was not found in the comparison."}), 404
    return jsonify(public_result(item))


@app.post("/api/tables/compare")
def compare_table_route():
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
    return jsonify({"results": [public_table_result(item) for item in vault_for_session().get("table_results", [])]})


@app.get("/api/tables/catalog")
def table_catalog():
    try:
        query = request.args.get("q", "").strip()
        return jsonify({"tables": fetch_table_names(require_role("td"), TABLE_NAME_PATTERN, query)})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/table/<path:key>/diff")
def table_diff(key):
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
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
