import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory, session

from config import DEBUG, EXPECTED_FUNCTIONS, EXPECTED_TABLES, HOST, PORT, SECRET_KEY, TABLE_NAME_PATTERN
from services.comparison_service import compare_functions
from services.db_service import clean_config, safe_error, test_connection
from services.deployment_service import deploy_records
from services.function_service import parse_expected
from services.table_service import _signature as table_signature, compare_tables, fetch_selected as fetch_tables, fetch_table_names, parse_expected as parse_table_names
from services.table_deployment_service import deploy_tables, generate_table_script
from services.backup_service import create_backup, safe_backup_path
from services.registry_service import ensure_registry, insert_backup, search_backups, update_status
from services.sql_generator import generate_script
from services.credential_service import connection_config, get_database, list_databases, save_database, update_database

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "generated_scripts"
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=2 * 1024 * 1024)
vault = {}
app.extensions["credential_vault"] = vault


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
        raw_expected = payload.get("expected_functions", "")
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
        names = sorted(set(EXPECTED_TABLES) | set(parse_table_names(payload.get("expected_tables", ""))))
        search = str(payload.get("table_search", "")).strip()
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
    items = [item for item in vault_for_session().get("table_results", []) if item["key"] in requested]
    if len(items) != len(requested) or not items: raise ValueError("Select at least one changed table.")
    if any(item["status"] not in ("NEW", "MODIFIED") or not item["source"] for item in items):
        raise ValueError("Only NEW and MODIFIED tables can be deployed or scripted.")
    return items


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
    try:
        payload = request.get_json(silent=True) or {}
        items = selected_tables()
        current = fetch_tables(require_role("live"), [item["name"] for item in items], pattern="")
        stale = [item["key"] for item in items if item["key"] not in current or not item["live"] or table_signature(item["live"]) != table_signature(current[item["key"]])]
        if stale:
            raise ValueError("Live changed after comparison. Refresh the comparison before deploying: " + ", ".join(stale))
        if any(item["destructive"] for item in items) and not payload.get("confirm_destructive"):
            return jsonify({"error": "Destructive table changes require explicit confirmation."}), 400
        deployment_id = "DEP_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + secrets.token_hex(2).upper()
        version = (payload.get("version") or datetime.now().strftime("%Y%m%d_%H%M%S")).strip()
        result = deploy_tables(require_role("live"), items, deployment_id, version, bool(payload.get("confirm_destructive")))
        for item in items:
            vault_for_session()["history"].insert(0, {"timestamp": result["timestamp"], "key": item["key"], "name": item["name"], "status_before": item["status"], "result": "SUCCESS" if result["success"] else "FAILED", "error": result.get("error", ""), "object_type": "TABLE", "deployment_id": deployment_id, "version": version})
        return jsonify(result), 200 if result["success"] else 400
    except Exception as exc: return jsonify({"error": safe_error(exc)}), 400


def selected_items():
    requested = set((request.get_json(silent=True) or {}).get("keys", []))
    items = [item for item in vault_for_session().get("results", []) if item["key"] in requested]
    invalid = [item["key"] for item in items if item["status"] not in ("NEW", "MODIFIED") or not item["source"]]
    if invalid:
        raise ValueError("Only NEW and MODIFIED functions can be deployed or scripted.")
    if len(items) != len(requested):
        raise ValueError("One or more selected functions are not in the current comparison.")
    if not items:
        raise ValueError("Select at least one changed function.")
    return items


@app.post("/api/generate-script")
def generate():
    try:
        items = selected_items()
        path = generate_script(items, OUTPUT_DIR)
        return jsonify({"success": True, "count": len(items), "filename": path.name, "download": f"/downloads/{path.name}"})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.post("/api/deploy-function")
def deploy_function():
    return _deploy()


@app.post("/api/deploy-selected")
def deploy_selected():
    return _deploy()


def _deploy():
    try:
        state = vault_for_session()
        live = require_role("live")
        items = selected_items()
        from services.function_service import fetch_matching_keys
        current = fetch_matching_keys(live, {item["key"] for item in items})
        stale = [item["key"] for item in items if item["key"] not in current or not item["live"] or item["live"]["definition"] != current[item["key"]]["definition"]]
        if stale:
            raise ValueError("Live changed after comparison. Refresh the comparison before deploying: " + ", ".join(stale))
        result = deploy_records(live, items)
        for item in items:
            state["history"].insert(0, {
                "timestamp": result["timestamp"], "key": item["key"], "name": item["name"],
                "status_before": item["status"], "result": "SUCCESS" if result["success"] else "FAILED",
                "error": result.get("error", ""), "object_type": "FUNCTION",
                "deployment_id": result.get("deployment_id", ""), "version": result.get("version", ""),
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
        return jsonify({"backups": search_backups(require_role("live"), request.args.to_dict())})
    except Exception as exc:
        return jsonify({"error": safe_error(exc)}), 400


@app.get("/api/backups/<int:backup_id>/view")
@app.get("/api/backups/<int:backup_id>/download")
def backup_file(backup_id):
    try:
        records = search_backups(require_role("live"), {"backup_id": str(backup_id)})
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
