from datetime import datetime, timezone

from .comparison_service import compare_functions
from .db_service import connection
from .sql_generator import generate_function_sql
from .backup_service import create_backup
from .registry_service import insert_backup, update_status


def deploy_records(config, records):
    ordered = sorted(records, key=lambda item: (item["name"].lower(), item["signature"]))
    started = datetime.now(timezone.utc).isoformat()
    deployment_id = "DEP_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_")
    version = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_ids = []
    try:
        with connection(config) as conn:
            try:
                with conn.cursor() as cursor:
                    for item in ordered:
                        try:
                            source_backup = create_backup("FUNCTION", item["source"], deployment_id, version, item["status"])
                            backup_ids.append(insert_backup(config, "FUNCTION", item["source"], source_backup, deployment_id, version, "FUNCTION_DEPLOYMENT", notes="T&D source snapshot"))
                            if item.get("live"):
                                backup = create_backup("FUNCTION", item["live"], deployment_id, version, item["status"])
                                backup_ids.append(insert_backup(config, "FUNCTION", item["live"], backup, deployment_id, version, "FUNCTION_DEPLOYMENT", notes="LIVE pre-deployment snapshot"))
                            cursor.execute(generate_function_sql(item["source"]))
                        except Exception as exc:
                            conn.rollback()
                            update_status(config, deployment_id, "FAILED")
                            return {
                                "success": False,
                                "timestamp": started,
                                "failed": item["key"],
                                "error": str(exc), "deployment_id": deployment_id, "backup_ids": backup_ids,
                            }
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        update_status(config, deployment_id, "SUCCESS")
        return {"success": True, "timestamp": started, "deployed": [item["key"] for item in ordered], "deployment_id": deployment_id, "backup_ids": backup_ids, "version": version}
    except Exception as exc:
        return {"success": False, "timestamp": started, "failed": ordered[0]["key"] if ordered else "", "error": str(exc)}


def refresh_comparison(td_config, live_config, expected_names):
    return compare_functions(td_config, live_config, expected_names)
