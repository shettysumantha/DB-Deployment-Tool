from services.notification_service import send_deployment_notification


result = {
    "deployment_id": "TEST-001",
    "timestamp": "2026-09-05 22:30:00",
    "deployed": [
        "test_function",
        "test_table"
    ],
    "failed": None,
    "backup_ids": [
        "backup-test-001"
    ],
    "success": True,
    "error": ""
}


response = send_deployment_notification(result)

print(response)