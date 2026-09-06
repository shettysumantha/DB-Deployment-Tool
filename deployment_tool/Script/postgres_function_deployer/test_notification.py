import os

from dotenv import load_dotenv

from services.notification_service import send_deployment_notification


# ==========================================================
# LOAD .ENV
# ==========================================================

load_dotenv(".env", override=True)


# ==========================================================
# HEADER
# ==========================================================

print("======================================")
print("NOTIFICATION TEST")
print("======================================")


# ==========================================================
# CONFIGURATION CHECK
# ==========================================================

email_configured = bool(
    os.getenv(
        "NOTIFICATION_EMAIL_TO",
        ""
    ).strip()
)

smtp_host_configured = bool(os.getenv("BREVO_SMTP_HOST", "").strip())

smtp_username_configured = bool(os.getenv("BREVO_SMTP_USERNAME", "").strip())

smtp_password_configured = bool(os.getenv("BREVO_SMTP_PASSWORD", "").strip())

recipient_configured = bool(
    os.getenv(
        "NOTIFICATION_EMAIL_TO",
        ""
    ).strip()
)


print("Configuration:")

print(
    f"Email configured: "
    f"{'YES' if email_configured else 'NO'}"
)

print(
    f"SMTP host configured: "
    f"{'YES' if smtp_host_configured else 'NO'}"
)

print(
    f"SMTP username configured: "
    f"{'YES' if smtp_username_configured else 'NO'}"
)

print(
    f"SMTP password configured: "
    f"{'YES' if smtp_password_configured else 'NO'}"
)

print(
    f"Recipient configured: "
    f"{'YES' if recipient_configured else 'NO'}"
)


# ==========================================================
# TEST DEPLOYMENT RESULT
# ==========================================================

result = {
    "deployment_id": "TEST-001",

    "timestamp": (
        "2026-09-06 00:00:00"
    ),

    "deployed": [
        "test_function",
        "test_table"
    ],

    "failed": None,

    "backup_ids": [],
    "backup_files": [
        "test_backup.sql"
    ],

    "success": True,

    "error": "",
}


# ==========================================================
# SEND NOTIFICATION
# ==========================================================

try:

    response = send_deployment_notification(
        result
    )

except Exception as exc:

    print("\nResult:")

    print(
        "Email: FAILED"
    )

    print(
        f"Errors: "
        f"['{type(exc).__name__}: {exc}']"
    )

    print(
        "Notification success: False"
    )

    raise


# ==========================================================
# RESULT
# ==========================================================

print("\nResult:")

print(
    f"Email: "
    f"{response.get('email', 'NOT_CONFIGURED')}"
)

print(
    f"Errors: "
    f"{response.get('errors', [])}"
)

print(
    f"Backup files attached: "
    f"{response.get('backup_files_attached', [])}"
)

print(
    f"Notification success: "
    f"{response.get('notification_success', False)}"
)

print("======================================")