import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage


def _summary(result):
    deployed = result.get("deployed", [])
    failed = result.get("failed")
    return {
        "deployment_id": result.get("deployment_id", ""),
        "timestamp": result.get("timestamp", ""),
        "deployed": deployed,
        "failed": [failed] if failed else [],
        "backup_ids": result.get("backup_ids", []),
        "success": bool(result.get("success")),
        "error": result.get("error", ""),
    }


def _message(summary):
    status = "SUCCESS" if summary["success"] else "FAILED"
    deployed = "\n".join(f"- {item}" for item in summary["deployed"]) or "- None"
    failed = "\n".join(f"- {item}" for item in summary["failed"]) or "- None"
    return (
        f"Database deployment: {status}\n"
        f"Date/time: {summary['timestamp']}\n"
        f"Deployment: {summary['deployment_id']}\n"
        f"Source: T&D\nTarget: LIVE\n"
        f"Successful objects: {len(summary['deployed'])}\n"
        f"Failed objects: {len(summary['failed'])}\n"
        f"Backup references: {', '.join(map(str, summary['backup_ids'])) or 'None'}\n\n"
        f"Successful:\n{deployed}\n\nFailed:\n{failed}\n"
        f"Error: {summary['error'] or 'None'}\n"
    )


def send_deployment_notification(result):
    summary = _summary(result)
    body = _message(summary)
    email_to = os.getenv("NOTIFICATION_EMAIL_TO", "SUMANTHASHETTYTECH@GMAIL.COM").strip()
    mobile_to = os.getenv("NOTIFICATION_MOBILE_TO", "1111111111").strip()
    email_sent = False
    mobile_sent = False
    errors = []

    smtp_host = os.getenv("SMTP_HOST", "").strip()
    if smtp_host and email_to:
        try:
            message = EmailMessage()
            message["Subject"] = f"Database deployment {('completed' if summary['success'] else 'failed')}"
            message["From"] = os.getenv("SMTP_FROM", "database-deployer@localhost")
            message["To"] = email_to
            message.set_content(body)
            with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as client:
                if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                    client.starttls()
                smtp_user = os.getenv("SMTP_USERNAME", "")
                if smtp_user:
                    client.login(smtp_user, os.getenv("SMTP_PASSWORD", ""))
                client.send_message(message)
            email_sent = True
        except Exception as exc:
            errors.append(f"email: {exc}")

    webhook = os.getenv("MOBILE_NOTIFICATION_WEBHOOK", "").strip()
    if webhook and mobile_to:
        try:
            payload = json.dumps({"to": mobile_to, "message": body}).encode("utf-8")
            request = urllib.request.Request(webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=10):
                pass
            mobile_sent = True
        except Exception as exc:
            errors.append(f"mobile: {exc}")

    configured = bool(smtp_host or webhook)
    return {
        "email": "SENT" if email_sent else ("FAILED" if smtp_host else "NOT_CONFIGURED"),
        "mobile": "SENT" if mobile_sent else ("FAILED" if webhook else "NOT_CONFIGURED"),
        "errors": errors,
        "configured": configured,
    }
