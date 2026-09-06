import json
import os
import re
import smtplib
import urllib.request
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from dotenv import load_dotenv


SERVICES_DIR = Path(__file__).resolve().parent
DEPLOYER_DIR = SERVICES_DIR.parent
ENV_FILE = DEPLOYER_DIR / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=True)

MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024


def _summary(result):
    deployed = result.get("deployed") or []
    failed = result.get("failed")
    if isinstance(failed, list):
        failed_items = failed
    elif failed:
        failed_items = [failed]
    else:
        failed_items = []
    backup_ids = result.get("backup_ids") or []
    return {
        "deployment_id": result.get("deployment_id", ""),
        "timestamp": result.get("timestamp", ""),
        "deployed": deployed,
        "failed": failed_items,
        "backup_ids": backup_ids,
        "success": bool(result.get("success")),
        "error": result.get("error", ""),
    }


def _normalize_recipients(value):
    if not value:
        return []
    return [item.strip() for item in re.split(r"[,;]", str(value)) if item.strip()]


def _message(summary):
    status = "SUCCESS" if summary["success"] else "FAILED"
    deployed = "\n".join(f"- {item}" for item in summary["deployed"]) or "- None"
    failed = "\n".join(f"- {item}" for item in summary["failed"]) or "- None"
    backup_ids = ", ".join(map(str, summary["backup_ids"])) or "None"
    return (
        f"Database deployment: {status}\n"
        f"Date/time: {summary['timestamp']}\n"
        f"Deployment ID: {summary['deployment_id']}\n"
        f"Source: T&D\n"
        f"Target: LIVE\n\n"
        f"Successful objects:\n{deployed}\n\n"
        f"Failed objects:\n{failed}\n\n"
        f"Backup references: {backup_ids}\n\n"
        f"Backup files attached:\n- Check the attachment list below\n\n"
        f"Error: {summary['error'] or 'None'}\n"
    )


def _normalize_backup_paths(result):
    values = []
    for key in ("backup_file", "backup_file_path", "backup_path", "backup_files", "backup_file_paths"):
        value = result.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            values.extend(list(value))
        else:
            values.append(value)
    normalized = []
    for item in values:
        if isinstance(item, Path):
            normalized.append(str(item))
        elif isinstance(item, str):
            normalized.append(item)
    return normalized


def _collect_backup_attachments(result):
    files = []
    seen = set()
    for raw_path in _normalize_backup_paths(result):
        candidate = Path(str(raw_path)).expanduser()
        if not candidate.is_absolute():
            candidate = (DEPLOYER_DIR / candidate).resolve()
        if candidate.exists() and candidate.is_file():
            resolved = str(candidate.resolve())
            if resolved not in seen:
                seen.add(resolved)
                files.append(candidate)
    return files


def _send_email_with_smtp(subject, body, recipients, attachments=None):
    smtp_host = os.getenv("BREVO_SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("BREVO_SMTP_PORT", "587") or 587)
    username = os.getenv("BREVO_SMTP_USERNAME", "").strip()
    password = os.getenv("BREVO_SMTP_PASSWORD", "").strip()
    from_email = os.getenv("NOTIFICATION_EMAIL_FROM", "").strip()
    from_name = os.getenv("NOTIFICATION_EMAIL_FROM_NAME", "PostgreSQL Deployment Manager").strip()
    if not all([smtp_host, username, password, from_email]):
        raise ValueError("Brevo SMTP is not fully configured.")

    message = MIMEMultipart()
    message["From"] = f"{from_name} <{from_email}>" if from_name else from_email
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain", "utf-8"))

    for attachment in attachments or []:
        size = attachment.stat().st_size
        if size > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"Attachment too large to send: {attachment.name} ({size} bytes)")
        with attachment.open("rb") as file_handle:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(file_handle.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment", filename=attachment.name)
        message.attach(part)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(from_email, recipients, message.as_string())

    return True


def _send_mobile_notification(webhook, mobile_to, body):
    payload = json.dumps({"to": mobile_to, "message": body}).encode("utf-8")
    request = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()
        return response.status


def send_deployment_notification(result):
    summary = _summary(result)
    body = _message(summary)

    email_recipients = _normalize_recipients(os.getenv("NOTIFICATION_EMAIL_TO", ""))
    mobile_to = os.getenv("NOTIFICATION_MOBILE_TO", "").strip()
    webhook = os.getenv("MOBILE_NOTIFICATION_WEBHOOK", "").strip()

    email_sent = False
    mobile_sent = False
    errors = []
    backup_files = _collect_backup_attachments(result)
    backup_files_attached = [str(path) for path in backup_files]

    if email_recipients:
        try:
            subject = "SUCCESS: Database deployment completed" if summary["success"] else "FAILURE: Database deployment failed"
            _send_email_with_smtp(subject, body, email_recipients, backup_files)
            email_sent = True
        except Exception as exc:
            errors.append(f"email: {type(exc).__name__}: {exc}")

    if webhook and mobile_to:
        try:
            _send_mobile_notification(webhook, mobile_to, body)
            mobile_sent = True
        except Exception as exc:
            errors.append(f"mobile: {type(exc).__name__}: {exc}")

    configured = bool(email_recipients or (webhook and mobile_to))
    return {
        "email": "SENT" if email_sent else ("FAILED" if email_recipients else "NOT_CONFIGURED"),
        "mobile": "SENT" if mobile_sent else ("FAILED" if webhook and mobile_to else "NOT_CONFIGURED"),
        "backup_files_attached": backup_files_attached,
        "errors": errors,
        "configured": configured,
        "notification_success": bool(email_sent or mobile_sent),
    }
