import base64
import json
import os
import urllib.request
from pathlib import Path
from email.message import EmailMessage

from dotenv import load_dotenv

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# ==========================================================
# PATH CONFIGURATION
# ==========================================================

# Current file:
# postgres_function_deployer/services/notification_service.py

SERVICES_DIR = Path(__file__).resolve().parent

# postgres_function_deployer
DEPLOYER_DIR = SERVICES_DIR.parent

# DB-Deployment-Tool
PROJECT_ROOT = DEPLOYER_DIR.parents[2]

# Environment file
ENV_FILE = DEPLOYER_DIR / ".env"

# Google OAuth files
DEFAULT_CREDENTIALS_FILE = PROJECT_ROOT / "credentials.json"
DEFAULT_TOKEN_FILE = PROJECT_ROOT / "token.json"


# ==========================================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================================

load_dotenv(
    dotenv_path=ENV_FILE,
    override=True
)


# ==========================================================
# GMAIL API
# ==========================================================

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.send"
]


# ==========================================================
# DEPLOYMENT SUMMARY
# ==========================================================

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


# ==========================================================
# EMAIL BODY
# ==========================================================

def _message(summary):

    status = (
        "SUCCESS"
        if summary["success"]
        else "FAILED"
    )

    deployed = "\n".join(
        f"- {item}"
        for item in summary["deployed"]
    ) or "- None"

    failed = "\n".join(
        f"- {item}"
        for item in summary["failed"]
    ) or "- None"

    backup_ids = ", ".join(
        map(str, summary["backup_ids"])
    ) or "None"

    return (
        f"Database deployment: {status}\n"
        f"Date/time: {summary['timestamp']}\n"
        f"Deployment: {summary['deployment_id']}\n"
        f"Source: T&D\n"
        f"Target: LIVE\n"
        f"Successful objects: {len(summary['deployed'])}\n"
        f"Failed objects: {len(summary['failed'])}\n"
        f"Backup references: {backup_ids}\n\n"
        f"Successful:\n"
        f"{deployed}\n\n"
        f"Failed:\n"
        f"{failed}\n\n"
        f"Error: {summary['error'] or 'None'}\n"
    )


# ==========================================================
# RESOLVE GOOGLE FILE PATH
# ==========================================================

def _resolve_project_path(value, default_path):

    value = (value or "").strip()

    if not value:
        return default_path

    path = Path(value)

    if path.is_absolute():
        return path

    return PROJECT_ROOT / path


# ==========================================================
# GMAIL AUTHENTICATION
# ==========================================================

def _get_gmail_service():

    credentials_file = _resolve_project_path(
        os.getenv("GOOGLE_CREDENTIALS_FILE"),
        DEFAULT_CREDENTIALS_FILE
    )

    token_file = _resolve_project_path(
        os.getenv("GOOGLE_TOKEN_FILE"),
        DEFAULT_TOKEN_FILE
    )

    # ------------------------------------------------------
    # Validate credentials.json
    # ------------------------------------------------------

    if not credentials_file.exists():

        raise FileNotFoundError(
            "Google OAuth credentials file not found:\n"
            f"{credentials_file}\n\n"
            "Place credentials.json in the project root or "
            "configure GOOGLE_CREDENTIALS_FILE in .env."
        )

    credentials = None

    # ------------------------------------------------------
    # Load existing token
    # ------------------------------------------------------

    if token_file.exists():

        try:

            credentials = (
                Credentials
                .from_authorized_user_file(
                    str(token_file),
                    GMAIL_SCOPES
                )
            )

        except Exception:

            credentials = None

    # ------------------------------------------------------
    # Authenticate / refresh
    # ------------------------------------------------------

    if not credentials or not credentials.valid:

        # Existing refresh token
        if (
            credentials
            and credentials.expired
            and credentials.refresh_token
        ):

            credentials.refresh(
                Request()
            )

        # First-time authorization
        else:

            flow = (
                InstalledAppFlow
                .from_client_secrets_file(
                    str(credentials_file),
                    GMAIL_SCOPES
                )
            )

            credentials = flow.run_local_server(
                port=0
            )

        # Save token
        token_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            token_file,
            "w",
            encoding="utf-8"
        ) as token:

            token.write(
                credentials.to_json()
            )

    # ------------------------------------------------------
    # Build Gmail service
    # ------------------------------------------------------

    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


# ==========================================================
# SEND EMAIL
# ==========================================================

def _send_email(
    to_email,
    subject,
    body
):

    service = _get_gmail_service()

    message = EmailMessage()

    message["To"] = to_email
    message["Subject"] = subject

    message.set_content(body)

    encoded_message = (
        base64.urlsafe_b64encode(
            message.as_bytes()
        )
        .decode("utf-8")
    )

    result = (
        service
        .users()
        .messages()
        .send(
            userId="me",
            body={
                "raw": encoded_message
            }
        )
        .execute()
    )

    return result


# ==========================================================
# MOBILE WEBHOOK
# ==========================================================

def _send_mobile_notification(
    webhook,
    mobile_to,
    body
):

    payload = json.dumps(
        {
            "to": mobile_to,
            "message": body
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        webhook,
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    with urllib.request.urlopen(
        request,
        timeout=10
    ) as response:

        response.read()

        return response.status


# ==========================================================
# MAIN NOTIFICATION FUNCTION
# ==========================================================

def send_deployment_notification(result):

    summary = _summary(result)

    body = _message(summary)

    # ------------------------------------------------------
    # Read configuration
    # ------------------------------------------------------

    email_to = os.getenv(
        "NOTIFICATION_EMAIL_TO",
        ""
    ).strip()

    mobile_to = os.getenv(
        "NOTIFICATION_MOBILE_TO",
        ""
    ).strip()

    webhook = os.getenv(
        "MOBILE_NOTIFICATION_WEBHOOK",
        ""
    ).strip()

    email_sent = False
    mobile_sent = False

    errors = []

    # ======================================================
    # EMAIL
    # ======================================================

    if email_to:

        try:

            subject = (
                "Database deployment completed"
                if summary["success"]
                else "Database deployment failed"
            )

            _send_email(
                email_to,
                subject,
                body
            )

            email_sent = True

        except Exception as exc:

            errors.append(
                f"email: {type(exc).__name__}: {exc}"
            )

    # ======================================================
    # MOBILE
    # ======================================================

    if webhook and mobile_to:

        try:

            _send_mobile_notification(
                webhook,
                mobile_to,
                body
            )

            mobile_sent = True

        except Exception as exc:

            errors.append(
                f"mobile: {type(exc).__name__}: {exc}"
            )

    # ======================================================
    # RESULT
    # ======================================================

    configured = bool(
        email_to
        or (webhook and mobile_to)
    )

    return {
        "email": (
            "SENT"
            if email_sent
            else (
                "FAILED"
                if email_to
                else "NOT_CONFIGURED"
            )
        ),

        "mobile": (
            "SENT"
            if mobile_sent
            else (
                "FAILED"
                if webhook and mobile_to
                else "NOT_CONFIGURED"
            )
        ),

        "errors": errors,

        "configured": configured,

        "notification_success": (
            email_sent or mobile_sent
        ),
    }