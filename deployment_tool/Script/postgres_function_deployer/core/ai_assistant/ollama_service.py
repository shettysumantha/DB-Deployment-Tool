import ipaddress
import json
import os
import re
from http.client import HTTPConnection, HTTPException
from urllib.parse import urlsplit


class AssistantError(Exception):
    pass


class UnsafePromptError(AssistantError):
    pass


_MAX_PROMPT_LENGTH = 2000
_MAX_RESPONSE_BYTES = 256 * 1024
_OLLAMA_TIMEOUT_SECONDS = 120
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?<![a-z0-9])(?:password|passwd|pwd|secret|credential|username|"
    r"api[_ -]?key|access[_ -]?token|client[_ -]?secret|pg[_-]?(?:password|user)|"
    r"database[_ -]?url|connection[_ -]?string)(?![a-z0-9])"
)
_DATABASE_URL_PATTERN = re.compile(r"(?i)\bpostgres(?:ql)?://")
_DATABASE_ENV_PATTERN = re.compile(r"(?im)^\s*(?:PG|TD_DB|LIVE_DB)_[A-Z_]+\s*=")
_SQL_DEFINITION_PATTERN = re.compile(
    r"(?is)\b(?:CREATE(?:\s+OR\s+REPLACE)?|ALTER|DROP|TRUNCATE)\s+"
    r"(?:TABLE|FUNCTION|PROCEDURE|VIEW|SCHEMA|DATABASE|INDEX|TRIGGER|TYPE)\b"
)
_SQL_STATEMENT_PATTERN = re.compile(
    r"(?im)^\s*(?:```(?:sql)?\s*)?(?:SELECT|INSERT|UPDATE|DELETE|WITH|GRANT|REVOKE)\b"
)
_CREDENTIAL_URL_PATTERN = re.compile(r"(?i)\b\w+://[^/\s:@]+:[^/\s@]+@")


def assistant_enabled():
    return os.getenv("AI_ASSISTANT_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }


def configured_model():
    return os.getenv("OLLAMA_MODEL", "qwen2.5:3b").strip()


def _validate_prompt(prompt):
    if not isinstance(prompt, str) or not prompt.strip():
        raise UnsafePromptError("Enter a question for the assistant.")
    if len(prompt) > _MAX_PROMPT_LENGTH:
        raise UnsafePromptError(
            f"Keep the question under {_MAX_PROMPT_LENGTH} characters."
        )
    if (
        _CREDENTIAL_PATTERN.search(prompt)
        or _CREDENTIAL_URL_PATTERN.search(prompt)
        or _DATABASE_URL_PATTERN.search(prompt)
        or _DATABASE_ENV_PATTERN.search(prompt)
        or "-----BEGIN" in prompt.upper()
    ):
        raise UnsafePromptError(
            "Do not include credential details, database connection strings, or private keys."
        )
    if (
        _SQL_DEFINITION_PATTERN.search(prompt)
        or _SQL_STATEMENT_PATTERN.search(prompt)
        or "```sql" in prompt.lower()
        or "$$" in prompt
    ):
        raise UnsafePromptError(
            "Do not include SQL statements, SQL definitions, or database schema."
        )
    return prompt.strip()


def _ollama_endpoint():
    raw_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip()
    try:
        parsed = urlsplit(raw_url)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port if parsed.port is not None else 11434
    except ValueError as exc:
        raise AssistantError(
            "OLLAMA_BASE_URL must use an IPv4 loopback address, such as "
            "http://127.0.0.1:11434."
        ) from exc

    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or address.version != 4
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65535
    ):
        raise AssistantError(
            "Ollama must be an unauthenticated HTTP service bound to an IPv4 "
            "loopback address, such as http://127.0.0.1:11434."
        )
    return str(address), port


def generate_answer(prompt):
    if not assistant_enabled():
        raise AssistantError("The local AI assistant is disabled.")

    safe_prompt = _validate_prompt(prompt)
    model = configured_model()
    if not model or len(model) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", model):
        raise AssistantError("OLLAMA_MODEL is missing or invalid.")

    host, port = _ollama_endpoint()
    payload = json.dumps({
        "model": model,
        "prompt": (
            "You are a local assistant for a PostgreSQL deployment application. "
            "Give concise general guidance. You have no access to the application, "
            "databases, credentials, or deployment actions. Do not request secrets "
            "or SQL definitions.\n\nQuestion:\n" + safe_prompt
        ),
        "stream": False,
        "options": {"num_predict": 512, "temperature": 0.2},
    }).encode("utf-8")

    connection = HTTPConnection(host, port, timeout=_OLLAMA_TIMEOUT_SECONDS)
    try:
        connection.request(
            "POST",
            "/api/generate",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response_body = response.read(_MAX_RESPONSE_BYTES + 1)
    except TimeoutError as exc:
        raise AssistantError(
            "The local model took too long to respond. Retry after it has loaded, "
            "or use a smaller Ollama model on this computer."
        ) from exc
    except (HTTPException, OSError) as exc:
        raise AssistantError(
            "The local Ollama service is unavailable. Start Ollama and verify the "
            "configured model on this computer."
        ) from exc
    finally:
        connection.close()

    if response.status == 404:
        raise AssistantError(
            f"The Ollama model '{model}' is not installed. Download it locally "
            "before using the assistant."
        )
    if response.status != 200:
        raise AssistantError(
            f"The local Ollama service returned HTTP {response.status}."
        )
    if len(response_body) > _MAX_RESPONSE_BYTES:
        raise AssistantError("The local Ollama response exceeded the size limit.")
    try:
        result = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssistantError("The local Ollama service returned an invalid response.") from exc

    answer = result.get("response") if isinstance(result, dict) else None
    if not isinstance(answer, str) or not answer.strip():
        raise AssistantError("The local Ollama service returned an empty response.")
    return answer.strip()
