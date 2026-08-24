from contextlib import contextmanager

import psycopg2


REQUIRED_FIELDS = ("host", "port", "database", "username", "password")


def clean_config(payload):
    values = {field: str(payload.get(field, "")).strip() for field in REQUIRED_FIELDS}
    if not all(values.values()):
        raise ValueError("Host, port, database, username, and password are required.")
    try:
        values["port"] = int(values["port"])
    except ValueError as exc:
        raise ValueError("Port must be a number.") from exc
    if not 1 <= values["port"] <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return values


@contextmanager
def connection(config):
    conn = psycopg2.connect(
        host=config["host"],
        port=config["port"],
        dbname=config["database"],
        user=config["username"],
        password=config["password"],
        connect_timeout=10,
        application_name="postgres-function-deployer",
    )
    try:
        yield conn
    finally:
        conn.close()


def test_connection(config):
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_database(), inet_server_addr()::text")
            database, server_address = cursor.fetchone()
    return {"database": database, "server_address": server_address}


def safe_error(error, secret=""):
    message = str(error).replace(secret, "[redacted]") if secret else str(error)
    return message.replace("password=", "password=[redacted]")
