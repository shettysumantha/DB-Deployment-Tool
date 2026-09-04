from .db_service import connection


FUNCTION_QUERY = """
SELECT
    p.oid::bigint,
    p.proname,
    n.nspname,
    pg_get_function_identity_arguments(p.oid),
    pg_get_function_arguments(p.oid),
    pg_get_function_result(p.oid),
    p.prosrc,
    l.lanname,
    p.procost,
    p.prosecdef,
    p.provolatile,
    p.proparallel,
    p.proisstrict,
    pg_get_functiondef(p.oid)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE n.nspname = 'public'
  AND p.prokind = 'f'
  AND (
        p.proname ILIKE ANY(
            ARRAY(
                SELECT '%%' || word || '%%'
                FROM unnest(%s::text[]) AS word
            )
        )
      )
ORDER BY
    p.proname,
    pg_get_function_identity_arguments(p.oid),
    p.oid
"""


def parse_expected(raw):
    return sorted({
        part.strip()
        for part in raw.replace(",", "\n").splitlines()
        if part.strip()
    })


def function_key(schema, name, identity_arguments):
    return f"{schema}.{name}({identity_arguments})"


def _record(row):
    (
        oid,
        name,
        schema,
        identity_arguments,
        arguments,
        result,
        body,
        language,
        cost,
        security_definer,
        volatility,
        parallel,
        strict,
        definition
    ) = row

    return {
        "oid": oid,
        "name": name,
        "schema": schema,
        "identity_arguments": identity_arguments,
        "arguments": arguments,
        "result": result,
        "body": body,
        "language": language,
        "cost": float(cost),
        "security_definer": bool(security_definer),
        "volatility": volatility,
        "parallel": parallel,
        "strict": bool(strict),
        "definition": definition,
        "key": function_key(schema, name, identity_arguments),
    }


def fetch_selected(config, expected_names):
    expected_names = expected_names or [""]

    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                FUNCTION_QUERY,
                (expected_names,)
            )
            records = [_record(row) for row in cursor.fetchall()]

    return {
        record["key"]: record
        for record in records
    }


def fetch_matching_keys(config, keys):
    if not keys:
        return {}

    names = sorted({
        key.split(".", 1)[1].split("(", 1)[0]
        for key in keys
    })

    records = fetch_selected(config, names)

    return {
        key: record
        for key, record in records.items()
        if key in keys
    }