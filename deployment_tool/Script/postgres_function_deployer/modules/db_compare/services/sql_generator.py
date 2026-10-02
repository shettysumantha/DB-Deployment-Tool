from datetime import datetime
from pathlib import Path


def dollar_tag(body):
    candidate = "$BODY$"
    index = 1
    while candidate in body:
        candidate = f"$FUNC{index}$"
        index += 1
    return candidate


def generate_function_sql(record):
    tag = dollar_tag(record["body"])
    body = record["body"]
    if not body.endswith(("\n", "\r")):
        body += "\n"
    options = [
        f"LANGUAGE '{record['language']}'",
        f"COST {record['cost']:.1f}",
        f"SECURITY {'DEFINER' if record['security_definer'] else 'INVOKER'}",
    ]
    if record["volatility"] != "v":
        options.insert(0, {"i": "IMMUTABLE", "s": "STABLE"}.get(record["volatility"], "VOLATILE"))
    if record["strict"]:
        options.append("STRICT")
    if record["parallel"] != "u":
        options.append({"r": "PARALLEL RESTRICTED", "s": "PARALLEL SAFE"}[record["parallel"]])
    return (
        f"CREATE OR REPLACE FUNCTION {record['schema']}.{record['name']}({record['arguments']})\n"
        f"RETURNS {record['result']}\n"
        f"AS {tag}\n{body}{tag}\n"
        + "\n".join(options)
        + ";\n"
    )


def generate_script(records, output_dir):
    selected = sorted(records, key=lambda item: (item["name"].lower(), item["signature"]))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"Deploy_Functions_{timestamp}.sql"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        output.write("-- FUNCTION DEPLOYMENT SCRIPT\n")
        output.write(f"-- Generated: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
        for record in selected:
            output.write(f"-- FUNCTION: {record['key']}\n\n")
            output.write(generate_function_sql(record["source"]))
            output.write("\n")
    return path
