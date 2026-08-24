import re

from .function_service import fetch_matching_keys


def normalize_definition(definition):
    if not definition:
        return ""
    lines = [re.sub(r"[ \t]+$", "", line) for line in definition.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def compare_functions(td_config, live_config, expected_names):
    from .function_service import fetch_selected
    source = fetch_selected(td_config, expected_names)
    live = fetch_matching_keys(live_config, set(source))
    results = []
    for key in sorted(set(source) | set(live)):
        source_record = source.get(key)
        live_record = live.get(key)
        if source_record and not live_record:
            status = "NEW"
        elif live_record and not source_record:
            status = "LIVE ONLY"
        elif normalize_definition(source_record["definition"]) != normalize_definition(live_record["definition"]):
            status = "MODIFIED"
        else:
            status = "IDENTICAL"
        results.append({
            "key": key,
            "name": (source_record or live_record)["name"],
            "signature": key,
            "status": status,
            "source": source_record,
            "live": live_record,
        })
    return results
