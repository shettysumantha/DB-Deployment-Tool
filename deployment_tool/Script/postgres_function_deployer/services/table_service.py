import re
from .db_service import connection

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TABLE_QUERY = """
SELECT c.oid::bigint, n.nspname, c.relname, c.relispartition,
       pg_get_partkeydef(c.oid),
       obj_description(c.oid, 'pg_class')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND (c.relname ILIKE %s OR c.relname = ANY(%s::text[]))
ORDER BY c.relname
"""
TABLE_NAMES_QUERY = """
SELECT n.nspname, c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname ILIKE %s
ORDER BY c.relname
"""


def parse_expected(raw):
    return sorted({part.strip() for part in raw.replace(',', '\n').splitlines() if part.strip()})


def _validate_names(names):
    invalid = [name for name in names if not IDENTIFIER.fullmatch(name)]
    if invalid:
        raise ValueError('Invalid PostgreSQL table name: ' + invalid[0])
    return sorted(set(names))


def table_key(schema, name):
    return f'{schema}.{name}'


def fetch_table_names(config, pattern='%', search=''):
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(TABLE_NAMES_QUERY, (f'%{search}%' if search else pattern,))
            return [{'key': table_key(schema, name), 'schema': schema, 'name': name}
                    for schema, name in cursor.fetchall()]


def _record(cursor, oid, schema, name, is_partition, partition_key, description):
    cursor.execute("""
        SELECT attname, format_type(atttypid, atttypmod), attnotnull,
               pg_get_expr(ad.adbin, ad.adrelid), attidentity, attgenerated,
               attnum
        FROM pg_attribute a LEFT JOIN pg_attrdef ad
          ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY a.attnum
    """, (oid,))
    columns = [{
        'name': row[0], 'data_type': row[1], 'nullable': not row[2],
        'default': row[3], 'identity': row[4], 'generated': row[5], 'order': row[6]
    } for row in cursor.fetchall()]
    cursor.execute("""
        SELECT conname, contype, pg_get_constraintdef(oid)
        FROM pg_constraint WHERE conrelid = %s
        ORDER BY conname
    """, (oid,))
    constraints = [{'name': row[0], 'type': row[1], 'definition': row[2]} for row in cursor.fetchall()]
    cursor.execute("""
        SELECT indexrelid::regclass::text, indisunique, indisprimary,
               pg_get_indexdef(indexrelid)
        FROM pg_index WHERE indrelid = %s AND NOT indisprimary
        ORDER BY indexrelid::regclass::text
    """, (oid,))
    indexes = [{'name': row[0].split('.')[-1].strip('"'), 'unique': row[1],
                'primary': row[2], 'definition': row[3]} for row in cursor.fetchall()]
    definition = _create_definition(schema, name, columns, constraints, indexes, partition_key)
    return {'key': table_key(schema, name), 'schema': schema, 'name': name,
            'columns': columns, 'constraints': constraints, 'indexes': indexes,
            'is_partition': bool(is_partition), 'partition_key': partition_key,
            'description': description or '', 'definition': definition}


def _create_definition(schema, name, columns, constraints, indexes, partition_key):
    lines = []
    for column in columns:
        line = f'    "{column["name"]}" {column["data_type"]}'
        if column['identity']:
            line += f" GENERATED {'ALWAYS' if column['identity'] == 'a' else 'BY DEFAULT'} AS IDENTITY"
        if column['generated']:
            line += ' GENERATED ALWAYS AS (' + (column['default'] or '') + ') STORED'
        elif column['default']:
            line += f" DEFAULT {column['default']}"
        if not column['nullable']:
            line += ' NOT NULL'
        lines.append(line)
    for constraint in constraints:
        lines.append(f'    CONSTRAINT "{constraint["name"]}" {constraint["definition"]}')
    suffix = f' PARTITION BY {partition_key}' if partition_key else ''
    sql = f'CREATE TABLE "{schema}"."{name}" (\n' + ',\n'.join(lines) + f'\n){suffix};\n'
    return sql + ''.join(f'{index["definition"]};\n' for index in indexes)


def fetch_selected(config, names, pattern='%'):
    names = _validate_names(names)
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(TABLE_QUERY, (pattern, names))
            records = [_record(cursor, *row) for row in cursor.fetchall()]
    return {record['key']: record for record in records}


def _signature(record):
    return {
        'columns': [{key: value for key, value in column.items() if key != 'order'} for column in record['columns']],
        'constraints': [(item['name'], item['type'], item['definition']) for item in record['constraints']],
        'indexes': [(item['name'], item['definition']) for item in record['indexes']],
        'partition_key': record['partition_key'], 'is_partition': record['is_partition']
    }


def compare_tables(td_config, live_config, names, include_live_only=False, pattern='%'):
    source = fetch_selected(td_config, names, pattern)
    live = fetch_selected(live_config, names if not include_live_only else names, pattern)
    results = []
    for key in sorted(set(source) | set(live)):
        source_record, live_record = source.get(key), live.get(key)
        if source_record and not live_record:
            status, changes = 'MISSING', ['Not available in Target']
        elif live_record and not source_record:
            status, changes = 'NEW', ['Not present in Source tables']
        elif _signature(source_record) != _signature(live_record):
            status, changes = 'MODIFIED', describe_changes(live_record, source_record)
        else:
            status, changes = 'IDENTICAL', ['No changes']
        results.append({'key': key, 'name': (source_record or live_record)['name'],
                        'schema': (source_record or live_record)['schema'], 'status': status,
                        'changes': changes, 'source': source_record, 'live': live_record,
                        'destructive': any(item.startswith(('REMOVED', 'DROP')) for item in changes)})
    return results


def describe_changes(old, new):
    changes = []
    old_columns, new_columns = {x['name']: x for x in old['columns']}, {x['name']: x for x in new['columns']}
    for name in sorted(new_columns.keys() - old_columns.keys()):
        changes.append(f'+ NEW COLUMN {name} {new_columns[name]["data_type"]}')
    for name in sorted(old_columns.keys() - new_columns.keys()):
        changes.append(f'- REMOVED COLUMN {name}')
    for name in sorted(old_columns.keys() & new_columns.keys()):
        before, after = old_columns[name], new_columns[name]
        if before['data_type'] != after['data_type']:
            changes.append(f'~ DATA TYPE CHANGED {name}: {before["data_type"]} -> {after["data_type"]}')
        if before['nullable'] != after['nullable']:
            changes.append(f'~ NULLABILITY CHANGED {name}')
        if before['default'] != after['default']:
            changes.append(f'~ DEFAULT VALUE CHANGED {name}')
        if before['identity'] != after['identity'] or before['generated'] != after['generated']:
            changes.append(f'~ IDENTITY/GENERATED CHANGED {name}')
    old_constraints = {(x['name'], x['definition']) for x in old['constraints']}
    new_constraints = {(x['name'], x['definition']) for x in new['constraints']}
    for name, _ in sorted(new_constraints - old_constraints): changes.append(f'+ CONSTRAINT {name}')
    for name, _ in sorted(old_constraints - new_constraints): changes.append(f'- REMOVED CONSTRAINT {name}')
    old_indexes = {(x['name'], x['definition']) for x in old['indexes']}
    new_indexes = {(x['name'], x['definition']) for x in new['indexes']}
    for name, _ in sorted(new_indexes - old_indexes): changes.append(f'+ INDEX {name}')
    for name, _ in sorted(old_indexes - new_indexes): changes.append(f'- REMOVED INDEX {name}')
    return changes or ['Table properties changed']
