import re
import logging
from time import perf_counter

from .db_service import connection

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LOGGER = logging.getLogger(__name__)
TABLE_QUERY = """
SELECT c.oid::bigint, n.nspname, c.relname, c.relispartition,
       pg_get_partkeydef(c.oid),
       obj_description(c.oid, 'pg_class')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND (c.relname ILIKE %s OR c.relname = ANY(%s::text[]))
ORDER BY c.relname
"""
TABLE_COLUMNS_QUERY = """
SELECT a.attrelid::bigint, a.attname, format_type(a.atttypid, a.atttypmod),
             a.attnotnull, pg_get_expr(ad.adbin, ad.adrelid), a.attidentity,
             a.attgenerated, a.attnum
FROM pg_attribute a
LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
WHERE a.attrelid = ANY(%s::bigint[]) AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attrelid, a.attnum
"""
TABLE_SEQUENCES_QUERY = """
SELECT a.attrelid::bigint, a.attname, sn.nspname, sc.relname,
             format_type(s.seqtypid, NULL), s.seqstart, s.seqincrement,
             s.seqmin, s.seqmax, s.seqcache, s.seqcycle
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class sc ON sc.oid = to_regclass(
        pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname)
)
JOIN pg_namespace sn ON sn.oid = sc.relnamespace
JOIN pg_sequence s ON s.seqrelid = sc.oid
WHERE a.attrelid = ANY(%s::bigint[]) AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attrelid, a.attnum
"""
TABLE_CONSTRAINTS_QUERY = """
SELECT conrelid::bigint, conname, contype, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = ANY(%s::bigint[])
ORDER BY conrelid, conname
"""
TABLE_INDEXES_QUERY = """
SELECT i.indrelid::bigint, i.indexrelid::regclass::text, i.indisunique,
             i.indisprimary, pg_get_indexdef(i.indexrelid)
FROM pg_index i
WHERE i.indrelid = ANY(%s::bigint[])
    AND NOT i.indisprimary
    AND NOT EXISTS (
            SELECT 1
            FROM pg_constraint constraint_record
            WHERE constraint_record.conindid = i.indexrelid
    )
ORDER BY i.indrelid, i.indexrelid::regclass::text
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


def _record(table, columns, sequences, constraints, indexes):
    schema, name = table['schema'], table['name']
    definition = _create_definition(schema, name, columns, constraints, indexes, table['partition_key'], sequences)
    return {'key': table_key(schema, name), 'schema': schema, 'name': name,
        'columns': columns, 'constraints': constraints, 'indexes': indexes,
        'sequences': sequences,
        'is_partition': table['is_partition'], 'partition_key': table['partition_key'],
        'description': table['description'], 'definition': definition}


def _create_definition(schema, name, columns, constraints, indexes, partition_key, sequences=None):
    sequences = sequences or []
    sequence_by_column = {item['column']: item for item in sequences}
    lines = []
    for column in columns:
        line = f'    "{column["name"]}" {column["data_type"]}'
        if column['identity']:
            line += f" GENERATED {'ALWAYS' if column['identity'] == 'a' else 'BY DEFAULT'} AS IDENTITY"
        if column['generated']:
            line += ' GENERATED ALWAYS AS (' + (column['default'] or '') + ') STORED'
        elif column['default'] and column['name'] in sequence_by_column and 'nextval' in column['default']:
            sequence = sequence_by_column[column['name']]
            qualified_sequence = f'"{sequence["schema"]}"."{sequence["name"]}"'
            line += f" DEFAULT nextval('{qualified_sequence}'::regclass)"
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


def fetch_selected(config, names, pattern='%', metrics=None):
    names = _validate_names(names)
    started = perf_counter()
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute(TABLE_QUERY, (pattern, names))
            table_rows = cursor.fetchall()
            table_ids = [row[0] for row in table_rows]
            tables = {
                row[0]: {
                    'oid': row[0], 'schema': row[1], 'name': row[2],
                    'is_partition': bool(row[3]), 'partition_key': row[4],
                    'description': row[5] or '',
                }
                for row in table_rows
            }
            cursor.execute(TABLE_COLUMNS_QUERY, (table_ids,))
            columns = {}
            for row in cursor.fetchall():
                columns.setdefault(row[0], []).append({
                    'name': row[1], 'data_type': row[2], 'nullable': not row[3],
                    'default': row[4], 'identity': row[5], 'generated': row[6], 'order': row[7]
                })
            cursor.execute(TABLE_SEQUENCES_QUERY, (table_ids,))
            sequences = {}
            for row in cursor.fetchall():
                sequences.setdefault(row[0], []).append({
                    'schema': row[2], 'name': row[3], 'data_type': row[4],
                    'start': row[5], 'increment': row[6], 'min': row[7],
                    'max': row[8], 'cache': row[9], 'cycle': row[10], 'column': row[1],
                })
            cursor.execute(TABLE_CONSTRAINTS_QUERY, (table_ids,))
            constraints = {}
            for row in cursor.fetchall():
                constraints.setdefault(row[0], []).append({
                    'name': row[1], 'type': row[2], 'definition': row[3]
                })
            cursor.execute(TABLE_INDEXES_QUERY, (table_ids,))
            indexes = {}
            for row in cursor.fetchall():
                indexes.setdefault(row[0], []).append({
                    'name': row[1].split('.')[-1].strip('"'), 'unique': row[2],
                    'primary': row[3], 'definition': row[4]
                })
    records = [
        _record(table, columns.get(oid, []), sequences.get(oid, []),
                constraints.get(oid, []), indexes.get(oid, []))
        for oid, table in tables.items()
    ]
    elapsed = perf_counter() - started
    if metrics is not None:
        metrics.update({'queries': 5, 'tables': len(records), 'elapsed': elapsed})
    LOGGER.info('table metadata fetched: tables=%d queries=%d elapsed=%.3fs', len(records), 5, elapsed)
    return {record['key']: record for record in records}


def _signature(record):
    return {
        'columns': [{key: value for key, value in column.items() if key != 'order'} for column in record['columns']],
        'constraints': [(item['name'], item['type'], item['definition']) for item in record['constraints']],
        'indexes': [(item['name'], item['definition']) for item in record['indexes']],
        'sequences': [(item['schema'], item['name'], item['data_type'], item['start'], item['increment'], item['min'], item['max'], item['cache'], item['cycle'], item['column']) for item in record.get('sequences', [])],
        'partition_key': record['partition_key'], 'is_partition': record['is_partition']
    }


def compare_tables(td_config, live_config, names, include_live_only=False, pattern='%'):
    started = perf_counter()
    source_metrics, live_metrics = {}, {}
    source = fetch_selected(td_config, names, pattern, source_metrics)
    live = fetch_selected(live_config, names if not include_live_only else names, pattern, live_metrics)
    results = []
    for key in sorted(set(source) | set(live)):
        source_record, live_record = source.get(key), live.get(key)
        if source_record and not live_record:
            status, changes = 'NEW', ['Not available in Target']
        elif live_record and not source_record:
            status, changes = 'MISSING', ['Not present in Source tables']
        elif _signature(source_record) != _signature(live_record):
            status, changes = 'MODIFIED', describe_changes(live_record, source_record)
        else:
            status, changes = 'IDENTICAL', ['No changes']
        results.append({'key': key, 'name': (source_record or live_record)['name'],
                        'schema': (source_record or live_record)['schema'], 'status': status,
                        'changes': changes, 'source': source_record, 'live': live_record,
                        'destructive': any(item.startswith(('REMOVED', 'DROP')) for item in changes)})
    LOGGER.info(
        'table comparison complete: source_queries=%d live_queries=%d tables=%d compare_elapsed=%.3fs total_elapsed=%.3fs',
        source_metrics.get('queries', 5), live_metrics.get('queries', 5), len(results),
        perf_counter() - started - source_metrics.get('elapsed', 0) - live_metrics.get('elapsed', 0),
        perf_counter() - started,
    )
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
