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
TABLE_METADATA_QUERY = """
WITH selected_tables AS (
    SELECT c.oid::bigint AS oid, n.nspname AS schema_name, c.relname AS table_name,
           c.relispartition AS is_partition, pg_get_partkeydef(c.oid) AS partition_key,
           obj_description(c.oid, 'pg_class') AS description
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND (c.relname ILIKE %s OR c.relname = ANY(%s::text[]))
), table_columns AS (
    SELECT a.attrelid::bigint AS oid,
           jsonb_agg(jsonb_build_object(
               'name', a.attname, 'data_type', format_type(a.atttypid, a.atttypmod),
               'nullable', NOT a.attnotnull, 'default', pg_get_expr(ad.adbin, ad.adrelid),
               'identity', a.attidentity, 'generated', a.attgenerated, 'order', a.attnum
           ) ORDER BY a.attnum) AS items
    FROM pg_attribute a LEFT JOIN pg_attrdef ad
      ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
    WHERE a.attrelid IN (SELECT oid FROM selected_tables)
      AND a.attnum > 0 AND NOT a.attisdropped
    GROUP BY a.attrelid
), table_sequences AS (
    SELECT a.attrelid::bigint AS oid,
           jsonb_agg(jsonb_build_object(
               'schema', sn.nspname, 'name', sc.relname,
               'data_type', format_type(s.seqtypid, NULL), 'start', s.seqstart,
               'increment', s.seqincrement, 'min', s.seqmin, 'max', s.seqmax,
               'cache', s.seqcache, 'cycle', s.seqcycle, 'column', a.attname
           ) ORDER BY a.attnum) AS items
    FROM pg_attribute a
    JOIN pg_depend d ON d.refobjid = a.attrelid AND d.refobjsubid = a.attnum
                    AND d.classid = 'pg_class'::regclass
                    AND d.refclassid = 'pg_class'::regclass
                    AND d.deptype IN ('a', 'i')
    JOIN pg_class sc ON sc.oid = d.objid AND sc.relkind = 'S'
    JOIN pg_namespace sn ON sn.oid = sc.relnamespace
    JOIN pg_sequence s ON s.seqrelid = sc.oid
    WHERE a.attrelid IN (SELECT oid FROM selected_tables)
      AND a.attnum > 0 AND NOT a.attisdropped
    GROUP BY a.attrelid
), table_constraints AS (
    SELECT conrelid::bigint AS oid,
           jsonb_agg(jsonb_build_object(
               'name', conname, 'type', contype, 'definition', pg_get_constraintdef(oid)
           ) ORDER BY conname) AS items
    FROM pg_constraint
    WHERE conrelid IN (SELECT oid FROM selected_tables)
    GROUP BY conrelid
), table_indexes AS (
    SELECT i.indrelid::bigint AS oid,
           jsonb_agg(jsonb_build_object(
               'name', i.indexrelid::regclass::text, 'unique', i.indisunique,
               'primary', i.indisprimary, 'definition', pg_get_indexdef(i.indexrelid)
           ) ORDER BY i.indexrelid::regclass::text) AS items
    FROM pg_index i
    WHERE i.indrelid IN (SELECT oid FROM selected_tables)
      AND NOT i.indisprimary
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint constraint_record
          WHERE constraint_record.conindid = i.indexrelid
      )
    GROUP BY i.indrelid
)
SELECT t.oid, t.schema_name, t.table_name, t.is_partition, t.partition_key, t.description,
       COALESCE(c.items, '[]'::jsonb), COALESCE(s.items, '[]'::jsonb),
       COALESCE(k.items, '[]'::jsonb), COALESCE(i.items, '[]'::jsonb)
FROM selected_tables t
LEFT JOIN table_columns c ON c.oid = t.oid
LEFT JOIN table_sequences s ON s.oid = t.oid
LEFT JOIN table_constraints k ON k.oid = t.oid
LEFT JOIN table_indexes i ON i.oid = t.oid
ORDER BY t.table_name
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
            cursor.execute(TABLE_METADATA_QUERY, (pattern, names))
            rows = cursor.fetchall()
    records = []
    for row in rows:
        table = {
            'oid': row[0], 'schema': row[1], 'name': row[2],
            'is_partition': bool(row[3]), 'partition_key': row[4],
            'description': row[5] or '',
        }
        indexes = [dict(item, name=item['name'].split('.')[-1].strip('"')) for item in row[9]]
        records.append(_record(table, row[6], row[7], row[8], indexes))
    elapsed = perf_counter() - started
    if metrics is not None:
        metrics.update({'queries': 1, 'tables': len(records), 'elapsed': elapsed})
    LOGGER.info('table metadata fetched: tables=%d queries=%d elapsed=%.3fs', len(records), 1, elapsed)
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
        source_metrics.get('queries', 1), live_metrics.get('queries', 1), len(results),
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
