from datetime import datetime, timezone
from .backup_service import create_backup
from .comparison_service import normalize_definition
from .db_service import connection
from .registry_service import insert_backup, update_status


def migration_sql(item, allow_destructive=False):
    source, live = item['source'], item['live']
    if not live:
        statements = []
        for sequence in source.get('sequences', []):
            qualified_sequence = f'"{sequence["schema"]}"."{sequence["name"]}"'
            cycle = ' CYCLE' if sequence['cycle'] else ''
            statements.append(
                f'CREATE SEQUENCE IF NOT EXISTS {qualified_sequence} '
                f'AS {sequence["data_type"]} START WITH {sequence["start"]} '
                f'INCREMENT BY {sequence["increment"]} MINVALUE {sequence["min"]} '
                f'MAXVALUE {sequence["max"]} CACHE {sequence["cache"]}{cycle};'
            )
        statements.append(source['definition'])
        for sequence in source.get('sequences', []):
            qualified_sequence = f'"{sequence["schema"]}"."{sequence["name"]}"'
            qualified_table = f'"{source["schema"]}"."{source["name"]}"'
            statements.append(f'ALTER SEQUENCE {qualified_sequence} OWNED BY {qualified_table}."{sequence["column"]}";')
        return '\n'.join(statements), False
    statements, destructive = [], []
    old_columns = {x['name']: x for x in live['columns']}
    new_columns = {x['name']: x for x in source['columns']}
    qualified = f'"{source["schema"]}"."{source["name"]}"'
    for name in sorted(new_columns.keys() - old_columns.keys()):
        column = new_columns[name]
        definition = f'"{name}" {column["data_type"]}'
        if column['default']: definition += f' DEFAULT {column["default"]}'
        if not column['nullable']: definition += ' NOT NULL'
        statements.append(f'ALTER TABLE {qualified} ADD COLUMN {definition};')
    for name in sorted(old_columns.keys() - new_columns.keys()):
        destructive.append(f'ALTER TABLE {qualified} DROP COLUMN "{name}";')
    for name in sorted(old_columns.keys() & new_columns.keys()):
        old, new = old_columns[name], new_columns[name]
        if old['data_type'] != new['data_type']:
            statements.append(f'ALTER TABLE {qualified} ALTER COLUMN "{name}" TYPE {new["data_type"]};')
        if old['default'] != new['default']:
            action = f'SET DEFAULT {new["default"]}' if new['default'] else 'DROP DEFAULT'
            statements.append(f'ALTER TABLE {qualified} ALTER COLUMN "{name}" {action};')
        if old['nullable'] != new['nullable']:
            statements.append(f'ALTER TABLE {qualified} ALTER COLUMN "{name}" {"DROP NOT NULL" if new["nullable"] else "SET NOT NULL"};')
    old_constraints = {x['name']: x for x in live['constraints']}
    new_constraints = {x['name']: x for x in source['constraints']}
    for name in sorted(new_constraints.keys() - old_constraints.keys()):
        item = new_constraints[name]
        statements.append(f'ALTER TABLE {qualified} ADD CONSTRAINT "{name}" {item["definition"]};')
    for name in sorted(old_constraints.keys() - new_constraints.keys()):
        destructive.append(f'ALTER TABLE {qualified} DROP CONSTRAINT "{name}";')
    for name in sorted(old_constraints.keys() & new_constraints.keys()):
        if old_constraints[name]['definition'] != new_constraints[name]['definition']:
            destructive.append(f'ALTER TABLE {qualified} DROP CONSTRAINT "{name}";')
            statements.append(f'ALTER TABLE {qualified} ADD CONSTRAINT "{name}" {new_constraints[name]["definition"]};')
    old_indexes = {x['name']: x for x in live['indexes']}
    new_indexes = {x['name']: x for x in source['indexes']}
    for name in sorted(new_indexes.keys() - old_indexes.keys()): statements.append(new_indexes[name]['definition'] + ';')
    for name in sorted(old_indexes.keys() - new_indexes.keys()): destructive.append(f'DROP INDEX "{name}";')
    for name in sorted(old_indexes.keys() & new_indexes.keys()):
        if old_indexes[name]['definition'] != new_indexes[name]['definition']:
            destructive.append(f'DROP INDEX "{name}";')
            statements.append(new_indexes[name]['definition'] + ';')
    if destructive and not allow_destructive:
        return '\n'.join(statements + ['-- DESTRUCTIVE SQL REQUIRES EXPLICIT CONFIRMATION:'] + ['-- ' + statement for statement in destructive]), True
    return '\n'.join(statements + destructive), bool(destructive)


def generate_table_script(items, output_dir, allow_destructive=False):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = output_dir / f'Deploy_Tables_{timestamp}.sql'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as output:
        output.write('-- TABLE DEPLOYMENT SCRIPT\n')
        for item in items:
            sql, destructive = migration_sql(item, allow_destructive)
            output.write(f'\n-- TABLE: {item["key"]} STATUS: {item["status"]}\n')
            if destructive and not allow_destructive: output.write('-- REVIEW REQUIRED: destructive statements are commented below.\n')
            output.write(sql + '\n')
    return path


def deploy_tables(config, items, deployment_id, version, allow_destructive=False):
    started = datetime.now(timezone.utc).isoformat()
    backups = []
    try:
        with connection(config) as conn:
            for item in items:
                sql, destructive = migration_sql(item, allow_destructive)
                if destructive and not allow_destructive:
                    return {'success': False, 'timestamp': started, 'error': 'Destructive table changes require explicit confirmation.'}
                source_backup = create_backup('TABLE', item['source'], deployment_id, version, item['status'])
                backups.append(insert_backup(config, 'TABLE', item['source'], source_backup, deployment_id, version, 'TABLE_DEPLOYMENT', notes='T&D source snapshot'))
                if item['live']:
                    backup = create_backup('TABLE', item['live'], deployment_id, version, item['status'])
                    backups.append(insert_backup(config, 'TABLE', item['live'], backup, deployment_id, version, 'TABLE_DEPLOYMENT', notes='LIVE pre-deployment snapshot'))
                with conn.cursor() as cursor: cursor.execute(sql)
            conn.commit()
        update_status(config, deployment_id, 'SUCCESS')
        return {'success': True, 'timestamp': started, 'deployed': [item['key'] for item in items], 'deployment_id': deployment_id, 'backup_ids': backups}
    except Exception as exc:
        try: update_status(config, deployment_id, 'FAILED')
        except Exception: pass
        return {'success': False, 'timestamp': started, 'deployment_id': deployment_id, 'error': str(exc), 'backup_ids': backups}
