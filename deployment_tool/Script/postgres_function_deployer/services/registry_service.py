from .db_service import connection

REGISTRY_DDL = """
CREATE TABLE IF NOT EXISTS public.tbl_deployment_backup_registry (
 backup_id BIGSERIAL PRIMARY KEY, object_type VARCHAR(20) NOT NULL,
 schema_name VARCHAR(255) NOT NULL, object_name VARCHAR(255) NOT NULL,
 object_signature TEXT, backup_file_name TEXT, backup_file_path TEXT,
 backup_file_type VARCHAR(20), backup_created_at TIMESTAMPTZ,
 deployment_version VARCHAR(100) NOT NULL, deployment_id VARCHAR(100) NOT NULL,
 deployment_type VARCHAR(40) NOT NULL, source_environment VARCHAR(20) NOT NULL DEFAULT 'T&D',
 target_environment VARCHAR(20) NOT NULL DEFAULT 'LIVE', previous_object_status VARCHAR(20) NOT NULL,
 backup_reason VARCHAR(40) NOT NULL DEFAULT 'PRE_DEPLOYMENT', deployment_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
 deployed_at TIMESTAMPTZ, deployed_by VARCHAR(255), file_size_bytes BIGINT, file_checksum CHAR(64),
 notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_backup_registry_file ON public.tbl_deployment_backup_registry (backup_file_name);
CREATE INDEX IF NOT EXISTS idx_backup_registry_object ON public.tbl_deployment_backup_registry (object_name);
CREATE INDEX IF NOT EXISTS idx_backup_registry_deployment ON public.tbl_deployment_backup_registry (deployment_id);
CREATE INDEX IF NOT EXISTS idx_backup_registry_created ON public.tbl_deployment_backup_registry (backup_created_at);
CREATE INDEX IF NOT EXISTS idx_backup_registry_version ON public.tbl_deployment_backup_registry (deployment_version);
"""


def ensure_registry(config):
    with connection(config) as conn:
        with conn.cursor() as cursor: cursor.execute(REGISTRY_DDL)
        conn.commit()


def insert_backup(config, object_type, record, backup, deployment_id, version, deployment_type, status='PENDING', notes=''):
    ensure_registry(config)
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute("""SELECT backup_id FROM public.tbl_deployment_backup_registry
                WHERE deployment_id=%s AND object_type=%s AND schema_name=%s AND object_name=%s
                ORDER BY backup_id LIMIT 1""", (deployment_id, object_type, record.get('schema', 'public'), record['name']))
            existing = cursor.fetchone()
            if existing:
                return existing[0]
            cursor.execute("""INSERT INTO public.tbl_deployment_backup_registry
                (object_type,schema_name,object_name,object_signature,backup_file_name,backup_file_path,
                 backup_file_type,backup_created_at,deployment_version,deployment_id,deployment_type,
                 previous_object_status,deployment_status,deployed_by,file_size_bytes,file_checksum,notes)
                VALUES (%s,%s,%s,%s,%s,%s,'SQL',%s,%s,%s,%s,%s,%s,current_user,%s,%s,%s)
                RETURNING backup_id""", (object_type, record.get('schema', 'public'), record['name'],
                record.get('signature', record.get('key')), backup.get('file_name'), backup.get('file_path'),
                backup.get('created_at'), version, deployment_id, deployment_type, status, status,
                backup.get('size'), backup.get('checksum'), notes))
            backup_id = cursor.fetchone()[0]
        conn.commit()
    return backup_id


def update_status(config, deployment_id, status):
    ensure_registry(config)
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE public.tbl_deployment_backup_registry SET deployment_status=%s, deployed_at=now(), updated_at=now() WHERE deployment_id=%s", (status, deployment_id))
        conn.commit()


def search_backups(config, params):
    ensure_registry(config)
    clauses, values = [], []
    for field in ('backup_id', 'backup_file_name', 'object_name', 'object_type', 'deployment_id', 'deployment_version', 'deployment_status'):
        if params.get(field): clauses.append(f'{field}::text ILIKE %s'); values.append(f"%{params[field]}%")
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with connection(config) as conn:
        with conn.cursor() as cursor:
            cursor.execute('SELECT backup_id, object_type, schema_name, object_name, backup_file_name, backup_file_path, deployment_version, backup_created_at, deployment_id, deployment_status, file_size_bytes, file_checksum FROM public.tbl_deployment_backup_registry' + where + ' ORDER BY backup_created_at DESC NULLS LAST LIMIT 200', values)
            columns = [item[0] for item in cursor.description]
            records = [dict(zip(columns, row)) for row in cursor.fetchall()]
            for record in records:
                if record.get('backup_created_at'):
                    record['backup_created_at'] = record['backup_created_at'].isoformat()
            return records
