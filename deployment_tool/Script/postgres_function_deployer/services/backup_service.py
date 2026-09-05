import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKUP_ROOT = Path(os.getenv('BACKUP_ROOT_PATH') or (Path.home() / 'DatabaseDeploymentBackups')).expanduser().resolve()


def _safe(value):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', value).strip('_') or 'object'


def create_backup(object_type, record, deployment_id, version, previous_status):
    if previous_status != 'MODIFIED':
        raise ValueError('Backups are only created for MODIFIED objects.')
    if not record or not record.get('definition'):
        raise ValueError('The existing LIVE definition is unavailable; deployment stopped before modification.')
    validate_storage()
    now = datetime.now(timezone.utc)
    folder = BACKUP_ROOT / 'LIVE' / f'{now:%Y}' / f'{now:%m}' / _safe(deployment_id)
    folder.mkdir(parents=True, exist_ok=True)
    suffix = record.get('signature', record.get('key', record.get('name', 'object')))
    filename = f'BACKUP_{object_type}_{_safe(suffix)}_{now:%Y%m%d_%H%M%S_%f}.sql'
    path = folder / filename
    with path.open('w', encoding='utf-8', newline='') as output:
        output.write(f'-- PRE-DEPLOYMENT LIVE BACKUP\n-- Deployment: {deployment_id}\n-- Version: {version}\n\n{record["definition"]}\n')
    if not path.is_file() or path.stat().st_size == 0:
        raise IOError('Backup file was not created successfully; deployment stopped.')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'file_name': filename, 'file_path': str(path), 'size': path.stat().st_size, 'checksum': digest,
            'created_at': now.isoformat(), 'previous_status': previous_status}


def safe_backup_path(path):
    validate_storage()
    candidate = Path(path).resolve()
    try:
        candidate.relative_to(BACKUP_ROOT)
    except ValueError:
        raise ValueError('Backup path is outside the configured backup root.')
    return candidate


def validate_storage():
    try:
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        probe = BACKUP_ROOT / '.write_test'
        probe.write_text('ok', encoding='utf-8')
        probe.unlink()
    except OSError as exc:
        raise RuntimeError('Backup storage location is unavailable. Please verify BACKUP_ROOT_PATH configuration.') from exc
