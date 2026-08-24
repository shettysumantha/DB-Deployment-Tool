import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKUP_ROOT = Path(__import__('os').environ.get('BACKUP_ROOT', BASE_DIR / 'backups')).resolve()


def _safe(value):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', value).strip('_') or 'object'


def create_backup(object_type, record, deployment_id, version, previous_status):
    now = datetime.now(timezone.utc)
    folder = BACKUP_ROOT / ('functions' if object_type == 'FUNCTION' else 'tables') / f'{now:%Y}' / f'{now:%m}'
    folder.mkdir(parents=True, exist_ok=True)
    suffix = record.get('signature', record.get('key', record.get('name', 'object')))
    filename = f'BACKUP_{object_type}_{_safe(suffix)}_{now:%Y%m%d_%H%M%S_%f}.sql'
    path = folder / filename
    definition = record.get('definition', '')
    if not definition:
        return {'file_name': None, 'file_path': None, 'size': None, 'checksum': None}
    path.write_text(f'-- PRE-DEPLOYMENT BACKUP\n-- Deployment: {deployment_id}\n-- Version: {version}\n\n{definition}\n', encoding='utf-8', newline='')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'file_name': filename, 'file_path': str(path), 'size': path.stat().st_size, 'checksum': digest,
            'created_at': now.isoformat(), 'previous_status': previous_status}


def safe_backup_path(path):
    candidate = Path(path).resolve()
    try:
        candidate.relative_to(BACKUP_ROOT)
    except ValueError:
        raise ValueError('Backup path is outside the configured backup root.')
    return candidate
