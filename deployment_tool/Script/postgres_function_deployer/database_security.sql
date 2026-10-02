-- DATABASE PREREQUISITE SCRIPT
-- This script must be executed manually by the DBA.
-- The Flask application does not execute this file at startup.
-- Add required PostgreSQL functions and database objects here.
-- Keep changes safe and idempotent where practical.

CREATE SCHEMA IF NOT EXISTS app_security;

CREATE TABLE IF NOT EXISTS app_security.users (
    user_id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(150),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ
);
ALTER TABLE app_security.users
    ADD COLUMN IF NOT EXISTS module_access_configured BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE app_security.users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE app_security.users
    ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS app_security.roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_security.user_roles (
    user_role_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_security.users(user_id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES app_security.roles(role_id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, role_id)
);
ALTER TABLE app_security.users
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE app_security.users u
SET is_admin = TRUE
WHERE EXISTS (
    SELECT 1
    FROM app_security.user_roles ur
    JOIN app_security.roles r ON r.role_id = ur.role_id
    WHERE ur.user_id = u.user_id AND r.role_name = 'ADMIN'
);
CREATE TABLE IF NOT EXISTS app_security.menus (
    menu_id BIGSERIAL PRIMARY KEY,
    parent_menu_id BIGINT REFERENCES app_security.menus(menu_id) ON DELETE CASCADE,
    menu_name VARCHAR(150) NOT NULL,
    menu_code VARCHAR(100) UNIQUE NOT NULL,
    menu_type VARCHAR(30) NOT NULL DEFAULT 'INTERNAL' CHECK (menu_type IN ('INTERNAL', 'EXTERNAL', 'GROUP')),
    route_path VARCHAR(500),
    external_url VARCHAR(1000),
    icon VARCHAR(100),
    display_order INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    open_in_new_tab BOOLEAN NOT NULL DEFAULT FALSE,
    created_by BIGINT REFERENCES app_security.users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_security.role_menu_permissions (
    permission_id BIGSERIAL PRIMARY KEY,
    role_id BIGINT NOT NULL REFERENCES app_security.roles(role_id) ON DELETE CASCADE,
    menu_id BIGINT NOT NULL REFERENCES app_security.menus(menu_id) ON DELETE CASCADE,
    can_view BOOLEAN NOT NULL DEFAULT FALSE,
    can_create BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete BOOLEAN NOT NULL DEFAULT FALSE,
    can_execute BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (role_id, menu_id)
);
CREATE TABLE IF NOT EXISTS app_security.user_menu_access (
    user_id BIGINT NOT NULL REFERENCES app_security.users(user_id) ON DELETE CASCADE,
    menu_id BIGINT NOT NULL REFERENCES app_security.menus(menu_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, menu_id)
);
CREATE TABLE IF NOT EXISTS app_security.password_reset_tokens (
    reset_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_security.users(user_id) ON DELETE CASCADE,
    token_hash CHAR(64) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_security.audit_logs (
    audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    action VARCHAR(60) NOT NULL,
    target_user_id BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_security.login_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_security.users(user_id),
    username VARCHAR(100), login_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMPTZ, ip_address VARCHAR(100), user_agent TEXT, login_status VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS app_security.configuration_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_security.users(user_id), action_type VARCHAR(50),
    entity_type VARCHAR(100), entity_id BIGINT, old_data JSONB, new_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- DATABASE DOCUMENTATION
-- COMMENT statements are repeatable and document the purpose and references
-- of the existing security tables and columns without changing stored data.
COMMENT ON TABLE app_security.users IS 'Application accounts, authentication state, and per-user security settings.';
COMMENT ON COLUMN app_security.users.user_id IS 'Primary key identifying the account; referenced by user_roles, user_menu_access, password_reset_tokens, audit_logs, login_audit, and configuration_audit.';
COMMENT ON COLUMN app_security.users.username IS 'Unique login name for the account.';
COMMENT ON COLUMN app_security.users.email IS 'Optional unique email address used for account communication and login.';
COMMENT ON COLUMN app_security.users.password_hash IS 'Werkzeug password hash; never store or return the plaintext password.';
COMMENT ON COLUMN app_security.users.full_name IS 'Display name shown for the account.';
COMMENT ON COLUMN app_security.users.is_active IS 'Whether the account may authenticate and access the application.';
COMMENT ON COLUMN app_security.users.created_at IS 'Timestamp when the account was created.';
COMMENT ON COLUMN app_security.users.updated_at IS 'Timestamp of the most recent account update.';
COMMENT ON COLUMN app_security.users.last_login_at IS 'Timestamp of the most recent successful login.';
COMMENT ON COLUMN app_security.users.module_access_configured IS 'True when explicit module assignments in user_menu_access replace inherited module visibility.';
COMMENT ON COLUMN app_security.users.must_change_password IS 'Requires the account to change its password before using other application pages.';
COMMENT ON COLUMN app_security.users.session_version IS 'Incremented to invalidate sessions after account or password security changes.';
COMMENT ON COLUMN app_security.users.is_admin IS 'Administrative account flag; application authorization also checks the active ADMIN role assignment.';

COMMENT ON TABLE app_security.roles IS 'Named application roles used to group users and grant menu permissions.';
COMMENT ON COLUMN app_security.roles.role_id IS 'Primary key referenced by user_roles and role_menu_permissions.';
COMMENT ON COLUMN app_security.roles.role_name IS 'Unique role identifier, such as ADMIN, DBA, or VIEWER.';
COMMENT ON COLUMN app_security.roles.role_description IS 'Human-readable explanation of the role.';
COMMENT ON COLUMN app_security.roles.is_active IS 'Whether users can inherit permissions from this role.';
COMMENT ON COLUMN app_security.roles.created_at IS 'Timestamp when the role was created.';

COMMENT ON TABLE app_security.user_roles IS 'Many-to-many assignments connecting accounts to roles.';
COMMENT ON COLUMN app_security.user_roles.user_role_id IS 'Primary key for a user-to-role assignment.';
COMMENT ON COLUMN app_security.user_roles.user_id IS 'Foreign key to users.user_id; deleting the account cascades to this assignment.';
COMMENT ON COLUMN app_security.user_roles.role_id IS 'Foreign key to roles.role_id; deleting the role cascades to this assignment.';
COMMENT ON COLUMN app_security.user_roles.assigned_at IS 'Timestamp when the role was assigned to the account.';

COMMENT ON TABLE app_security.menus IS 'Application navigation entries and module definitions used by permission checks.';
COMMENT ON COLUMN app_security.menus.menu_id IS 'Primary key referenced by child menus, role_menu_permissions, and user_menu_access.';
COMMENT ON COLUMN app_security.menus.parent_menu_id IS 'Optional self-reference to the parent menu; deleting a parent cascades to its children.';
COMMENT ON COLUMN app_security.menus.menu_name IS 'Display label for the navigation entry.';
COMMENT ON COLUMN app_security.menus.menu_code IS 'Unique stable identifier used by application routes and authorization checks.';
COMMENT ON COLUMN app_security.menus.menu_type IS 'Entry kind: INTERNAL route, EXTERNAL link, or GROUP container.';
COMMENT ON COLUMN app_security.menus.route_path IS 'Internal Flask route used when menu_type is INTERNAL.';
COMMENT ON COLUMN app_security.menus.external_url IS 'Destination URL used when menu_type is EXTERNAL.';
COMMENT ON COLUMN app_security.menus.icon IS 'Icon key consumed by the navigation template.';
COMMENT ON COLUMN app_security.menus.display_order IS 'Sort order among entries sharing the same parent.';
COMMENT ON COLUMN app_security.menus.is_active IS 'Whether the menu is visible and eligible for permission checks.';
COMMENT ON COLUMN app_security.menus.open_in_new_tab IS 'Whether an external menu destination opens in a new browser tab.';
COMMENT ON COLUMN app_security.menus.created_by IS 'Optional foreign key to users.user_id identifying the account that created the menu.';
COMMENT ON COLUMN app_security.menus.created_at IS 'Timestamp when the menu entry was created.';
COMMENT ON COLUMN app_security.menus.updated_at IS 'Timestamp of the most recent menu entry update.';

COMMENT ON TABLE app_security.role_menu_permissions IS 'Per-role capabilities for each menu or application module.';
COMMENT ON COLUMN app_security.role_menu_permissions.permission_id IS 'Primary key for a role-menu permission record.';
COMMENT ON COLUMN app_security.role_menu_permissions.role_id IS 'Foreign key to roles.role_id; deleting the role cascades to its permissions.';
COMMENT ON COLUMN app_security.role_menu_permissions.menu_id IS 'Foreign key to menus.menu_id; deleting the menu cascades to its permissions.';
COMMENT ON COLUMN app_security.role_menu_permissions.can_view IS 'Allows the role to view the menu or module.';
COMMENT ON COLUMN app_security.role_menu_permissions.can_create IS 'Allows the role to create managed records for the menu or module.';
COMMENT ON COLUMN app_security.role_menu_permissions.can_edit IS 'Allows the role to edit managed records for the menu or module.';
COMMENT ON COLUMN app_security.role_menu_permissions.can_delete IS 'Allows the role to delete managed records for the menu or module.';
COMMENT ON COLUMN app_security.role_menu_permissions.can_execute IS 'Allows the role to execute deployment or other controlled actions.';

COMMENT ON TABLE app_security.user_menu_access IS 'Explicit per-user module assignments used after module access has been configured for that account.';
COMMENT ON COLUMN app_security.user_menu_access.user_id IS 'Foreign key to users.user_id and part of the primary key; deleting the account cascades to this assignment.';
COMMENT ON COLUMN app_security.user_menu_access.menu_id IS 'Foreign key to menus.menu_id and part of the primary key; identifies the assigned module.';
COMMENT ON COLUMN app_security.user_menu_access.created_at IS 'Timestamp when the explicit user-module assignment was created.';
COMMENT ON COLUMN app_security.user_menu_access.updated_at IS 'Timestamp of the most recent user-module assignment update.';

COMMENT ON TABLE app_security.password_reset_tokens IS 'Hashed, expiring, single-use credentials for password reset flows.';
COMMENT ON COLUMN app_security.password_reset_tokens.reset_id IS 'Primary key for a password reset token record.';
COMMENT ON COLUMN app_security.password_reset_tokens.user_id IS 'Foreign key to users.user_id; deleting the account cascades to its reset tokens.';
COMMENT ON COLUMN app_security.password_reset_tokens.token_hash IS 'Unique SHA-256 hash of the reset token; the plaintext token is not stored.';
COMMENT ON COLUMN app_security.password_reset_tokens.expires_at IS 'Deadline after which the reset token cannot be used.';
COMMENT ON COLUMN app_security.password_reset_tokens.used_at IS 'Timestamp when the token was consumed; NULL means it has not been used.';
COMMENT ON COLUMN app_security.password_reset_tokens.created_at IS 'Timestamp when the reset token was issued.';

COMMENT ON TABLE app_security.audit_logs IS 'General security and administration audit trail.';
COMMENT ON COLUMN app_security.audit_logs.audit_id IS 'Primary key for the audit event.';
COMMENT ON COLUMN app_security.audit_logs.user_id IS 'Optional foreign key to users.user_id for the actor; set to NULL if that account is deleted.';
COMMENT ON COLUMN app_security.audit_logs.action IS 'Stable event code describing the recorded action.';
COMMENT ON COLUMN app_security.audit_logs.target_user_id IS 'Optional foreign key to users.user_id for the affected account; set to NULL if it is deleted.';
COMMENT ON COLUMN app_security.audit_logs.details IS 'Structured JSONB metadata for the event; should not contain passwords or reset tokens.';
COMMENT ON COLUMN app_security.audit_logs.created_at IS 'Timestamp when the event was recorded.';

COMMENT ON TABLE app_security.login_audit IS 'Login and logout attempts, with request context for security review.';
COMMENT ON COLUMN app_security.login_audit.audit_id IS 'Primary key for the login audit event.';
COMMENT ON COLUMN app_security.login_audit.user_id IS 'Optional foreign key to users.user_id when the account is known.';
COMMENT ON COLUMN app_security.login_audit.username IS 'Submitted or authenticated username associated with the event.';
COMMENT ON COLUMN app_security.login_audit.login_time IS 'Timestamp when the login or logout event was recorded.';
COMMENT ON COLUMN app_security.login_audit.logout_time IS 'Optional timestamp for a separately recorded session logout time.';
COMMENT ON COLUMN app_security.login_audit.ip_address IS 'Client IP address observed by the application, subject to trusted proxy configuration.';
COMMENT ON COLUMN app_security.login_audit.user_agent IS 'HTTP User-Agent supplied with the authentication request.';
COMMENT ON COLUMN app_security.login_audit.login_status IS 'Outcome or type of event, such as SUCCESS, FAILED, or LOGOUT.';

COMMENT ON TABLE app_security.configuration_audit IS 'Audit trail for configuration entity changes.';
COMMENT ON COLUMN app_security.configuration_audit.audit_id IS 'Primary key for the configuration audit event.';
COMMENT ON COLUMN app_security.configuration_audit.user_id IS 'Optional foreign key to users.user_id identifying the actor.';
COMMENT ON COLUMN app_security.configuration_audit.action_type IS 'Operation performed on the configuration, such as create, update, or delete.';
COMMENT ON COLUMN app_security.configuration_audit.entity_type IS 'Kind of configuration entity that changed.';
COMMENT ON COLUMN app_security.configuration_audit.entity_id IS 'Identifier of the changed entity in its owning table; not a foreign key because entity_type varies.';
COMMENT ON COLUMN app_security.configuration_audit.old_data IS 'JSONB snapshot of the entity before the change.';
COMMENT ON COLUMN app_security.configuration_audit.new_data IS 'JSONB snapshot of the entity after the change.';
COMMENT ON COLUMN app_security.configuration_audit.created_at IS 'Timestamp when the configuration change was recorded.';

INSERT INTO app_security.roles (role_name, role_description) VALUES
('ADMIN', 'Full application administration'), ('DEVELOPER', 'Development and deployment access'),
('DBA', 'Database administration access'), ('DEPLOYMENT_USER', 'Database deployment access'),
('VIEWER', 'Read-only access')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO app_security.menus (menu_name, menu_code, menu_type, route_path, icon, display_order) VALUES
('Dashboard', 'DASHBOARD', 'INTERNAL', '/dashboard', 'dashboard', 1),
('Database Operation Module', 'DATABASE_OPERATIONS', 'GROUP', NULL, 'database', 2),
('Deployment Manager', 'DEPLOYMENT_MANAGER', 'INTERNAL', '/deployment', 'deploy', 1),
('DB Compare Tool', 'COMPARISON_RESULTS', 'INTERNAL', '/comparison', 'compare', 2),
('Deployment History', 'DEPLOYMENT_HISTORY', 'INTERNAL', '/history#history', 'history', 3),
('Backup Repository', 'BACKUP_REPOSITORY', 'INTERNAL', '/backups#backups', 'backup', 4),
('Configuration', 'CONFIGURATION', 'GROUP', NULL, 'settings', 3),
('User Management', 'USER_MANAGEMENT', 'INTERNAL', '/admin/users', 'users', 1),
('Role Management', 'ROLE_MANAGEMENT', 'INTERNAL', '/admin/roles', 'shield', 2),
('Menu Management', 'MENU_MANAGEMENT', 'INTERNAL', '/admin/menus', 'menu', 3),
('Role Permissions', 'ROLE_PERMISSIONS', 'INTERNAL', '/admin/permissions', 'lock', 4),
('Database Management', 'DATABASE_MANAGEMENT', 'INTERNAL', '/admin/databases', 'database', 5)
ON CONFLICT (menu_code) DO NOTHING;

UPDATE app_security.menus SET route_path = '/deployment' WHERE menu_code = 'DEPLOYMENT_MANAGER';
UPDATE app_security.menus SET route_path = '/comparison' WHERE menu_code = 'COMPARISON_RESULTS';
UPDATE app_security.menus SET route_path = '/history#history' WHERE menu_code = 'DEPLOYMENT_HISTORY';
UPDATE app_security.menus SET route_path = '/backups#backups' WHERE menu_code = 'BACKUP_REPOSITORY';
UPDATE app_security.menus SET route_path = '/admin/databases' WHERE menu_code = 'DATABASE_MANAGEMENT';

UPDATE app_security.menus child
SET parent_menu_id = parent.menu_id
FROM app_security.menus parent
WHERE (child.menu_code, parent.menu_code) IN (
    ('DEPLOYMENT_MANAGER', 'DATABASE_OPERATIONS'),
    ('COMPARISON_RESULTS', 'DATABASE_OPERATIONS'),
    ('DEPLOYMENT_HISTORY', 'DATABASE_OPERATIONS'),
    ('BACKUP_REPOSITORY', 'DATABASE_OPERATIONS'),
    ('USER_MANAGEMENT', 'CONFIGURATION'),
    ('ROLE_MANAGEMENT', 'CONFIGURATION'),
    ('MENU_MANAGEMENT', 'CONFIGURATION'),
    ('ROLE_PERMISSIONS', 'CONFIGURATION'),
    ('DATABASE_MANAGEMENT', 'CONFIGURATION')
);

UPDATE app_security.menus
SET parent_menu_id = NULL
WHERE menu_code IN ('DEPLOYMENT_MANAGER', 'DEPLOYMENT_HISTORY', 'BACKUP_REPOSITORY');

UPDATE app_security.menus child
SET parent_menu_id = parent.menu_id
FROM app_security.menus parent
WHERE child.menu_code = 'COMPARISON_RESULTS'
    AND parent.menu_code = 'DATABASE_OPERATIONS';

UPDATE app_security.menus
SET menu_name = 'Database Operation Module'
WHERE menu_code = 'DATABASE_OPERATIONS';

UPDATE app_security.menus
SET menu_name = 'DB Compare Tool'
WHERE menu_code = 'COMPARISON_RESULTS';

INSERT INTO app_security.role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete, can_execute)
SELECT r.role_id, m.menu_id,
       (r.role_name = 'ADMIN'
        OR (m.menu_code NOT IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT','ROLE_PERMISSIONS','DATABASE_MANAGEMENT')
            AND (m.menu_code <> 'DEPLOYMENT_MANAGER' OR r.role_name IN ('DBA','DEVELOPER','DEPLOYMENT_USER')))),
    r.role_name = 'ADMIN' AND m.menu_code IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT','DATABASE_MANAGEMENT'),
    r.role_name = 'ADMIN', r.role_name = 'ADMIN' AND m.menu_code IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT','DATABASE_MANAGEMENT'),
       m.menu_code = 'DEPLOYMENT_MANAGER' AND r.role_name IN ('ADMIN','DBA','DEVELOPER','DEPLOYMENT_USER')
FROM app_security.roles r CROSS JOIN app_security.menus m
ON CONFLICT (role_id, menu_id) DO NOTHING;

UPDATE app_security.role_menu_permissions p
SET can_view = (r.role_name = 'ADMIN'),
        can_create = (r.role_name = 'ADMIN'),
        can_edit = (r.role_name = 'ADMIN'),
        can_delete = (r.role_name = 'ADMIN'),
        can_execute = FALSE
FROM app_security.roles r, app_security.menus m
WHERE p.role_id = r.role_id
    AND p.menu_id = m.menu_id
    AND m.menu_code IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT','ROLE_PERMISSIONS','DATABASE_MANAGEMENT');

UPDATE app_security.role_menu_permissions p
SET can_view = (r.role_name IN ('ADMIN','DBA','DEVELOPER','DEPLOYMENT_USER')),
        can_execute = (r.role_name IN ('ADMIN','DBA','DEVELOPER','DEPLOYMENT_USER'))
FROM app_security.roles r, app_security.menus m
WHERE p.role_id = r.role_id
    AND p.menu_id = m.menu_id
    AND m.menu_code = 'DEPLOYMENT_MANAGER';

CREATE INDEX IF NOT EXISTS idx_app_security_user_roles_user ON app_security.user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_app_security_users_username_lower ON app_security.users(LOWER(username), user_id);
CREATE INDEX IF NOT EXISTS idx_app_security_menus_parent ON app_security.menus(parent_menu_id);
CREATE INDEX IF NOT EXISTS idx_app_security_permissions_role ON app_security.role_menu_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_app_security_user_menu_access_user ON app_security.user_menu_access(user_id);
CREATE INDEX IF NOT EXISTS idx_app_security_reset_tokens_user ON app_security.password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_app_security_reset_tokens_expiry ON app_security.password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_app_security_audit_logs_created ON app_security.audit_logs(created_at);

CREATE OR REPLACE FUNCTION app_security.fn_get_users(
    p_limit INTEGER DEFAULT 50,
    p_offset INTEGER DEFAULT 0,
    p_user_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    user_id BIGINT,
    username VARCHAR(100),
    email VARCHAR(255),
    full_name VARCHAR(150),
    is_active BOOLEAN,
    is_admin BOOLEAN,
    created_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    roles TEXT,
    modules TEXT,
    module_ids BIGINT[]
)
LANGUAGE SQL
STABLE
AS $function$
    WITH page_users AS (
        SELECT u.user_id, u.username, u.email, u.full_name, u.is_active,
               u.is_admin, u.created_at, u.last_login_at,
               u.module_access_configured
        FROM app_security.users AS u
        WHERE p_user_id IS NULL OR u.user_id = p_user_id
        ORDER BY LOWER(u.username), u.user_id
        LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 101)
        OFFSET GREATEST(COALESCE(p_offset, 0), 0)
    )
    SELECT u.user_id, u.username, u.email, u.full_name, u.is_active,
           u.is_admin, u.created_at, u.last_login_at,
           COALESCE(role_data.roles, ''),
           CASE WHEN u.module_access_configured
                THEN COALESCE(assigned_modules.module_names, '')
                ELSE COALESCE(inherited_modules.module_names, '') END,
           CASE WHEN u.module_access_configured
                THEN COALESCE(assigned_modules.module_ids, ARRAY[]::BIGINT[])
                ELSE COALESCE(inherited_modules.module_ids, ARRAY[]::BIGINT[]) END
    FROM page_users AS u
    LEFT JOIN LATERAL (
        SELECT string_agg(r.role_name, ', ' ORDER BY r.role_name) AS roles
        FROM app_security.user_roles AS ur
        JOIN app_security.roles AS r ON r.role_id = ur.role_id
        WHERE ur.user_id = u.user_id
    ) AS role_data ON TRUE
    LEFT JOIN LATERAL (
        SELECT string_agg(m.menu_name, ', ' ORDER BY m.menu_name) AS module_names,
               array_agg(a.menu_id ORDER BY a.menu_id) AS module_ids
        FROM app_security.user_menu_access AS a
        LEFT JOIN app_security.menus AS m ON m.menu_id = a.menu_id
        WHERE a.user_id = u.user_id
    ) AS assigned_modules ON TRUE
    LEFT JOIN LATERAL (
        SELECT string_agg(DISTINCT m.menu_name, ', ' ORDER BY m.menu_name) AS module_names,
               array_agg(DISTINCT m.menu_id ORDER BY m.menu_id) AS module_ids
        FROM app_security.user_roles AS ur
        JOIN app_security.roles AS r ON r.role_id = ur.role_id AND r.is_active
        JOIN app_security.role_menu_permissions AS p
          ON p.role_id = r.role_id AND p.can_view
        JOIN app_security.menus AS m
          ON m.menu_id = p.menu_id AND m.is_active AND m.menu_type = 'INTERNAL'
        WHERE ur.user_id = u.user_id
    ) AS inherited_modules ON TRUE
    ORDER BY LOWER(u.username), u.user_id
$function$;
