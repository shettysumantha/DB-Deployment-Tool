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

INSERT INTO app_security.roles (role_name, role_description) VALUES
('ADMIN', 'Full application administration'), ('DEVELOPER', 'Development and deployment access'),
('DBA', 'Database administration access'), ('VIEWER', 'Read-only access')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO app_security.menus (menu_name, menu_code, menu_type, route_path, icon, display_order) VALUES
('Dashboard', 'DASHBOARD', 'INTERNAL', '/dashboard', 'dashboard', 1),
('Database Operations', 'DATABASE_OPERATIONS', 'GROUP', NULL, 'database', 2),
('Deployment Manager', 'DEPLOYMENT_MANAGER', 'INTERNAL', '/', 'deploy', 1),
('Deployment History', 'DEPLOYMENT_HISTORY', 'INTERNAL', '/#history', 'history', 2),
('Backup Repository', 'BACKUP_REPOSITORY', 'INTERNAL', '/#backups', 'backup', 3),
('Configuration', 'CONFIGURATION', 'GROUP', NULL, 'settings', 3),
('User Management', 'USER_MANAGEMENT', 'INTERNAL', '/admin/users', 'users', 1),
('Role Management', 'ROLE_MANAGEMENT', 'INTERNAL', '/admin/roles', 'shield', 2),
('Menu Management', 'MENU_MANAGEMENT', 'INTERNAL', '/admin/menus', 'menu', 3),
('Role Permissions', 'ROLE_PERMISSIONS', 'INTERNAL', '/admin/permissions', 'lock', 4)
ON CONFLICT (menu_code) DO NOTHING;

UPDATE app_security.menus child
SET parent_menu_id = parent.menu_id
FROM app_security.menus parent
WHERE (child.menu_code, parent.menu_code) IN (
    ('DEPLOYMENT_MANAGER', 'DATABASE_OPERATIONS'),
    ('DEPLOYMENT_HISTORY', 'DATABASE_OPERATIONS'),
    ('BACKUP_REPOSITORY', 'DATABASE_OPERATIONS'),
    ('USER_MANAGEMENT', 'CONFIGURATION'),
    ('ROLE_MANAGEMENT', 'CONFIGURATION'),
    ('MENU_MANAGEMENT', 'CONFIGURATION'),
    ('ROLE_PERMISSIONS', 'CONFIGURATION')
);

INSERT INTO app_security.role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete, can_execute)
SELECT r.role_id, m.menu_id,
       TRUE, r.role_name = 'ADMIN' AND m.menu_code IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT'),
       r.role_name = 'ADMIN', r.role_name = 'ADMIN' AND m.menu_code IN ('USER_MANAGEMENT','ROLE_MANAGEMENT','MENU_MANAGEMENT'),
       m.menu_code = 'DEPLOYMENT_MANAGER' AND r.role_name IN ('ADMIN','DBA','DEVELOPER')
FROM app_security.roles r CROSS JOIN app_security.menus m
ON CONFLICT (role_id, menu_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_app_security_user_roles_user ON app_security.user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_app_security_menus_parent ON app_security.menus(parent_menu_id);
CREATE INDEX IF NOT EXISTS idx_app_security_permissions_role ON app_security.role_menu_permissions(role_id);
