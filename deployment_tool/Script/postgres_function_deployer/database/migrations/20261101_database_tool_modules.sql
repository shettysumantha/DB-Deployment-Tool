-- Register database tools and the permission-controlled Error Logs menu.
ALTER TABLE app_security.api_endpoints
    ADD COLUMN IF NOT EXISTS endpoint_source VARCHAR(16) NOT NULL DEFAULT 'EXTERNAL'
    CHECK (endpoint_source IN ('INTERNAL', 'EXTERNAL'));

ALTER TABLE public.tbl_errorlogs
    ADD COLUMN IF NOT EXISTS module VARCHAR(150);

ALTER TABLE public.tbl_errorlogs
    ADD COLUMN IF NOT EXISTS operation VARCHAR(500);

INSERT INTO app_security.menus
    (menu_name, menu_code, menu_type, route_path, icon, display_order)
VALUES
    ('Database Health', 'DATABASE_HEALTH', 'INTERNAL', '/database-health', 'database', 3),
    ('SQL Query Tool', 'SQL_QUERY_TOOL', 'INTERNAL', '/database-tools', 'database', 4),
    ('Error Logs', 'ERROR_LOG', 'INTERNAL', '/admin/error-logs', 'history', 7)
ON CONFLICT (menu_code) DO UPDATE SET
    menu_name = EXCLUDED.menu_name,
    menu_type = EXCLUDED.menu_type,
    route_path = EXCLUDED.route_path,
    icon = EXCLUDED.icon,
    is_active = TRUE;

UPDATE app_security.menus AS child
SET parent_menu_id = parent.menu_id
FROM app_security.menus AS parent
WHERE (child.menu_code, parent.menu_code) IN (
    ('DATABASE_HEALTH', 'DATABASE_OPERATIONS'),
    ('SQL_QUERY_TOOL', 'DATABASE_OPERATIONS'),
    ('ERROR_LOG', 'CONFIGURATION')
);

INSERT INTO app_security.role_menu_permissions
    (role_id, menu_id, can_view, can_create, can_edit, can_delete, can_execute)
SELECT role.role_id, menu.menu_id,
       role.role_name = 'ADMIN',
       role.role_name = 'ADMIN',
       role.role_name = 'ADMIN',
       role.role_name = 'ADMIN',
       FALSE
FROM app_security.roles AS role
CROSS JOIN app_security.menus AS menu
WHERE menu.menu_code = 'ERROR_LOG'
ON CONFLICT (role_id, menu_id) DO NOTHING;

UPDATE app_security.role_menu_permissions AS permission
SET can_view = TRUE,
    can_create = TRUE,
    can_edit = TRUE,
    can_delete = TRUE,
    can_execute = FALSE
FROM app_security.roles AS role
JOIN app_security.menus AS menu ON menu.menu_code = 'ERROR_LOG'
WHERE permission.role_id = role.role_id
  AND permission.menu_id = menu.menu_id
  AND role.role_name = 'ADMIN';

INSERT INTO app_security.role_menu_permissions
    (role_id, menu_id, can_view, can_create, can_edit, can_delete, can_execute)
SELECT role.role_id, menu.menu_id,
       TRUE, FALSE, FALSE, FALSE,
       role.role_name IN ('ADMIN', 'DBA', 'DEVELOPER', 'DEPLOYMENT_USER')
FROM app_security.roles AS role
CROSS JOIN app_security.menus AS menu
WHERE menu.menu_code IN ('DATABASE_HEALTH', 'SQL_QUERY_TOOL')
ON CONFLICT (role_id, menu_id) DO NOTHING;
