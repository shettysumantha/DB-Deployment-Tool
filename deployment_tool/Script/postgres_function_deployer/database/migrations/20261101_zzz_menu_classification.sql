-- Distinguish application navigation from administration using stable menu keys.
ALTER TABLE app_security.menus
    ADD COLUMN IF NOT EXISTS menu_classification VARCHAR(24) NOT NULL
        DEFAULT 'NON_CONFIGURATION'
        CHECK (menu_classification IN ('CONFIGURATION', 'NON_CONFIGURATION'));

ALTER TABLE app_security.modules
    ADD COLUMN IF NOT EXISTS module_classification VARCHAR(24) NOT NULL
        DEFAULT 'NON_CONFIGURATION'
        CHECK (module_classification IN ('CONFIGURATION', 'NON_CONFIGURATION'));

ALTER TABLE app_security.api_catalog
    ADD COLUMN IF NOT EXISTS web_url TEXT;

UPDATE app_security.menus
SET menu_classification = 'CONFIGURATION'
WHERE menu_code IN (
    'CONFIGURATION', 'DATABASE_MANAGEMENT', 'USER_MANAGEMENT', 'ROLE_MANAGEMENT',
    'MENU_MANAGEMENT', 'ROLE_PERMISSIONS', 'MODULE_MANAGEMENT', 'ERROR_LOG'
)
   OR route_path LIKE '/admin/%';

UPDATE app_security.modules AS module
SET module_classification = menu.menu_classification
FROM app_security.menus AS menu
WHERE menu.menu_id = COALESCE(module.navigation_menu_id, module.parent_menu_id);

UPDATE app_security.modules
SET module_classification = 'CONFIGURATION'
WHERE module_code IN (
    'DATABASE_MANAGEMENT', 'USER_MANAGEMENT', 'ROLE_MANAGEMENT',
    'MENU_MANAGEMENT', 'ROLE_PERMISSIONS', 'MODULE_MANAGEMENT', 'ERROR_LOG'
);

DELETE FROM app_security.user_module_access AS assignment
USING app_security.modules AS module
WHERE assignment.module_id = module.module_id
  AND module.module_classification = 'CONFIGURATION';

CREATE OR REPLACE FUNCTION app_security.fn_get_available_modules(
    p_user_id BIGINT,
    p_limit INTEGER DEFAULT 100,
    p_offset INTEGER DEFAULT 0
)
RETURNS TABLE (
    module_id BIGINT,
    module_code VARCHAR(100),
    module_name VARCHAR(150),
    description TEXT,
    version VARCHAR(50),
    module_type VARCHAR(20),
    is_enabled BOOLEAN,
    is_active BOOLEAN,
    web_url TEXT,
    api_base_url TEXT,
    manifest_url TEXT,
    health_url TEXT,
    entry_path TEXT,
    icon VARCHAR(50),
    parent_menu_id BIGINT,
    display_order INTEGER,
    health_status VARCHAR(10),
    last_health_check_at TIMESTAMPTZ,
    capabilities JSONB,
    created_by BIGINT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    parent_menu_name VARCHAR(150)
)
LANGUAGE SQL
STABLE
AS $function$
    SELECT m.module_id, m.module_code, m.module_name, m.description, m.version,
           m.module_type, m.is_enabled, m.is_active, m.web_url, m.api_base_url,
           m.manifest_url, m.health_url, m.entry_path, m.icon, m.parent_menu_id,
           m.display_order, m.health_status, m.last_health_check_at,
           m.capabilities, m.created_by, m.created_at, m.updated_at, parent.menu_name
    FROM app_security.modules AS m
    JOIN app_security.users AS u ON u.user_id = p_user_id AND u.is_active
    LEFT JOIN app_security.menus AS parent ON parent.menu_id = m.parent_menu_id
    WHERE m.is_active AND m.is_enabled AND (
        (u.is_admin AND EXISTS (
            SELECT 1 FROM app_security.user_roles ur
            JOIN app_security.roles r ON r.role_id = ur.role_id
            WHERE ur.user_id = u.user_id AND r.is_active AND r.role_name = 'ADMIN'
        ))
        OR (m.module_classification = 'NON_CONFIGURATION' AND (
            (u.module_access_configured AND EXISTS (
                SELECT 1 FROM app_security.user_module_access uma
                WHERE uma.user_id = u.user_id AND uma.module_id = m.module_id
            ))
            OR (NOT u.module_access_configured AND EXISTS (
                SELECT 1 FROM app_security.user_roles ur
                JOIN app_security.roles r ON r.role_id = ur.role_id AND r.is_active
                JOIN app_security.role_module_permissions p ON p.role_id = r.role_id
                    AND p.module_id = m.module_id AND p.can_view
                WHERE ur.user_id = u.user_id
            ))
        ))
    )
    ORDER BY m.display_order, m.module_name, m.module_id
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 100), 1), 101)
    OFFSET GREATEST(COALESCE(p_offset, 0), 0)
$function$;
