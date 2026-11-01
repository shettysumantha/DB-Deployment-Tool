-- Apply after 20261101_module_endpoint_catalog.sql and database_tool_modules.sql.
-- Add explicit API definitions while preserving the existing endpoint catalog.
ALTER TABLE app_security.modules
    ALTER COLUMN parent_menu_id DROP NOT NULL;

CREATE TABLE IF NOT EXISTS app_security.api_catalog (
    api_id BIGSERIAL PRIMARY KEY,
    api_name VARCHAR(150) NOT NULL,
    api_type VARCHAR(16) NOT NULL CHECK (api_type IN ('INTERNAL', 'EXTERNAL')),
    source_key VARCHAR(500) NOT NULL UNIQUE,
    api_base_url TEXT NOT NULL,
    endpoint_id BIGINT REFERENCES app_security.api_endpoints(endpoint_id) ON DELETE SET NULL,
    manifest_url TEXT,
    health_url TEXT,
    sql_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (api_type, api_name)
);

CREATE TABLE IF NOT EXISTS app_security.module_api_catalog (
    module_id BIGINT PRIMARY KEY REFERENCES app_security.modules(module_id) ON DELETE CASCADE,
    api_id BIGINT NOT NULL REFERENCES app_security.api_catalog(api_id) ON DELETE NO ACTION,
    assigned_by BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_module_api_catalog_api_id
    ON app_security.module_api_catalog(api_id);

-- A module must not retain a navigation assignment to a menu that is hidden.
UPDATE app_security.modules AS module
SET navigation_menu_id = NULL,
    updated_at = CURRENT_TIMESTAMP
FROM app_security.menus AS navigation
WHERE module.navigation_menu_id = navigation.menu_id
  AND module.is_active
  AND NOT navigation.is_active;

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
        OR (u.module_access_configured AND EXISTS (
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
    )
    ORDER BY m.display_order, m.module_name, m.module_id
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 100), 1), 101)
    OFFSET GREATEST(COALESCE(p_offset, 0), 0)
$function$;
