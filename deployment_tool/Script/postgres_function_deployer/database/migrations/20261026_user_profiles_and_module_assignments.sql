CREATE TABLE IF NOT EXISTS app_security.user_module_access (
    user_id BIGINT NOT NULL REFERENCES app_security.users(user_id) ON DELETE CASCADE,
    module_id BIGINT NOT NULL REFERENCES app_security.modules(module_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, module_id)
);

INSERT INTO app_security.user_module_access (user_id, module_id)
SELECT legacy.user_id, module.module_id
FROM app_security.user_menu_access AS legacy
JOIN app_security.modules AS module
    ON module.navigation_menu_id = legacy.menu_id
ON CONFLICT (user_id, module_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS app_security.user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES app_security.users(user_id) ON DELETE CASCADE,
    mobile_number VARCHAR(32),
    avatar_key VARCHAR(100),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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
    module_ids TEXT
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
                THEN COALESCE(assigned_modules.module_ids, '')
                ELSE COALESCE(inherited_modules.module_ids, '') END
    FROM page_users AS u
    LEFT JOIN LATERAL (
        SELECT string_agg(r.role_name, ', ' ORDER BY r.role_name) AS roles
        FROM app_security.user_roles AS ur
        JOIN app_security.roles AS r ON r.role_id = ur.role_id
        WHERE ur.user_id = u.user_id
    ) AS role_data ON TRUE
    LEFT JOIN LATERAL (
         SELECT string_agg(assigned.module_name, ', ') AS module_names,
             string_agg(assigned.module_id::STRING, ',') AS module_ids
         FROM (
             SELECT m.module_id, m.module_name
             FROM app_security.user_module_access AS a
             JOIN app_security.modules AS m ON m.module_id = a.module_id AND m.is_active
             WHERE a.user_id = u.user_id
             ORDER BY m.module_name, m.module_id
         ) AS assigned
    ) AS assigned_modules ON TRUE
    LEFT JOIN LATERAL (
                  SELECT string_agg(inherited.module_name, ', ') AS module_names,
                      string_agg(inherited.module_id::STRING, ',') AS module_ids
                FROM (
                        SELECT DISTINCT m.module_id, m.module_name
                        FROM app_security.user_roles AS ur
                        JOIN app_security.roles AS r ON r.role_id = ur.role_id AND r.is_active
                        JOIN app_security.role_module_permissions AS p
                            ON p.role_id = r.role_id AND p.can_view
                        JOIN app_security.modules AS m ON m.module_id = p.module_id AND m.is_active
                        WHERE ur.user_id = u.user_id
                ) AS inherited
    ) AS inherited_modules ON TRUE
    ORDER BY LOWER(u.username), u.user_id
$function$;

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
        OR ((NOT u.module_access_configured OR m.navigation_menu_id IS NULL) AND EXISTS (
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
