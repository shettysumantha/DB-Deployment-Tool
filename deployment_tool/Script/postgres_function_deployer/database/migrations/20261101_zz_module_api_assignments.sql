-- Keep the API list focused on module APIs and assign the known platform modules.
INSERT INTO app_security.api_catalog
    (api_name, api_type, source_key, api_base_url, endpoint_id, created_by)
SELECT 'DB Compare API', 'INTERNAL', 'INTERNAL:compare', '/api/compare',
       endpoint.endpoint_id, module.created_by
FROM app_security.modules AS module
LEFT JOIN app_security.api_endpoints AS endpoint
  ON endpoint.endpoint_path = '/api/compare' AND endpoint.is_active
WHERE module.module_code = 'DB_COMPARE'
ON CONFLICT (source_key) DO UPDATE SET
    api_name = EXCLUDED.api_name,
    api_base_url = EXCLUDED.api_base_url,
    endpoint_id = EXCLUDED.endpoint_id,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO app_security.api_catalog
    (api_name, api_type, source_key, api_base_url, created_by)
SELECT 'DB Schema Tracker API', 'EXTERNAL',
       'EXTERNAL:MODULE:DB_SCHEMA_TRACKER_1',
       'https://db-schema-tracker-1.onrender.com/api',
       module.created_by
FROM app_security.modules AS module
WHERE module.module_code = 'DB_SCHEMA_TRACKER_1'
ON CONFLICT (source_key) DO UPDATE SET
    api_name = EXCLUDED.api_name,
    api_base_url = EXCLUDED.api_base_url,
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO app_security.module_api_catalog (module_id, api_id)
SELECT module.module_id, api.api_id
FROM app_security.modules AS module
JOIN app_security.api_catalog AS api
  ON api.source_key = 'INTERNAL:compare'
WHERE module.module_code = 'DB_COMPARE'
ON CONFLICT (module_id) DO NOTHING;

INSERT INTO app_security.module_api_catalog (module_id, api_id)
SELECT module.module_id, api.api_id
FROM app_security.modules AS module
JOIN app_security.api_catalog AS api
  ON api.source_key = 'EXTERNAL:MODULE:DB_SCHEMA_TRACKER_1'
WHERE module.module_code = 'DB_SCHEMA_TRACKER_1'
ON CONFLICT (module_id) DO NOTHING;

UPDATE app_security.modules AS module
SET api_base_url = api.api_base_url,
    updated_at = CURRENT_TIMESTAMP
FROM app_security.module_api_catalog AS assignment
JOIN app_security.api_catalog AS api ON api.api_id = assignment.api_id
WHERE assignment.module_id = module.module_id
  AND module.module_code IN ('DB_COMPARE', 'DB_SCHEMA_TRACKER_1')
  AND api.source_key = CASE module.module_code
      WHEN 'DB_COMPARE' THEN 'INTERNAL:compare'
      WHEN 'DB_SCHEMA_TRACKER_1' THEN 'EXTERNAL:MODULE:DB_SCHEMA_TRACKER_1'
  END
  AND (
      module.api_base_url IS NULL
      OR module.api_base_url = ''
      OR (module.module_code = 'DB_COMPARE' AND module.api_base_url = '/api')
      OR module.api_base_url = api.api_base_url
  );
