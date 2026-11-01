-- Run manually against the application database before using Module Management
-- endpoint registration and error-log viewer. This migration supports CockroachDB.
CREATE SCHEMA IF NOT EXISTS app_security;

CREATE TABLE IF NOT EXISTS app_security.api_endpoints (
    endpoint_id BIGSERIAL PRIMARY KEY,
    endpoint_name VARCHAR(150) NOT NULL,
    endpoint_path TEXT NOT NULL UNIQUE
        CHECK (endpoint_path LIKE '/api/%' AND endpoint_path NOT LIKE '//%'),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_security.module_api_endpoints (
    module_id BIGINT PRIMARY KEY
        REFERENCES app_security.modules(module_id) ON DELETE CASCADE,
    endpoint_id BIGINT NOT NULL
        REFERENCES app_security.api_endpoints(endpoint_id) ON DELETE NO ACTION,
    assigned_by BIGINT REFERENCES app_security.users(user_id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_module_api_endpoints_endpoint_id
    ON app_security.module_api_endpoints(endpoint_id);

CREATE TABLE IF NOT EXISTS public.tbl_errorlogs (
    error_id BIGSERIAL PRIMARY KEY,
    logged_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    log_level VARCHAR(16) NOT NULL,
    error_type VARCHAR(200),
    error_message TEXT NOT NULL,
    endpoint VARCHAR(500),
    http_method VARCHAR(16),
    http_status INTEGER,
    user_id BIGINT,
    username VARCHAR(100),
    request_id VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_tbl_errorlogs_logged_at
    ON public.tbl_errorlogs(logged_at DESC);
