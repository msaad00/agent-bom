-- Upgrade existing Native App installs with privacy-safe endpoint fleet state.
CREATE TABLE IF NOT EXISTS core.fleet_endpoints (
    tenant_id    VARCHAR NOT NULL,
    endpoint_id  VARCHAR NOT NULL,
    completeness VARCHAR NOT NULL,
    updated_at   TIMESTAMP_TZ NOT NULL,
    data         VARIANT NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id)
);
