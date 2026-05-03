-- =============================================================================
-- DCM migration V002 — Snowpark compliance hub procedure
-- =============================================================================
-- Creates core.apply_compliance_hub(), a Snowpark Python stored procedure that
-- reads findings from core.compliance_hub_findings, applies the 14-framework
-- classification table (mirrors compliance_hub.py:select_frameworks), and
-- writes the result to core.findings_by_framework.
--
-- Also creates core.compliance_hub_classify_task — a scheduled task that
-- re-classifies findings hourly.  The consumer must RESUME the task after
-- installation:
--
--   ALTER TASK core.compliance_hub_classify_task RESUME;
--
-- Naming: V<seq>__<description>.sql per DCM convention.
-- Depends on: V001__core_schema.sql (core.compliance_hub_findings,
--             core.findings_by_framework tables must exist).
-- =============================================================================

CREATE OR REPLACE PROCEDURE core.apply_compliance_hub(tenant_id VARCHAR)
    RETURNS OBJECT
    LANGUAGE PYTHON
    RUNTIME_VERSION = '3.11'
    PACKAGES = ('snowflake-snowpark-python')
    HANDLER = 'run'
AS
$$
# ---------------------------------------------------------------------------
# Framework classification table — mirrors compliance_hub.py:select_frameworks
# All 14 slugs in canonical order (same as ALL_FRAMEWORKS tuple).
# ---------------------------------------------------------------------------
_ALL = [
    "owasp-llm", "owasp-mcp", "owasp-agentic", "atlas",
    "nist", "nist-csf", "nist-800-53", "fedramp",
    "eu-ai-act", "iso-27001", "soc2", "cis", "cmmc", "pci-dss",
]

_AI       = {"owasp-llm", "owasp-mcp", "owasp-agentic", "atlas", "nist", "eu-ai-act"}
_ENT      = {"nist-csf", "iso-27001", "soc2"}
_CONT     = {"cis", "nist-csf", "pci-dss", "soc2"}
_CLOUD    = {"cis", "soc2", "iso-27001", "nist-800-53"}

# Source → baseline frameworks
_SRC = {
    "mcp_scan":    _AI,
    "skill":       _AI,
    "proxy":       {"owasp-llm", "owasp-agentic", "atlas"},
    "browser_ext": {"owasp-llm", "atlas"},
    "container":   _CONT,
    "cloud_cis":   _CLOUD,
    "sbom":        {"nist-csf", "soc2", "pci-dss"},
    "sast":        {"nist-csf", "soc2", "pci-dss"},
    "filesystem":  {"cis", "soc2"},
    "external":    set(_ALL),
}

# Asset-type additive refinements
_ASSET = {
    "mcp_server":     _AI,
    "agent":          _AI,
    "tool":           _AI,
    "skill":          _AI,
    "container":      _CONT,
    "cloud_resource": _CLOUD,
    "iac_resource":   {"cis", "nist-800-53", "fedramp"},
}

# Finding-type additive refinements
_FTYPE = {
    "credential_exposure": _ENT,
    "license":             {"nist-csf", "soc2"},
    "injection":           _AI,
    "exfiltration":        _AI | {"soc2"},
    "cis_fail":            {"cis"},
}


def _select_frameworks(source: str, asset_type: str, finding_type: str) -> list:
    selected = set(_SRC.get(source, set()))
    selected |= _ASSET.get(asset_type, set())
    selected |= _FTYPE.get(finding_type, set())
    return [f for f in _ALL if f in selected]


def run(session, tenant_id: str) -> dict:
    rows = session.sql(
        """
        SELECT
            finding_id,
            LOWER(source)                        AS source,
            LOWER(COALESCE(payload:asset_type::VARCHAR,  '')) AS asset_type,
            LOWER(COALESCE(payload:finding_type::VARCHAR,'')) AS finding_type,
            COALESCE(payload:severity::VARCHAR,  '')     AS severity,
            COALESCE(payload:asset:name::VARCHAR,'')     AS asset_name
        FROM core.compliance_hub_findings
        WHERE tenant_id = ?
        """,
        [tenant_id],
    ).collect()

    inserted = 0
    skipped = 0
    for r in rows:
        slugs = _select_frameworks(
            r["SOURCE"], r["ASSET_TYPE"], r["FINDING_TYPE"]
        )
        for slug in slugs:
            result = session.sql(
                """
                MERGE INTO core.findings_by_framework t
                USING (SELECT ? AS fid, ? AS fslug) s
                    ON t.finding_id = s.fid AND t.framework_slug = s.fslug
                WHEN NOT MATCHED THEN
                    INSERT (finding_id, framework_slug, tenant_id,
                            severity, finding_type, asset_type, asset_name,
                            classified_at)
                    VALUES (?, ?, ?,   ?, ?, ?, ?,   CURRENT_TIMESTAMP())
                """,
                [
                    r["FINDING_ID"], slug,
                    r["FINDING_ID"], slug, tenant_id,
                    r["SEVERITY"], r["FINDING_TYPE"],
                    r["ASSET_TYPE"], r["ASSET_NAME"],
                ],
            ).collect()
            # MERGE returns rows_inserted / rows_updated counts
            if result and result[0].get("number of rows inserted", 0):
                inserted += 1
            else:
                skipped += 1

    return {
        "tenant_id":          tenant_id,
        "findings_processed": len(rows),
        "rows_inserted":      inserted,
        "rows_skipped":       skipped,
    }
$$;

GRANT USAGE ON PROCEDURE core.apply_compliance_hub(VARCHAR)
    TO APPLICATION ROLE app_user;

-- ---------------------------------------------------------------------------
-- Hourly scheduled task — consumer must RESUME after installation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE TASK core.compliance_hub_classify_task
    WAREHOUSE = 'COMPUTE_WH'
    SCHEDULE  = 'USING CRON 0 * * * * UTC'
    USER_TASK_TIMEOUT_MS = 300000
AS
    CALL core.apply_compliance_hub('default');

GRANT MONITOR ON TASK core.compliance_hub_classify_task
    TO APPLICATION ROLE app_user;

-- Convenience view: framework posture summary (framework → severity breakdown)
CREATE OR REPLACE VIEW core.compliance_posture AS
SELECT
    framework_slug,
    severity,
    tenant_id,
    COUNT(*) AS finding_count
FROM core.findings_by_framework
GROUP BY framework_slug, severity, tenant_id;

GRANT SELECT ON VIEW core.compliance_posture TO APPLICATION ROLE app_user;

-- =============================================================================
