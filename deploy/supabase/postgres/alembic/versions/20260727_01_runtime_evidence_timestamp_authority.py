"""Make runtime-evidence observation ordering timezone-aware.

Revision ID: 20260727_01
Revises: 20260726_01
"""

from __future__ import annotations

from alembic import op

revision = "20260727_01"
down_revision = "20260726_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Python treats timezone-naive source timestamps as UTC; pin the migration
    # session to the same authority before converting legacy TEXT rows.
    op.execute("SET LOCAL TIME ZONE 'UTC'")
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.runtime_workload_evidence') IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'runtime_workload_evidence'
                     AND column_name = 'observed_at'
                     AND data_type <> 'timestamp with time zone'
               ) THEN
                ALTER TABLE runtime_workload_evidence
                    ALTER COLUMN observed_at TYPE TIMESTAMPTZ
                    USING observed_at::timestamptz;
            END IF;
        END
        $$
        """
    )
    # The evidence table is FORCE RLS. This one-time scrub must cover every
    # tenant before schema v2 is recorded, using the transaction-local bypass
    # honoured by the canonical policy.
    op.execute("SELECT set_config('app.bypass_rls', '1', true)")
    op.execute(
        r"""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM runtime_workload_evidence
                WHERE btrim(tenant_id) = ''
                   OR btrim(provider) = ''
                   OR btrim(account_id) = ''
                   OR btrim(workload_ref) = ''
                   OR btrim(workload_id) = ''
                   OR btrim(source_id) = ''
                   OR btrim(source_kind) = ''
                   OR btrim(dedup_key) = ''
                   OR length(tenant_id) > 256
                   OR length(account_id) > 512
                   OR length(workload_ref) > 2048
                   OR length(workload_id) > 4096
                   OR length(source_id) > 256
                   OR length(source_kind) > 128
                   OR length(dedup_key) > 512
                   OR provider NOT IN ('aws', 'azure', 'gcp')
                   OR signal_type NOT IN (
                       'process_exec', 'ioc_detection', 'network_connection',
                       'file_integrity', 'behavioral_alert'
                   )
                   OR workload_ref ~* (
                       '(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|'
                       '(AKIA|ASIA)[A-Z0-9]{16}|'
                       '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|'
                       'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|'
                       'xox[bpsar]-[A-Za-z0-9-]{10,}|'
                       '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|'
                       '[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|'
                       '(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|'
                       'ya29\.[A-Za-z0-9._-]{20,}|'
                       'sk-(proj-)?[A-Za-z0-9_-]{20,}|'
                       '(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}|'
                       '(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}'
                   )
                   OR workload_id ~* (
                       '(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|'
                       '(AKIA|ASIA)[A-Z0-9]{16}|'
                       '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|'
                       'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|'
                       'xox[bpsar]-[A-Za-z0-9-]{10,}|'
                       '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|'
                       '[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|'
                       '(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|'
                       'ya29\.[A-Za-z0-9._-]{20,}|'
                       'sk-(proj-)?[A-Za-z0-9_-]{20,}|'
                       '(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}|'
                       '(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}'
                   )
                   OR dedup_key ~* (
                       '(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|'
                       '(AKIA|ASIA)[A-Z0-9]{16}|'
                       '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|'
                       'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|'
                       'xox[bpsar]-[A-Za-z0-9-]{10,}|'
                       '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|'
                       '[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|'
                       '(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|'
                       'ya29\.[A-Za-z0-9._-]{20,}|'
                       'sk-(proj-)?[A-Za-z0-9_-]{20,}|'
                       '(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}|'
                       '(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}'
                   )
            ) THEN
                RAISE EXCEPTION 'runtime workload evidence contains unsafe legacy identity rows';
            END IF;
        END
        $$
        """
    )
    # Rebuild the v1 payload from authoritative columns, preserving only the
    # current bounded metadata allowlist. Sensitive metadata is removed (or a
    # title is marked redacted) while unknown top-level fields are discarded.
    op.execute(
        r"""
        WITH normalized AS (
            SELECT
                ctid,
                tenant_id,
                provider,
                account_id,
                workload_ref,
                workload_id,
                signal_type,
                CASE
                    WHEN lower(severity) IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')
                    THEN lower(severity)
                    ELSE 'unknown'
                END AS severity,
                observed_at,
                source_id,
                source_kind,
                dedup_key,
                payload_json::jsonb AS legacy_payload
            FROM runtime_workload_evidence
        ),
        safe_metadata AS (
            SELECT
                normalized.*,
                CASE
                    WHEN COALESCE(legacy_payload->>'title', '') ~* (
                        '(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|'
                        '(AKIA|ASIA)[A-Z0-9]{16}|'
                        '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|'
                        'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|'
                        'xox[bpsar]-[A-Za-z0-9-]{10,}|'
                        '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|'
                        '[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|'
                        '(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|'
                        'ya29\.[A-Za-z0-9._-]{20,}|'
                        'sk-(proj-)?[A-Za-z0-9_-]{20,}|'
                        '(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}|'
                        '(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}|'
                        '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}|'
                        'https?://[^[:space:]]+[?#][^[:space:]]*|'
                        '[[:cntrl:]]'
                    ) THEN '<redacted>'
                    ELSE left(COALESCE(legacy_payload->>'title', ''), 256)
                END AS safe_title,
                COALESCE(
                    (
                        SELECT jsonb_object_agg(entry.key, to_jsonb(left(entry.value #>> '{}', 256)))
                        FROM jsonb_each(
                            CASE
                                WHEN jsonb_typeof(legacy_payload->'evidence') = 'object'
                                THEN legacy_payload->'evidence'
                                ELSE '{}'::jsonb
                            END
                        ) AS entry(key, value)
                        WHERE entry.key IN (
                            'action', 'alert_id', 'alert_ref', 'category', 'count',
                            'destination_ref', 'event_type', 'file_ref', 'hash_ref', 'hash_type',
                            'indicator_ref', 'ioc_type', 'network_ref', 'outcome', 'process_ref',
                            'rule_id', 'rule_ref', 'source_ref', 'tactic_id', 'technique_id'
                        )
                          AND jsonb_typeof(entry.value) IN ('string', 'number', 'boolean')
                          AND NOT (entry.value #>> '{}') ~* (
                              '(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|'
                              '(AKIA|ASIA)[A-Z0-9]{16}|'
                              '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|'
                              'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|'
                              'xox[bpsar]-[A-Za-z0-9-]{10,}|'
                              '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|'
                              '[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|'
                              '(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|'
                              'ya29\.[A-Za-z0-9._-]{20,}|'
                              'sk-(proj-)?[A-Za-z0-9_-]{20,}|'
                              '(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}|'
                              '(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}|'
                              '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}|'
                              'https?://[^[:space:]]+[?#][^[:space:]]*|'
                              '[[:cntrl:]]'
                          )
                    ),
                    '{}'::jsonb
                ) AS safe_evidence
            FROM normalized
        ),
        scrubbed AS (
            SELECT
                ctid,
                jsonb_build_object(
                    'schema_version', 'agent-bom.cwpp.runtime_workload.evidence.v1',
                    'tenant_id', tenant_id,
                    'provider', provider,
                    'account_id', account_id,
                    'workload_ref', workload_ref,
                    'workload_id', workload_id,
                    'signal_type', signal_type,
                    'severity', severity,
                    'observed_at', to_char(observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                    'source_id', source_id,
                    'source_kind', source_kind,
                    'dedup_key', dedup_key,
                    'title', safe_title,
                    'evidence', safe_evidence
                ) AS payload
            FROM safe_metadata
        )
        UPDATE runtime_workload_evidence AS target
        SET payload_json = scrubbed.payload::text
        FROM scrubbed
        WHERE target.ctid = scrubbed.ctid
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('runtime_workload_evidence', 2, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Runtime evidence timestamp authority is intentionally irreversible.")
