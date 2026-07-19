"""Operator self-posture — agent-bom audits its OWN deployment hardening.

A product that governs other estates must be able to report the security
posture of its OWN control plane. This module points agent-bom's honesty model
at itself: it reads (never writes) the security-relevant configuration of the
running deployment and reports an honest per-check posture — hardened,
misconfigured, weakened-but-acknowledged, or genuinely unknown.

Design (mirrors :mod:`agent_bom.cloud_sdk_freshness`, the tool's other
self-inspection surface):

    * **Read-only + deterministic.** Inspects environment configuration only.
      It never mutates state, never reaches the network, and never reads a
      secret *value* — only whether a secret is *configured* and *how*
      (literal env vs sealed file/external provider). Reproducible + air-gap
      safe.
    * **Never raises.** A missing or unparseable variable degrades to an
      explicit ``unknown`` status rather than crashing the report.
    * **Honest — no self-flattery.** A check is ``pass`` only with evidence the
      hardened path is actually configured. When production gating cannot be
      evaluated (deployment env undeclared), the dependent checks report
      ``unknown``, never an assumed ``pass``. There is no "we're secure"
      without a concrete, verifiable signal behind it.
    * **Injectable.** :func:`self_posture` accepts an ``env`` mapping so tests
      are deterministic and never depend on the ambient process environment.

Surfaced via ``agent-bom self-audit`` (+ ``--agent-mode`` JSON) and
``GET /v1/self-posture``. Supply-chain / CVE detail is intentionally NOT
re-derived here (that is the job of ``agent-bom scan --self-scan``); this
surface reports the *attack-surface size* as context and points at the scan,
rather than faking a clean CVE result inline.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import cast

SCHEMA_VERSION = 1

# Status vocabulary (honest, four-way — unknown is a first-class outcome):
#   pass    — the hardened configuration is verifiably in effect
#   fail    — a configuration that weakens posture for this deployment mode
#   warn    — a weakened setting that is explicitly acknowledged / dev-scoped
#   unknown — cannot be determined from configuration alone (never a silent pass)
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"
STATUS_UNKNOWN = "unknown"

_PRODUCTION_LABELS = {"prod", "production"}

# Secrets that agent-bom supports supplying as a sealed file reference or via an
# external secret provider, rather than as a literal value in the environment.
# (literal_var, file_var, check_id, human label)
_SEALABLE_SECRETS: tuple[tuple[str, str, str, str], ...] = (
    ("AGENT_BOM_AUDIT_HMAC_KEY", "AGENT_BOM_AUDIT_HMAC_KEY_FILE", "audit_hmac_key", "audit-log HMAC signing key"),
    ("AGENT_BOM_CONNECTIONS_KEY", "AGENT_BOM_CONNECTIONS_KEY_FILE", "connections_key", "connection-secret encryption key"),
)


@dataclass(frozen=True)
class PostureCheck:
    """One self-posture check outcome."""

    id: str
    category: str
    title: str
    status: str
    detail: str
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _truthy(env: Mapping[str, str], key: str) -> bool:
    raw = (env.get(key) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _first_non_empty(env: Mapping[str, str], *keys: str) -> str:
    for key in keys:
        raw = env.get(key)
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    return ""


def _deployment_env(env: Mapping[str, str]) -> str:
    return _first_non_empty(env, "AGENT_BOM_DEPLOYMENT_ENV", "AGENT_BOM_ENV", "ENVIRONMENT").lower()


def _is_production(env: Mapping[str, str]) -> bool:
    return _deployment_env(env) in _PRODUCTION_LABELS


def _replica_count(env: Mapping[str, str]) -> int:
    raw = (env.get("AGENT_BOM_CONTROL_PLANE_REPLICAS") or "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def _check_deployment_env(env: Mapping[str, str]) -> PostureCheck:
    label = _deployment_env(env)
    if not label:
        return PostureCheck(
            id="deployment.env_declared",
            category="deployment",
            title="Deployment environment declared",
            status=STATUS_UNKNOWN,
            detail=(
                "No AGENT_BOM_DEPLOYMENT_ENV / AGENT_BOM_ENV set — production-gated checks cannot be evaluated and are reported as unknown."
            ),
            remediation="Set AGENT_BOM_DEPLOYMENT_ENV=production (or =dev) so posture gating is explicit.",
        )
    return PostureCheck(
        id="deployment.env_declared",
        category="deployment",
        title="Deployment environment declared",
        status=STATUS_PASS,
        detail=f"Deployment declared as '{label}'.",
    )


def _check_api_auth(env: Mapping[str, str]) -> PostureCheck:
    unauth = _truthy(env, "AGENT_BOM_ALLOW_UNAUTHENTICATED_API")
    if not unauth:
        return PostureCheck(
            id="auth.api_authentication",
            category="auth",
            title="API authentication enforced",
            status=STATUS_PASS,
            detail="Unauthenticated API access is disabled (default) — every request must present a credential.",
        )
    production = _is_production(env)
    role = (env.get("AGENT_BOM_NO_AUTH_ROLE") or "viewer").strip() or "viewer"
    if production:
        return PostureCheck(
            id="auth.api_authentication",
            category="auth",
            title="API authentication enforced",
            status=STATUS_FAIL,
            detail=(
                "AGENT_BOM_ALLOW_UNAUTHENTICATED_API is enabled in a production deployment — "
                f"unauthenticated callers are granted the '{role}' role."
            ),
            remediation="Unset AGENT_BOM_ALLOW_UNAUTHENTICATED_API in production and issue scoped API keys.",
        )
    return PostureCheck(
        id="auth.api_authentication",
        category="auth",
        title="API authentication enforced",
        status=STATUS_WARN,
        detail=(
            f"Unauthenticated API access is enabled (non-production) — callers get the '{role}' role. Acceptable only for local/dev use."
        ),
        remediation="Unset AGENT_BOM_ALLOW_UNAUTHENTICATED_API before exposing the API beyond localhost.",
    )


def _check_db_rls(env: Mapping[str, str]) -> PostureCheck:
    bypass = _truthy(env, "AGENT_BOM_ALLOW_SUPERUSER_DB")
    if not bypass:
        return PostureCheck(
            id="database.rls_isolation",
            category="database",
            title="Tenant isolation enforced by the database",
            status=STATUS_UNKNOWN,
            detail=(
                "AGENT_BOM_ALLOW_SUPERUSER_DB is not enabled, but configuration alone cannot "
                "prove that the active database role is non-superuser, lacks BYPASSRLS, and is "
                "subject to the expected Row-Level Security policies."
            ),
            remediation="Verify the active database role and RLS policies against the running database.",
        )
    production = _is_production(env)
    status = STATUS_FAIL if production else STATUS_WARN
    scope = "production deployment" if production else "single-tenant/dev deployment"
    return PostureCheck(
        id="database.rls_isolation",
        category="database",
        title="Tenant isolation enforced by the database",
        status=status,
        detail=(
            f"AGENT_BOM_ALLOW_SUPERUSER_DB is set ({scope}) — a superuser/BYPASSRLS role voids "
            "FORCE ROW LEVEL SECURITY, so tenant isolation is NOT enforced by the database."
        ),
        remediation="Connect the control plane with a non-superuser role that cannot BYPASSRLS, then unset AGENT_BOM_ALLOW_SUPERUSER_DB.",
    )


def _check_audit_hmac(env: Mapping[str, str]) -> PostureCheck:
    configured = bool(_first_non_empty(env, "AGENT_BOM_AUDIT_HMAC_KEY", "AGENT_BOM_AUDIT_HMAC_KEY_FILE"))
    production = _is_production(env)
    clustered = _replica_count(env) > 1
    required = production or clustered
    ephemeral_allowed = _truthy(env, "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC")
    require_flag = _truthy(env, "AGENT_BOM_REQUIRE_AUDIT_HMAC")

    if configured:
        return PostureCheck(
            id="audit.hmac_integrity",
            category="governance",
            title="Audit-log integrity signing configured",
            status=STATUS_PASS,
            detail=(
                "A persistent audit-log HMAC signing key is configured — the tamper-evident "
                "hash chain survives restarts and is consistent across replicas."
            ),
        )
    if (required or require_flag) and not ephemeral_allowed:
        why = "production" if production else "a multi-replica control plane" if clustered else "AGENT_BOM_REQUIRE_AUDIT_HMAC"
        return PostureCheck(
            id="audit.hmac_integrity",
            category="governance",
            title="Audit-log integrity signing configured",
            status=STATUS_FAIL,
            detail=(
                f"No audit-log HMAC signing key is configured but this deployment ({why}) requires "
                "one — the audit chain would use an ephemeral per-process key that cannot be verified "
                "across restarts/replicas."
            ),
            remediation="Set AGENT_BOM_AUDIT_HMAC_KEY_FILE (preferred) or AGENT_BOM_AUDIT_HMAC_KEY to a durable secret.",
        )
    if required and ephemeral_allowed:
        return PostureCheck(
            id="audit.hmac_integrity",
            category="governance",
            title="Audit-log integrity signing configured",
            status=STATUS_WARN,
            detail=(
                "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC is set — the audit chain uses a per-process key "
                "that is not verifiable across restarts/replicas. Acknowledged, but weakens tamper-evidence."
            ),
            remediation="Configure a durable AGENT_BOM_AUDIT_HMAC_KEY_FILE and unset AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC.",
        )
    return PostureCheck(
        id="audit.hmac_integrity",
        category="governance",
        title="Audit-log integrity signing configured",
        status=STATUS_UNKNOWN,
        detail=(
            "No audit-log HMAC signing key is configured. Not required for this non-production "
            "single-process deployment, so the audit chain runs with a per-process key."
        ),
        remediation="Set AGENT_BOM_AUDIT_HMAC_KEY_FILE before promoting this instance to production or scaling to multiple replicas.",
    )


def _check_secret_sealing(env: Mapping[str, str]) -> list[PostureCheck]:
    external = _truthy(env, "AGENT_BOM_EXTERNAL_SECRETS_ENABLED")
    checks: list[PostureCheck] = []
    for literal_var, file_var, check_id, label in _SEALABLE_SECRETS:
        has_literal = bool((env.get(literal_var) or "").strip())
        has_file = bool((env.get(file_var) or "").strip())
        title = f"Secret sealed via file/provider — {label}"
        if has_literal:
            checks.append(
                PostureCheck(
                    id=f"secrets.{check_id}",
                    category="secrets",
                    title=title,
                    status=STATUS_WARN,
                    detail=(
                        f"The {label} is set as a literal environment value ({literal_var}) — "
                        "readable to anything that can inspect the process environment."
                    ),
                    remediation=f"Remove {literal_var} and use only {file_var} (mounted secret file).",
                )
            )
        elif has_file:
            checks.append(
                PostureCheck(
                    id=f"secrets.{check_id}",
                    category="secrets",
                    title=title,
                    status=STATUS_PASS,
                    detail=f"The {label} is configured through a file reference, not a literal environment value.",
                )
            )
        else:
            external_note = (
                " External-secrets integration is enabled, but that deployment-level flag does not prove this specific secret is populated."
                if external
                else ""
            )
            checks.append(
                PostureCheck(
                    id=f"secrets.{check_id}",
                    category="secrets",
                    title=title,
                    status=STATUS_UNKNOWN,
                    detail=f"No file or literal configuration for the {label} is visible, so sealing cannot be assessed.{external_note}",
                    remediation=f"When you configure it, prefer {file_var} over a literal {literal_var}.",
                )
            )
    return checks


def _supply_chain_context(env: Mapping[str, str], distribution_count: int | None) -> PostureCheck:
    if distribution_count is None:
        return PostureCheck(
            id="supply_chain.dependency_surface",
            category="supply_chain",
            title="Dependency / supply-chain surface",
            status=STATUS_UNKNOWN,
            detail="Installed-distribution count could not be enumerated.",
            remediation="Run `agent-bom scan --self-scan` for the full dependency CVE / malicious-package posture.",
        )
    return PostureCheck(
        id="supply_chain.dependency_surface",
        category="supply_chain",
        title="Dependency / supply-chain surface",
        status=STATUS_UNKNOWN,
        detail=(
            f"{distribution_count} Python distributions are installed in this environment "
            "(attack-surface size). CVE / malicious-package posture is not evaluated inline."
        ),
        remediation="Run `agent-bom scan --self-scan` to evaluate the dependency CVE and malicious-package posture honestly.",
    )


def audit_chain_integrity_check(chain: Mapping[str, int] | None) -> PostureCheck:
    """Honest posture for the tenant's governance audit hash-chain.

    ``chain`` is the ``{"verified", "tampered", "checked"}`` result of
    :meth:`agent_bom.api.governance_audit_log.GovernanceAuditLog.verify_chain`
    for one tenant. The check reconciles to that single source of truth — the
    numbers here are never re-derived independently:

        * ``None``     — not evaluated in this (config-only) context; an honest
          ``unknown`` that points at the tenant-scoped surface, never an implied
          pass.
        * ``checked == 0`` — no governance lifecycle actions recorded yet, so the
          tamper-evident chain has nothing to verify. Absence of a signal is
          reported as ``unknown``, NEVER as healthy/hardened (§7/§11).
        * ``tampered > 0`` — the chain is broken or forked → ``fail`` with
          remediation.
        * otherwise — every record verifies → ``pass``.
    """
    check_id = "governance.audit_chain_integrity"
    title = "Governance audit-chain integrity verified"
    if chain is None:
        return PostureCheck(
            id=check_id,
            category="governance",
            title=title,
            status=STATUS_UNKNOWN,
            detail=(
                "The tenant-scoped governance audit hash-chain is verified against the durable "
                "audit store by the tenant-aware API/UI; it was not evaluated in this context."
            ),
            remediation="Query GET /v1/self-posture (tenant-scoped) or the Self-Audit page for the live audit-chain integrity result.",
        )
    checked = int(chain.get("checked", 0))
    tampered = int(chain.get("tampered", 0))
    verified = int(chain.get("verified", 0))
    if checked == 0:
        return PostureCheck(
            id=check_id,
            category="governance",
            title=title,
            status=STATUS_UNKNOWN,
            detail=(
                "No governance lifecycle actions have been recorded for this tenant yet, so the "
                "tamper-evident audit chain has nothing to verify. This is not evidence the chain is healthy."
            ),
            remediation="Integrity is reported once the NHI governance loop records its first audited action for this tenant.",
        )
    if tampered > 0:
        return PostureCheck(
            id=check_id,
            category="governance",
            title=title,
            status=STATUS_FAIL,
            detail=(
                f"{tampered} of {checked} governance audit records fail hash-chain verification — the "
                "tamper-evident chain is broken or forked."
            ),
            remediation=(
                "Investigate the governance audit store: a forked chain can indicate concurrent multi-writer "
                "corruption or tampering. Use the Postgres backend for a single durable per-tenant chain across replicas."
            ),
        )
    return PostureCheck(
        id=check_id,
        category="governance",
        title=title,
        status=STATUS_PASS,
        detail=(
            f"All {verified} governance audit records verify against the tamper-evident hash chain — "
            "no tampering or forks detected for this tenant."
        ),
    )


def _count_installed_distributions() -> int | None:
    try:
        import importlib.metadata as metadata

        seen: set[str] = set()
        for dist in metadata.distributions():
            try:
                name = str(dist.metadata["Name"] or "").strip().lower()
            except Exception:
                name = ""
            if name:
                seen.add(name)
        return len(seen)
    except Exception:
        return None


_AUTO = object()
_OMIT_AUDIT_CHAIN = object()


def self_posture(
    env: Mapping[str, str] | None = None,
    *,
    distribution_count: int | None | object = _AUTO,
    audit_chain: Mapping[str, int] | None | object = _OMIT_AUDIT_CHAIN,
) -> dict[str, object]:
    """Return an honest self-posture report for this agent-bom deployment.

    ``env`` defaults to the process environment; pass a mapping for
    deterministic tests. ``distribution_count`` defaults to enumerating the
    installed distributions; pass an int, or ``None`` to force an
    unknown supply-chain context row in tests.

    ``audit_chain`` adds the tenant-scoped governance audit-chain integrity
    check (see :func:`audit_chain_integrity_check`). Omit it — the default —
    for the config-only report every surface has always returned. Tenant-aware
    surfaces (the API/UI) pass the tenant's ``verify_chain`` result (a mapping),
    or ``None`` when the chain could not be read; config-only surfaces (the CLI)
    pass ``None`` so the dimension shows as an honest unknown rather than being
    silently dropped.
    """
    resolved_env: Mapping[str, str] = os.environ if env is None else env
    if distribution_count is _AUTO:
        dist_count: int | None = _count_installed_distributions()
    else:
        dist_count = distribution_count  # type: ignore[assignment]

    governance_checks: list[PostureCheck] = [_check_audit_hmac(resolved_env)]
    if audit_chain is not _OMIT_AUDIT_CHAIN:
        governance_checks.append(
            audit_chain_integrity_check(cast("Mapping[str, int] | None", audit_chain))
        )

    checks: list[PostureCheck] = [
        _check_deployment_env(resolved_env),
        _check_api_auth(resolved_env),
        _check_db_rls(resolved_env),
        *governance_checks,
        *_check_secret_sealing(resolved_env),
        _supply_chain_context(resolved_env, dist_count),
    ]

    counts = {
        STATUS_PASS: 0,
        STATUS_FAIL: 0,
        STATUS_WARN: 0,
        STATUS_UNKNOWN: 0,
    }
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1

    if counts[STATUS_FAIL] > 0:
        overall = "at_risk"
    elif counts[STATUS_WARN] > 0:
        overall = "action_advised"
    elif counts[STATUS_UNKNOWN] > 0:
        overall = "needs_review"
    else:
        overall = "hardened"

    return {
        "schema_version": SCHEMA_VERSION,
        "overall_status": overall,
        "hardened": overall == "hardened",
        "deployment_env": _deployment_env(resolved_env) or "unknown",
        "counts": counts,
        "checks": [check.to_dict() for check in checks],
    }
