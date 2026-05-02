"""Cross-provider envelope lock-in matrix (#2083 PR D).

PR A landed the schema, PR B wired every provider, PR C surfaced the envelope
through the API + dashboard. PR D is the lock-in stage: invariant tests that
guard the trust contract against silent drift.

Two classes of invariants:

1. **Least-privilege** -- every entry in a provider's `permissions_used`
   catalog must follow a recognised `<service>:<action>` shape AND must be a
   read-only verb. A future contributor cannot quietly add a write verb
   (e.g. `s3:PutObject`) to a provider's catalog without this matrix
   failing.

2. **Redaction** -- providers that read from a remote surface must declare
   `central_sanitizer_applied`. `not_applicable` is reserved for providers
   that demonstrably never see sensitive values (e.g. local manifest reads).

The matrix runs in pure Python (no SDK mocks required) so it stays fast and
runs on every PR via the standard pytest gate.
"""

from __future__ import annotations

import importlib
import re

import pytest

from agent_bom.discovery_envelope import RedactionStatus, ScanMode

# (module_path, declared_scan_mode, expected_redaction_status)
PROVIDERS: list[tuple[str, ScanMode, RedactionStatus]] = [
    ("agent_bom.cloud.aws", ScanMode.CLOUD_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.gcp", ScanMode.CLOUD_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.azure", ScanMode.CLOUD_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.coreweave", ScanMode.CLOUD_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.nebius", ScanMode.CLOUD_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.snowflake", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.databricks", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.mlflow_provider", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.wandb_provider", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.huggingface", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.openai_provider", ScanMode.SAAS_READ_ONLY, RedactionStatus.CENTRAL_SANITIZER_APPLIED),
    ("agent_bom.cloud.ollama", ScanMode.LOCAL_ONLY, RedactionStatus.NOT_APPLICABLE),
]


# ─── Permission-shape regex ────────────────────────────────────────────────
# Most cloud / SaaS providers use one of:
#   service:Action          (AWS-style)
#   service.resource.verb   (GCP-style)
#   Microsoft.Service/.../verb  (Azure ARM style)
#   service:resource.verb   (Nebius / OpenAI / W&B style)
#   kube:resource.api:verb  (Kubernetes RBAC)
#   INFORMATION_SCHEMA.X:SELECT (Snowflake-style SQL grants)
_PERMISSION_PATTERN = re.compile(
    r"""
    ^(?:
        # GCP-style dotted permission: service.resource.verb
        [a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+){2,}
        |
        # Azure ARM: Microsoft.Service/path/verb
        Microsoft\.[A-Za-z0-9._/]+(?:/[a-z]+)+
        |
        # AWS / Snowflake / kube / SaaS: prefix:Action(.with.dots)?
        [A-Z_][A-Z0-9_.-]*:[A-Z][A-Z_]*
        |
        [a-z][a-z0-9-]*:[A-Z][A-Za-z0-9._]*
        |
        [a-z][a-z0-9-]*:[a-z][a-z0-9._-]*(?::[a-z][a-z0-9._-]*)?
        |
        # MLflow-style: tool:resource:verb
        [a-z][a-z0-9_-]*:[a-z_][a-z0-9_]*:[a-z][a-z_]*
        |
        # Snowflake: INFORMATION_SCHEMA.X:SELECT (allow dotted resource names)
        [A-Z_]+(?:\.[A-Z_][A-Z0-9_]*)+:[A-Z]+
        |
        # HTTP-style permission used by Ollama: "ollama:GET /api/tags"
        [a-z][a-z0-9_-]*:[A-Z]+\s+/[a-z0-9/_-]*
        |
        # Filesystem permission used by Ollama: "filesystem:read manifests"
        filesystem:[a-z]+\s+[a-z]+
    )$
    """,
    re.VERBOSE,
)

# Read-only verb allowlist. Anything outside this set is treated as a write
# / mutation. This is the core "least-privilege" guard.
_READ_VERBS = {
    # SDK-style
    "get",
    "list",
    "describe",
    "search",
    "read",
    "head",
    "view",
    "select",
    "retrieve",
    "show",
    "fetch",
    "scan",
    # AWS / Azure flavour
    "Get",
    "List",
    "Describe",
    "Search",
    "Read",
    "Head",
    "View",
    "Retrieve",
    "Show",
    "Fetch",
    "Scan",
    "BatchGet",
    "BatchList",
    "ListAll",
    "GetAll",
    # SQL
    "SELECT",
    # HTTP
    "GET",
    "HEAD",
    "OPTIONS",
    # Kubernetes RBAC
    "watch",
}


def _extract_verb(perm: str) -> str | None:
    """Pull the trailing verb out of a permission string.

    Strategy: the verb is always the last meaningful segment. Walk the
    perm string from the end, splitting on the most-specific delimiter
    seen, and return the final token. AWS camelCase (`DescribeInstances`)
    is split to extract the leading verb.
    """

    # HTTP: "ollama:GET /api/tags" -> "GET"
    m = re.match(r"^[a-z][a-z0-9_-]*:([A-Z]+)\s", perm)
    if m:
        return m.group(1)
    # Filesystem: "filesystem:read manifests" -> "read"
    m = re.match(r"^filesystem:([a-z]+)", perm)
    if m:
        return m.group(1)

    # Find the last token after splitting on /, :, or . (in that priority).
    last_token: str
    if "/" in perm:
        last_token = perm.rsplit("/", 1)[1]
    elif ":" in perm:
        last_token = perm.rsplit(":", 1)[1]
    elif "." in perm:
        last_token = perm.rsplit(".", 1)[1]
    else:
        last_token = perm

    # Strip trailing args / qualifiers.
    last_token = last_token.split(".")[-1].split(":")[-1].strip()

    if not last_token:
        return None

    # SQL: all-caps, e.g. "SELECT".
    if last_token.isupper() and last_token.replace("_", "").isalpha():
        return last_token
    # AWS camelCase: "DescribeInstances" -> "Describe".
    m = re.match(r"^([A-Z][a-z]+)", last_token)
    if m:
        return m.group(1)
    # Lowercase verb: "list", "search", "get".
    m = re.match(r"^([a-z]+)", last_token)
    if m:
        return m.group(1)
    return None


def _parse_permissions_block(src: str) -> list[str]:
    """Pull every string in a `permissions_used=(...)` tuple out of a source file.

    Skips per-job catalogs (`_AWS_BEDROCK_PERMISSIONS = (...)`); those are
    aggregated by `_aws_permissions_for_jobs` and the union shape is what
    actually flows into the envelope. The aggregated unique values get tested
    end-to-end on AWS via `_aws_permissions_for_jobs`.
    """
    perms: set[str] = set()
    # Match `permissions_used=(...)` blocks (multi-line tuples).
    for match in re.finditer(
        r"permissions_used\s*=\s*\(\s*((?:[^()]|\([^()]*\))*?)\s*\)",
        src,
        re.DOTALL,
    ):
        block = match.group(1)
        for s in re.findall(r'"([^"]+)"', block):
            perms.add(s)
    # AWS uses sorted/aggregated tuples; pull the per-job catalogs too.
    for match in re.finditer(
        r"^_AWS_[A-Z_]+_PERMISSIONS\s*:\s*tuple.*?=\s*\(\s*((?:[^()]|\([^()]*\))*?)\s*\)",
        src,
        re.DOTALL | re.MULTILINE,
    ):
        block = match.group(1)
        for s in re.findall(r'"([^"]+)"', block):
            perms.add(s)
    return sorted(perms)


# ─── Tests ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "module_path,scan_mode,redaction",
    PROVIDERS,
    ids=[p[0].rsplit(".", 1)[-1] for p in PROVIDERS],
)
def test_provider_permissions_match_expected_shape(module_path: str, scan_mode: ScanMode, redaction: RedactionStatus) -> None:
    """Every permission entry follows a known service:action / dotted shape."""
    mod = importlib.import_module(module_path)
    src = open(mod.__file__).read()  # noqa: SIM115
    perms = _parse_permissions_block(src)
    assert perms, f"{module_path} declares no permissions_used"
    bad = [p for p in perms if not _PERMISSION_PATTERN.match(p)]
    assert not bad, (
        f"{module_path} has malformed permissions: {bad}. "
        "Use one of: service:Action (AWS), service.resource.verb (GCP), "
        "Microsoft.Service/.../verb (Azure ARM), service:resource.verb "
        "(SaaS), kube:resource.api:verb (k8s), INFORMATION_SCHEMA.X:SELECT "
        "(Snowflake), or service:HTTP_VERB /path / filesystem:verb noun."
    )


@pytest.mark.parametrize(
    "module_path,scan_mode,redaction",
    PROVIDERS,
    ids=[p[0].rsplit(".", 1)[-1] for p in PROVIDERS],
)
def test_provider_permissions_are_read_only(module_path: str, scan_mode: ScanMode, redaction: RedactionStatus) -> None:
    """Every permission entry is a read-only verb.

    This is the core least-privilege guard. A future contributor cannot
    quietly add `s3:PutObject` or `compute.instances.delete` to a
    provider's catalog without this test failing -- and that failure is the
    signal to either drop the verb or have a deliberate conversation about
    why a write permission is being claimed.
    """
    mod = importlib.import_module(module_path)
    src = open(mod.__file__).read()  # noqa: SIM115
    perms = _parse_permissions_block(src)
    write_verbs: list[tuple[str, str]] = []
    for perm in perms:
        verb = _extract_verb(perm)
        if verb is None:
            # If we can't extract a verb the shape test will catch it.
            continue
        if verb not in _READ_VERBS:
            write_verbs.append((perm, verb))
    assert not write_verbs, (
        f"{module_path} declares non-read permissions: {write_verbs}. "
        "agent-bom is read-only by contract; promote the verb to "
        "`_READ_VERBS` in this test only after confirming the SDK call "
        "the provider issues is genuinely read-only."
    )


@pytest.mark.parametrize(
    "module_path,scan_mode,redaction",
    PROVIDERS,
    ids=[p[0].rsplit(".", 1)[-1] for p in PROVIDERS],
)
def test_provider_redaction_status_matches_expected(module_path: str, scan_mode: ScanMode, redaction: RedactionStatus) -> None:
    """Provider sources literally reference the expected RedactionStatus.

    Cloud / SaaS providers must declare `CENTRAL_SANITIZER_APPLIED` because
    they read raw API responses that may include credentials / PII; the
    central sanitizer in `agent_bom.security` is what scrubs values before
    storage.

    `LOCAL_ONLY` providers (Ollama) declare `NOT_APPLICABLE` because they
    don't read sensitive values to begin with.
    """
    mod = importlib.import_module(module_path)
    src = open(mod.__file__).read()  # noqa: SIM115
    needle = f"RedactionStatus.{redaction.name}"
    assert needle in src, f"{module_path} should declare {needle}"


def test_read_verb_allowlist_is_explicit() -> None:
    """Sanity check on the verb allowlist itself.

    The allowlist is read-only by intent. If someone adds, e.g., 'create' to
    `_READ_VERBS`, that is a deliberate change that should require code
    review explicitly. This test fails if the allowlist starts containing
    obviously-mutation verbs.
    """
    write_signals = {
        "create",
        "delete",
        "put",
        "post",
        "update",
        "modify",
        "remove",
        "destroy",
        "drop",
        "alter",
        "exec",
        "run",
        "invoke",
        "submit",
        "send",
        "rotate",
        "revoke",
        "patch",
        "Create",
        "Delete",
        "Put",
        "Post",
        "Update",
        "Modify",
        "Remove",
        "Destroy",
        "Drop",
        "Alter",
        "Exec",
        "Run",
        "Invoke",
        "Submit",
        "Send",
        "Rotate",
        "Revoke",
        "Patch",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "TRUNCATE",
        "ALTER",
    }
    leak = _READ_VERBS & write_signals
    assert not leak, f"Mutation verbs leaked into _READ_VERBS: {leak}"


def test_provider_table_covers_every_wired_provider() -> None:
    """Catches the case where a new cloud/* provider is wired in PR-B style
    but not added to the PROVIDERS table here -- which would mean the
    least-privilege matrix silently skips it.
    """
    import pkgutil

    import agent_bom.cloud as cloud_pkg

    declared = {p[0] for p in PROVIDERS}
    # Modules that aren't Agent producers -- excluded by intent in PR B.
    exclusions = {
        "agent_bom.cloud.base",
        "agent_bom.cloud.normalization",
        "agent_bom.cloud.resilience",
        "agent_bom.cloud.gpu_infra",
        "agent_bom.cloud.sbom_pull",
        "agent_bom.cloud.model_provenance",
        "agent_bom.cloud.aisvs_benchmark",
        "agent_bom.cloud.aws_cis_benchmark",
        "agent_bom.cloud.azure_cis_benchmark",
        "agent_bom.cloud.gcp_cis_benchmark",
        "agent_bom.cloud.snowflake_cis_benchmark",
        "agent_bom.cloud.cis_remediation",
        "agent_bom.cloud.databricks_security",
        "agent_bom.cloud.snowflake_observability",
        "agent_bom.cloud.clickhouse",
        "agent_bom.cloud.vector_db",
    }
    for info in pkgutil.iter_modules(cloud_pkg.__path__):
        full = f"agent_bom.cloud.{info.name}"
        if full in exclusions:
            continue
        mod = importlib.import_module(full)
        src = open(mod.__file__).read()  # noqa: SIM115
        if "permissions_used=" in src:
            assert full in declared, (
                f"{full} declares permissions_used but is missing from the PROVIDERS table in test_discovery_envelope_lock_in.py"
            )
