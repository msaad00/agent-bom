"""CWE-aware impact classification for blast radius accuracy.

Maps CWE weakness types to impact categories that determine which
credentials and tools a vulnerability can realistically reach.
A CWE-79 (XSS) client-side bug does not expose server-side DATABASE_URL.
A CWE-94 (code injection) RCE does.

Conservative default: when CWE data is missing, assume worst case
(code-execution) so no risk is hidden.
"""

from __future__ import annotations

from typing import Optional

# ── Impact categories ────────────────────────────────────────────────────────
#
# Each category describes what a vulnerability *can* reach on the server
# where the vulnerable package runs.
#
#   code-execution   — attacker runs arbitrary code → full env/file/tool access
#   credential-access — direct credential compromise (auth bypass, hardcoded)
#   file-access      — read/write files on disk → can read config/env files
#   injection        — inject into DB/LDAP/etc → DB credential scope
#   ssrf             — forge requests to internal services
#   data-leak        — information disclosure → possible credential exposure
#   availability     — denial of service → no credential access
#   client-side      — browser-side only → no server credential access

IMPACT_CODE_EXECUTION = "code-execution"
IMPACT_CREDENTIAL_ACCESS = "credential-access"
IMPACT_FILE_ACCESS = "file-access"
IMPACT_INJECTION = "injection"
IMPACT_SSRF = "ssrf"
IMPACT_DATA_LEAK = "data-leak"
IMPACT_AVAILABILITY = "availability"
IMPACT_CLIENT_SIDE = "client-side"

# Ordered from most to least severe — used for worst-case selection
_IMPACT_SEVERITY_ORDER = [
    IMPACT_CODE_EXECUTION,
    IMPACT_CREDENTIAL_ACCESS,
    IMPACT_FILE_ACCESS,
    IMPACT_SSRF,
    IMPACT_INJECTION,
    IMPACT_DATA_LEAK,
    IMPACT_AVAILABILITY,
    IMPACT_CLIENT_SIDE,
]

# ── CWE → Impact mapping ────────────────────────────────────────────────────
#
# Sources: MITRE CWE, NVD, OWASP Top 10
# Only maps CWEs that appear in real-world OSV/NVD/GHSA advisories.

CWE_IMPACT_CATEGORIES: dict[str, str] = {
    # Code execution — full server access
    "CWE-77": IMPACT_CODE_EXECUTION,  # Command injection
    "CWE-78": IMPACT_CODE_EXECUTION,  # OS command injection
    "CWE-94": IMPACT_CODE_EXECUTION,  # Code injection
    "CWE-95": IMPACT_CODE_EXECUTION,  # Eval injection
    "CWE-96": IMPACT_CODE_EXECUTION,  # Static code injection
    "CWE-98": IMPACT_CODE_EXECUTION,  # PHP remote file inclusion
    "CWE-502": IMPACT_CODE_EXECUTION,  # Deserialization of untrusted data
    "CWE-787": IMPACT_CODE_EXECUTION,  # Out-of-bounds write
    "CWE-788": IMPACT_CODE_EXECUTION,  # Out-of-bounds write (buffer end)
    "CWE-416": IMPACT_CODE_EXECUTION,  # Use after free
    "CWE-119": IMPACT_CODE_EXECUTION,  # Buffer overflow
    "CWE-120": IMPACT_CODE_EXECUTION,  # Classic buffer overflow
    "CWE-122": IMPACT_CODE_EXECUTION,  # Heap-based buffer overflow
    "CWE-125": IMPACT_CODE_EXECUTION,  # Out-of-bounds read (can chain to RCE)
    "CWE-190": IMPACT_CODE_EXECUTION,  # Integer overflow
    "CWE-434": IMPACT_CODE_EXECUTION,  # Unrestricted file upload
    "CWE-917": IMPACT_CODE_EXECUTION,  # Expression language injection
    "CWE-1321": IMPACT_CODE_EXECUTION,  # Prototype pollution
    "CWE-913": IMPACT_CODE_EXECUTION,  # Improper control of dynamic code
    # Credential access — direct credential compromise
    "CWE-287": IMPACT_CREDENTIAL_ACCESS,  # Improper authentication
    "CWE-306": IMPACT_CREDENTIAL_ACCESS,  # Missing authentication
    "CWE-307": IMPACT_CREDENTIAL_ACCESS,  # Brute force
    "CWE-347": IMPACT_CREDENTIAL_ACCESS,  # Signature verification
    "CWE-384": IMPACT_CREDENTIAL_ACCESS,  # Session fixation
    "CWE-522": IMPACT_CREDENTIAL_ACCESS,  # Insufficiently protected credentials
    "CWE-798": IMPACT_CREDENTIAL_ACCESS,  # Hardcoded credentials
    "CWE-862": IMPACT_CREDENTIAL_ACCESS,  # Missing authorization
    "CWE-863": IMPACT_CREDENTIAL_ACCESS,  # Incorrect authorization
    "CWE-1259": IMPACT_CREDENTIAL_ACCESS,  # Improper restriction of security token
    # File access — can read/write files on disk
    "CWE-22": IMPACT_FILE_ACCESS,  # Path traversal
    "CWE-23": IMPACT_FILE_ACCESS,  # Relative path traversal
    "CWE-36": IMPACT_FILE_ACCESS,  # Absolute path traversal
    "CWE-59": IMPACT_FILE_ACCESS,  # Symlink following
    "CWE-73": IMPACT_FILE_ACCESS,  # External control of file name
    "CWE-67": IMPACT_FILE_ACCESS,  # Improper handling of Windows device names
    # Injection — DB/LDAP/template injection
    "CWE-89": IMPACT_INJECTION,  # SQL injection
    "CWE-90": IMPACT_INJECTION,  # LDAP injection
    "CWE-91": IMPACT_INJECTION,  # XML injection
    "CWE-943": IMPACT_INJECTION,  # Improper neutralization in data query
    "CWE-1236": IMPACT_INJECTION,  # CSV injection
    # SSRF — server-side request forgery
    "CWE-918": IMPACT_SSRF,  # SSRF
    # Data leak — information disclosure
    "CWE-200": IMPACT_DATA_LEAK,  # Exposure of sensitive information
    "CWE-209": IMPACT_DATA_LEAK,  # Error message information exposure
    "CWE-215": IMPACT_DATA_LEAK,  # Debug information exposure
    "CWE-532": IMPACT_DATA_LEAK,  # Insertion of sensitive info into log
    "CWE-538": IMPACT_DATA_LEAK,  # Insertion of sensitive info into file
    "CWE-312": IMPACT_DATA_LEAK,  # Cleartext storage of sensitive info
    "CWE-319": IMPACT_DATA_LEAK,  # Cleartext transmission
    "CWE-327": IMPACT_DATA_LEAK,  # Broken/risky crypto algorithm
    "CWE-326": IMPACT_DATA_LEAK,  # Inadequate encryption strength
    "CWE-330": IMPACT_DATA_LEAK,  # Insufficient randomness
    "CWE-331": IMPACT_DATA_LEAK,  # Insufficient entropy
    "CWE-338": IMPACT_DATA_LEAK,  # Weak PRNG
    # Availability — denial of service
    "CWE-400": IMPACT_AVAILABILITY,  # Uncontrolled resource consumption
    "CWE-770": IMPACT_AVAILABILITY,  # Allocation without limits
    "CWE-674": IMPACT_AVAILABILITY,  # Uncontrolled recursion
    "CWE-834": IMPACT_AVAILABILITY,  # Excessive iteration
    "CWE-835": IMPACT_AVAILABILITY,  # Infinite loop
    "CWE-1333": IMPACT_AVAILABILITY,  # ReDoS
    "CWE-410": IMPACT_AVAILABILITY,  # Insufficient resource pool
    "CWE-404": IMPACT_AVAILABILITY,  # Resource leak
    "CWE-407": IMPACT_AVAILABILITY,  # Algorithmic complexity
    "CWE-409": IMPACT_AVAILABILITY,  # Improper handling of compressed data
    # Client-side — does not affect server credentials
    "CWE-79": IMPACT_CLIENT_SIDE,  # XSS
    "CWE-80": IMPACT_CLIENT_SIDE,  # Basic XSS
    "CWE-352": IMPACT_CLIENT_SIDE,  # CSRF
    "CWE-601": IMPACT_CLIENT_SIDE,  # Open redirect
    "CWE-1021": IMPACT_CLIENT_SIDE,  # Clickjacking
    "CWE-524": IMPACT_CLIENT_SIDE,  # Sensitive info in cache
    "CWE-539": IMPACT_CLIENT_SIDE,  # Session cookie in persistent storage
    "CWE-614": IMPACT_CLIENT_SIDE,  # Sensitive cookie without secure flag
    "CWE-1004": IMPACT_CLIENT_SIDE,  # Sensitive cookie without HttpOnly
    "CWE-1275": IMPACT_CLIENT_SIDE,  # Sensitive cookie with SameSite=None
    # Input validation — ambiguous, treat as data-leak (conservative mid-ground)
    "CWE-20": IMPACT_DATA_LEAK,  # Improper input validation
    "CWE-116": IMPACT_DATA_LEAK,  # Improper encoding/escaping
    "CWE-173": IMPACT_DATA_LEAK,  # Improper handling of alternate encoding
    "CWE-670": IMPACT_DATA_LEAK,  # Always-incorrect control flow
    "CWE-754": IMPACT_DATA_LEAK,  # Improper check for exceptional conditions
    "CWE-1286": IMPACT_DATA_LEAK,  # Improper validation of syntactic correctness
}


def classify_cwe_impact(cwe_ids: list[str]) -> str:
    """Classify the worst-case impact category from a list of CWE IDs.

    Returns the most severe impact category found. If no CWE data is
    available, returns ``code-execution`` (conservative default — we don't
    hide risk we can't disprove).
    """
    if not cwe_ids:
        return IMPACT_CODE_EXECUTION

    best_rank = len(_IMPACT_SEVERITY_ORDER)
    for cwe in cwe_ids:
        cwe_upper = cwe.upper() if not cwe.startswith("CWE-") else cwe
        category = CWE_IMPACT_CATEGORIES.get(cwe_upper)
        if category is not None:
            rank = _IMPACT_SEVERITY_ORDER.index(category)
            if rank < best_rank:
                best_rank = rank

    if best_rank < len(_IMPACT_SEVERITY_ORDER):
        return _IMPACT_SEVERITY_ORDER[best_rank]

    # CWE IDs present but none recognized — conservative default
    return IMPACT_CODE_EXECUTION


# ── Credential filters ───────────────────────────────────────────────────────
#
# Patterns for identifying credential types by env var name.

_DB_CREDENTIAL_PATTERNS = frozenset(
    {
        "database",
        "db_",
        "mysql",
        "postgres",
        "mongo",
        "redis",
        "dsn",
        "sql",
        "clickhouse",
        "snowflake",
        "supabase",
    }
)


def _is_db_credential(name: str) -> bool:
    """Check if a credential name looks database-related."""
    lower = name.lower()
    return any(pat in lower for pat in _DB_CREDENTIAL_PATTERNS)


def filter_credentials_by_impact(
    category: str,
    all_credentials: list[str],
) -> list[str]:
    """Filter exposed credentials based on CWE impact category.

    Returns only credentials that the vulnerability type can realistically
    reach. For categories that don't affect server-side state (client-side,
    availability), returns an empty list.

    Args:
        category: Impact category from :func:`classify_cwe_impact`.
        all_credentials: Full list of credentials from the MCP server config.

    Returns:
        Filtered list of credentials actually at risk.
    """
    if not all_credentials:
        return []

    if category in (IMPACT_CODE_EXECUTION, IMPACT_CREDENTIAL_ACCESS, IMPACT_DATA_LEAK):
        # Full access — can read env vars, config files, or disclose data
        return list(all_credentials)

    if category == IMPACT_FILE_ACCESS:
        # Can read config files — all credentials potentially in .env or config
        return list(all_credentials)

    if category == IMPACT_SSRF:
        # Can reach internal services — all credentials potentially usable
        return list(all_credentials)

    if category == IMPACT_INJECTION:
        # DB injection — only DB credentials are in scope
        return [c for c in all_credentials if _is_db_credential(c)]

    if category in (IMPACT_AVAILABILITY, IMPACT_CLIENT_SIDE):
        # No server-side credential access
        return []

    # Unknown category — conservative default
    return list(all_credentials)


def filter_tools_by_impact(
    category: str,
    all_tools: list,
) -> list:
    """Filter exposed tools based on CWE impact category.

    Returns only tools that the vulnerability type can realistically invoke.

    Args:
        category: Impact category from :func:`classify_cwe_impact`.
        all_tools: Full list of MCPTool objects from the server.

    Returns:
        Filtered list of tools actually reachable.
    """
    if not all_tools:
        return []

    if category in (IMPACT_CODE_EXECUTION, IMPACT_CREDENTIAL_ACCESS):
        # Full access — can invoke any tool
        return list(all_tools)

    if category in (IMPACT_FILE_ACCESS, IMPACT_SSRF, IMPACT_DATA_LEAK):
        # Partial access — can potentially invoke tools
        return list(all_tools)

    if category == IMPACT_INJECTION:
        # DB injection — only DB/query tools
        db_keywords = {"query", "sql", "execute", "database", "db", "select", "insert"}
        return [t for t in all_tools if any(kw in t.name.lower() for kw in db_keywords)]

    if category in (IMPACT_AVAILABILITY, IMPACT_CLIENT_SIDE):
        # No tool access
        return []

    return list(all_tools)


def build_attack_vector_summary(
    cwe_ids: list[str],
    category: str,
    filtered_creds: list[str],
    filtered_tools: list,
    severity: Optional[str] = None,
    is_kev: bool = False,
) -> str:
    """Build a human-readable attack vector summary.

    Returns a one-sentence description of what this vulnerability enables
    in the context of the MCP server it runs in.
    """
    cwe_str = cwe_ids[0] if cwe_ids else "Unknown CWE"
    n_creds = len(filtered_creds)
    n_tools = len(filtered_tools)

    kev_prefix = "Actively exploited. " if is_kev else ""

    summaries = {
        IMPACT_CODE_EXECUTION: (
            f"{kev_prefix}Code execution ({cwe_str}) grants full server access"
            + (f": {n_creds} credential(s) and {n_tools} tool(s) reachable." if n_creds or n_tools else ".")
        ),
        IMPACT_CREDENTIAL_ACCESS: (
            f"{kev_prefix}Authentication bypass ({cwe_str}) enables direct credential compromise"
            + (f": {n_creds} credential(s) at risk." if n_creds else ".")
        ),
        IMPACT_FILE_ACCESS: (
            f"{kev_prefix}File access ({cwe_str}) may expose configuration and credentials"
            + (f": {n_creds} credential(s) potentially readable." if n_creds else ".")
        ),
        IMPACT_INJECTION: (
            f"{kev_prefix}Injection ({cwe_str}) targets data stores" + (f": {n_creds} database credential(s) in scope." if n_creds else ".")
        ),
        IMPACT_SSRF: (
            f"{kev_prefix}SSRF ({cwe_str}) enables internal service access" + (f": {n_creds} credential(s) reachable." if n_creds else ".")
        ),
        IMPACT_DATA_LEAK: (
            f"{kev_prefix}Information disclosure ({cwe_str}) may expose sensitive data"
            + (f": {n_creds} credential(s) potentially visible." if n_creds else ".")
        ),
        IMPACT_AVAILABILITY: (
            f"{kev_prefix}Denial of service ({cwe_str}) may disrupt service availability. Does not expose credentials or tools."
        ),
        IMPACT_CLIENT_SIDE: (
            f"{kev_prefix}Client-side vulnerability ({cwe_str}) affects end-user browsers. "
            "Does not expose server-side credentials or tools."
        ),
    }

    return summaries.get(category, f"{kev_prefix}Vulnerability ({cwe_str}) with {category} impact.")
