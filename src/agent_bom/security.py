"""Security validation and hardening utilities."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Recognized MCP server launcher binaries (package managers, runtimes, and
# container tools commonly used to launch MCP servers).
#
# This list is a misconfiguration/typo guard for the stdio proxy spawn path —
# it is NOT a sandbox and NOT an isolation boundary. Every binary here can
# execute arbitrary code with the proxy's full host privileges; membership
# only means the command *shape* looks like a plausible MCP launcher. The
# actual execution control is container isolation via
# ``agent_bom.proxy_sandbox`` (``--isolate`` / AGENT_BOM_MCP_SANDBOX).
KNOWN_MCP_LAUNCHERS = {
    # JavaScript/TypeScript runtimes & package managers
    "npx",
    "npm",
    "node",
    "deno",
    "bun",
    "tsx",
    # Python runtimes & package managers
    "python",
    "python3",
    "uvx",
    "uv",
    "pipx",
    # Go
    "go",
    # Java/JVM
    "java",
    "mvn",
    "gradle",
    # .NET
    "dotnet",
    # Ruby
    "ruby",
    "bundle",
    # Rust
    "cargo",
    # Container tools (MCP servers often run in containers)
    "docker",
    "podman",
    # Common MCP server launchers
    "mcp",
    "mcp-server",
}

# Dangerous environment variables that should never be set
DANGEROUS_ENV_VARS = {
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",  # Can be used for code injection
    "NODE_OPTIONS",  # Can inject malicious code
}

# Shell metacharacters rejected by validate_arguments. agent-bom itself spawns
# MCP servers via an exec array (never a shell), so these characters are not
# interpreted on our spawn path; the check flags configs that appear to expect
# shell interpolation. Config hygiene, not an execution control.
SHELL_METACHARACTERS = {";", "|", "&", "$", "`", "<", ">", "\n", "\r"}

# Patterns for sensitive data (for redaction)
SENSITIVE_PATTERNS = [
    r"token",
    r"password",
    r"secret",
    r"api[_-]?key",
    r"auth",
    r"credential",
    r"bearer",
    r"jwt",
]


def sanitize_log_label(value: object, max_len: int = 500) -> str:
    """Return a single-line, ANSI-free label for logs and terminal output."""
    text = ANSI_ESCAPE_RE.sub("", str(value))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return re.sub(r" {2,}", " ", text).strip()[:max_len]


class SecurityError(Exception):
    """Raised when a security validation fails."""

    pass


def require_recognized_launcher(command: str) -> None:
    """
    Require that *command* is a recognized MCP launcher binary.

    This is a launch-hygiene check that catches typos and obviously
    misconfigured server commands before the proxy spawns them. It provides
    NO isolation: every recognized launcher (``python``, ``node``,
    ``docker``, …) can still execute arbitrary code as the host user.
    Passing this check must never be read as "the server is sandboxed" —
    the real execution control is container isolation via
    ``agent_bom.proxy_sandbox`` (``--isolate``).

    Args:
        command: The launcher command to check

    Raises:
        SecurityError: If command is not a recognized MCP launcher
    """
    if command not in KNOWN_MCP_LAUNCHERS:
        raise SecurityError(
            f"Command '{command}' is not a recognized MCP launcher. Recognized launchers: "
            f"{', '.join(sorted(KNOWN_MCP_LAUNCHERS))}. This check guards against misconfigured "
            "server commands only — it is not a sandbox. Use container isolation (--isolate) "
            "to restrict what a server can do."
        )
    logger.debug(f"Command '{command}' is a recognized MCP launcher")


def validate_arguments(args: list[str]) -> None:
    """
    Reject command arguments containing shell metacharacters.

    Config-hygiene check: agent-bom spawns MCP servers via an exec array
    (never through a shell), so these characters are not interpreted on our
    spawn path. An argument that contains them was almost certainly written
    for shell interpolation and indicates a misconfigured server entry.
    This is not an execution control and confers no isolation.

    Args:
        args: List of command arguments

    Raises:
        SecurityError: If shell metacharacters found
    """
    for arg in args:
        for char in SHELL_METACHARACTERS:
            if char in arg:
                raise SecurityError(f"Dangerous character '{char}' found in argument: {arg}")
    logger.debug(f"Validated {len(args)} argument(s) successfully")


def validate_environment(env: dict[str, str]) -> None:
    """
    Validate environment variables for dangerous settings.

    Args:
        env: Dictionary of environment variables

    Raises:
        SecurityError: If dangerous environment variable found
    """
    for var in env:
        if var in DANGEROUS_ENV_VARS:
            raise SecurityError(f"Dangerous environment variable '{var}' not allowed")
    logger.debug(f"Validated {len(env)} environment variable(s)")


def validate_path(
    path: str | Path,
    must_exist: bool = False,
    restrict_to_home: bool = False,
) -> Path:
    """
    Validate and normalize a file path.

    Args:
        path: Path to validate
        must_exist: If True, path must exist
        restrict_to_home: If True, path must resolve inside the user's home directory

    Returns:
        Validated and normalized Path object

    Raises:
        SecurityError: If path is invalid or contains path traversal
    """
    path = Path(path).expanduser()

    # Resolve to absolute path (prevents path traversal)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path '{path}': {e}")

    # Restrict to home directory (used by MCP server for user-provided paths)
    if restrict_to_home and not resolved.is_relative_to(Path.home()):
        raise SecurityError(f"Path resolves outside home directory: {path}")

    # Check for path traversal attempts (on unresolved path)
    if ".." in path.parts:
        logger.warning(f"Path traversal attempt detected: {path}")
        raise SecurityError(f"Path traversal not allowed: {path}")

    # Check if path must exist
    if must_exist and not resolved.exists():
        raise SecurityError(f"Path does not exist: {resolved}")

    logger.debug(f"Validated path: {resolved}")
    return resolved


_VALUE_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}", re.I),  # Stripe/service keys
    re.compile(r"sk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{20,}"),  # OpenAI/Anthropic-style keys
    re.compile(r"hf_[A-Za-z0-9]{20,}"),  # Hugging Face tokens
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),  # Google API keys
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}"),  # GitHub tokens
    re.compile(r"(?:glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}"),  # GitLab tokens
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),  # AWS access key IDs
    # Any PEM private-key label, not an enumerated few: `OPENSSH` (ssh-keygen's
    # default since OpenSSH 7.8), `ENCRYPTED` and `PGP … BLOCK` were all missing,
    # so those keys reached reports verbatim. Requiring the literal `PRIVATE KEY`
    # keeps public material (`-----BEGIN CERTIFICATE-----`, `PUBLIC KEY`) out.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"),  # Private keys
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}"),  # JWTs
    re.compile(r"xox[bpsar]-[A-Za-z0-9-]{10,}"),  # Slack tokens
]

# Keep credential-bearing connection URLs on a literal-prefixed fast path.
# Putting an unbounded scheme expression in ``_VALUE_CREDENTIAL_PATTERNS``
# makes regex search backtrack from every character of a non-URL model payload,
# turning a linear redaction pass into minutes of CPU time.
_CONNECTION_CREDENTIAL_RE = re.compile(r"://[^:\s/@]+:[^@\s/]+@")
_REFERENCE_SAFE_PREFIXES = (
    "arn:",
    "vault://",
    "keyvault://",
    "aws-secretsmanager://",
    "gcp-secretmanager://",
    "secret-manager://",
    "workload-identity/",
)


def _contains_value_credential(value: str) -> bool:
    return any(pattern.search(value) for pattern in _VALUE_CREDENTIAL_PATTERNS) or (
        "://" in value and _CONNECTION_CREDENTIAL_RE.search(value) is not None
    )


def _decode_reference_component(value: str) -> str:
    """Decode bounded nested percent-encoding before classifying a reference."""
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def value_looks_like_secret(value: object) -> bool:
    """Return whether an external reference is actually credential material.

    Credential-reference APIs accept names, role ARNs, and secret-manager
    *paths*, never their values. Known credential patterns are authoritative;
    a bounded entropy fallback catches opaque pasted tokens while allowlisting
    the explicit reference shapes the product documents.
    """

    text = str(value or "").strip()
    if not text:
        return False
    if _contains_value_credential(text):
        return True
    lowered = text.lower()
    if "://" in text:
        try:
            parsed = urlsplit(text)
        except ValueError:
            return True
        # Query strings and fragments frequently carry bearer material. A
        # credential reference has no reason to preserve either.
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return True
        # A reference-shaped URL can still carry an opaque credential in its
        # host or path (for example ``vault://team/<pasted token>``). Apply the
        # same bounded entropy classifier to individual decoded components;
        # checking the whole URL would skip entropy because it contains ``://``.
        components = [_decode_reference_component(parsed.hostname or "")]
        decoded_path = _decode_reference_component(parsed.path)
        components.extend(part for part in decoded_path.split("/") if part)
        return any(_looks_sensitive_value(component) for component in components)
    if lowered.startswith(_REFERENCE_SAFE_PREFIXES):
        # Non-URL reference forms (ARNs and workload-identity names) receive
        # the same segment-level check instead of bypassing entropy wholesale.
        components = [part for part in re.split(r"[/:]", _decode_reference_component(text)) if part]
        return any(_looks_sensitive_value(component) for component in components)
    return _looks_sensitive_value(text)


# Base64 alphabet (standard + URL-safe)
_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+=*$")

# Minimum length to bother trying base64 decode (encodes ≥20 bytes)
_B64_MIN_LEN = 28

# Shannon entropy threshold — secrets typically score >3.8 bits/char;
# readable English scores ~4.0 but with spaces; env var values without
# spaces that score >4.5 over a long string are almost certainly secrets.
# Shorter strings (24-39 chars) require higher entropy to reduce false positives.
_HIGH_ENTROPY_THRESHOLD = 4.5
_HIGH_ENTROPY_MIN_LEN = 24
_HIGH_ENTROPY_SHORT_THRESHOLD = 5.0  # stricter for shorter strings (24-39 chars)

_STRUCTURED_EDGE_ID_RE = re.compile(r"^[^\s>]+->[A-Za-z][A-Za-z0-9_.:-]*->[^\s>]+$")


def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_obfuscated_credential(value: str) -> bool:
    """Return True if value looks like a base64-encoded or high-entropy secret.

    Two detection strategies:
    1. Base64 decode: if the value decodes to valid UTF-8 text that itself
       matches a key name or value credential pattern, flag it.
    2. High-entropy: strings (≥24 chars) with no whitespace and high Shannon
       entropy are extremely likely to be opaque secrets (keys, tokens,
       passwords).  Short strings (24-39 chars) require entropy >5.0 to reduce
       false positives; longer strings (≥40 chars) use the standard 4.5
       threshold.  Pure random bytes score ~6.0; base64-encoded secrets
       score ~5.8; UUIDs score ~3.8.
    """
    stripped = value.strip()

    # Strategy 1: base64 decode and re-check
    if len(stripped) >= _B64_MIN_LEN and _B64_RE.match(stripped):
        try:
            decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="strict")
            decoded_lower = decoded.lower()
            # Decoded text contains a sensitive keyword
            if any(re.search(p, decoded_lower) for p in SENSITIVE_PATTERNS):
                return True
            # Decoded text matches a known credential value pattern
            if _contains_value_credential(decoded):
                return True
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass  # Not valid base64 — fall through to entropy check

    # Strategy 2: high Shannon entropy on a compact, non-URL string
    # Short strings (24-39 chars) use a stricter threshold to avoid false positives
    str_len = len(stripped)
    if str_len >= _HIGH_ENTROPY_MIN_LEN and " " not in stripped and "://" not in stripped:
        entropy = _shannon_entropy(stripped)
        threshold = _HIGH_ENTROPY_SHORT_THRESHOLD if str_len < 40 else _HIGH_ENTROPY_THRESHOLD
        if entropy > threshold:
            return True

    return False


def env_key_is_credential(key: str) -> bool:
    """Whether an environment-variable *name* denotes a credential.

    Environment variable names are classified product-wide by
    ``constants.is_credential_key`` — it backs ``MCPServer.credential_names``
    and therefore every surface that reports an exposed credential.  Redaction
    has to cover at least those names, or a report can list a variable as an
    exposed credential in one field while publishing its value in another.
    ``SENSITIVE_PATTERNS`` adds forms that are not env-var-shaped (``api-key``,
    ``jwt``); it stays regex-based and is not widened, because
    :func:`_key_looks_sensitive` applies it to arbitrary payload keys where
    over-matching collapses distinct graph nodes.
    """
    from agent_bom.constants import is_credential_key

    low = key.lower()
    return is_credential_key(key) or any(re.search(pattern, low) for pattern in SENSITIVE_PATTERNS)


def sanitize_env_vars(env: dict[str, Any]) -> dict[str, str]:
    """
    Sanitize environment variables by redacting sensitive values.

    Checks both key names (via :func:`env_key_is_credential`) and values (via
    _VALUE_CREDENTIAL_PATTERNS) to catch hardcoded credentials in
    custom-named variables.

    Args:
        env: Dictionary of environment variables

    Returns:
        Dictionary with sensitive values redacted
    """
    sanitized = {}
    for key, value in env.items():
        if env_key_is_credential(key):
            sanitized[key] = "***REDACTED***"
        else:
            str_value = str(value)
            # Scan values for plaintext credential patterns (catches custom-named vars)
            if _contains_value_credential(str_value):
                sanitized[key] = "***REDACTED***"
            # Detect obfuscated secrets: base64-encoded values and high-entropy strings
            elif _is_obfuscated_credential(str_value):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = str_value

    return sanitized


# Email is sensitive PII. We mask the local part and the domain label while
# preserving enough shape to keep records correlatable (first char + TLD).
# Conservative on purpose: only well-formed addresses are masked so legitimate
# non-PII fields (versions, identifiers containing "@" such as scoped npm
# package names like "@scope/pkg") are left untouched.
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+)\.([A-Za-z]{2,})\b")


def _mask_email_match(local: str, domain: str, tld: str) -> str:
    """Mask one parsed email address into ``a***@e***.com`` shape."""
    local_masked = f"{local[0]}***" if local else "***"
    domain_masked = f"{domain[0]}***" if domain else "***"
    return f"{local_masked}@{domain_masked}.{tld}"


def mask_email(value: object) -> str:
    """Mask every email address in *value*, preserving non-email text.

    ``alice@example.com`` → ``a***@e***.com``. Strings without a well-formed
    address pass through unchanged, so scoped package names (``@scope/pkg``)
    and version specifiers are not corrupted.
    """
    text = str(value)
    return _EMAIL_RE.sub(lambda m: _mask_email_match(m.group(1), m.group(2), m.group(3)), text)


def _contains_email(value: str) -> bool:
    return bool(_EMAIL_RE.search(value))


# Field names whose values are email addresses and must always be masked in
# operational records (audit metadata, connector identity fields, evidence).
_EMAIL_KEYS = {
    "email",
    "email_address",
    "user_email",
    "actor_email",
    "owner_email",
    "contact_email",
    "notify_email",
    "reporter_email",
    "assignee_email",
    "mail",
}


def _key_looks_like_email(key: object) -> bool:
    key_text = str(key or "").strip().lower().replace("-", "_")
    return key_text in _EMAIL_KEYS or key_text.endswith("_email")


def sanitize_url(value: str | None) -> str | None:
    """Strip credentials, query strings, and fragments from display/export URLs."""
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-url>"
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def redact_secret_url(value: str | None) -> str:
    """Redact a secret-bearing URL down to scheme+host plus a short fingerprint.

    Unlike :func:`sanitize_url`, this also drops the *path*: for incoming
    webhooks (Slack-style) the URL path segments carry the secret token, so the
    URL itself is credential material. The returned form keeps just enough
    (scheme, host, and a stable 8-char fingerprint of the full URL) for an
    operator to correlate failures without exposing the secret in logs or an
    audit export.
    """
    if not value:
        return "<none>"
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    try:
        parsed = urlsplit(value)
    except ValueError:
        return f"<redacted-url>#{fingerprint}"
    if not parsed.scheme or not parsed.netloc:
        return f"<redacted-url>#{fingerprint}"
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}/…#{fingerprint}"


# `KEY = "value"` in the shapes free text actually uses: bare, quoted, spaced,
# JSON (`"api_key": "…"`), YAML (`api_key: …`). The previous scanner took a run
# of non-space characters and `rpartition`-ed it, so it found the key only in
# the single unquoted `KEY=value` form — and on a base64 value it split at the
# `=` *padding*, leaving an empty candidate. Everything else printed verbatim.
#
# Widening happens on the key side only. `[^\s"',;<>]` is the value: a plain run,
# never entropy-tested on its own, because free text is full of legitimate
# high-entropy tokens (digests, ARNs, request ids) and a redactor that eats them
# is one people switch off.
#
# A bare `:` with nothing around it is *not* an assignment — it is the delimiter
# in the graph's own structured identifiers
# (`credential_ref:credential_ref:credential_reference:redacted`) and in ARNs and
# digests. Reading one as `key: value` redacts the tail of a node id, and the
# graph exporter then collapses distinct nodes into one phantom. So a colon has
# to look like an assignment: quoted as in JSON, or followed by whitespace as
# YAML requires. `=` needs no such proof; structured ids do not use it.
_TEXT_KEY_VALUE_RE = re.compile(
    r"""(?P<key>[A-Za-z][A-Za-z0-9_.\-]{1,63})   # key name
        (?P<sep>["']?[ \t]*=[ \t]*               # `KEY=v`, `KEY = v`, `"KEY"=v`
             |["'][ \t]*:[ \t]*                  # `"key": v`
             |[ \t]*:[ \t]*(?=["'])              # `key:"v"`
             |[ \t]*:[ \t]+)                     # `key: v`
        (?P<quote>["']?)                         # optional opening quote on the value
        (?P<value>[^\s"',;<>]+)                  # the value
    """,
    re.VERBOSE,
)

# Values that are plainly not credential material. The key name cannot tell a
# secret from a count or a placeholder, and redacting these makes logs
# unreadable without making anything safer.
_NON_SECRET_VALUE_RE = re.compile(
    r"^(?:\d+(?:\.\d+)*|true|false|yes|on|off|none|null|nil|unset|unknown|missing|empty|n/?a|redacted|\*+redacted\*+|\*+|-+)$",
    re.I,
)

# An env-var *name* is an identifier, not a secret. Reports carry
# `credential_names=OPENAI_API_KEY` as evidence; redacting the name loses the
# finding and protects nothing — only the value of a credential is sensitive.
_CREDENTIAL_IDENTIFIER_VALUE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")

# Below this a value is an enum or a flag, not authentication material.
_MIN_SECRET_VALUE_LEN = 4


def sanitize_text(value: object, max_len: int = 1000) -> str:
    """Redact credential-shaped substrings, credential-bearing URLs, and emails in text."""
    text = sanitize_log_label(value, max_len=max_len)
    text = re.sub(r"https?://[^\s\"'<>]+", lambda match: str(sanitize_url(match.group(0)) or ""), text)
    for pattern in _VALUE_CREDENTIAL_PATTERNS:
        text = pattern.sub("<redacted>", text)
    if "://" in text:
        text = _CONNECTION_CREDENTIAL_RE.sub("://<redacted>@", text)
    # The pattern list carries AWS access key *ids* but nothing for the 40-char
    # secret access key, so the harmless half was redacted while the dangerous
    # half was printed verbatim. Anything the shapes above miss is caught by the
    # variable *name* it is written under, using the product-wide predicate.
    text = _TEXT_KEY_VALUE_RE.sub(_redact_keyed_value, text)
    # Email is sensitive PII — mask any addresses left in free text.
    text = mask_email(text)
    return text[:max_len]


def _redact_keyed_value(match: re.Match[str]) -> str:
    """Redact the value of a `key: value` pair when the *key* names a credential.

    Requiring the key is what keeps this usable. The entropy fallback that
    `sanitize_env_vars` applies is safe there, because a high-entropy env var
    value is almost certainly a secret — but free text is full of high-entropy
    tokens that are not: content hashes, ARNs, request ids, digests. Applying it
    to bare tokens redacted a `hash_ref` and a GuardDuty ARN in the runtime
    taxonomy. So the two paths share the *predicate for names* and deliberately
    do not share the bare-value heuristic.

    A named credential's value is redacted on the strength of the name alone —
    a 64-char hex API key scores below every value threshold there is, and
    waiting for the value to look secret is what let it through.
    """
    value = match.group("value")
    if not env_key_is_credential(match.group("key")) or not _is_credential_material(value):
        return match.group(0)
    prefix = f"{match.group('key')}{match.group('sep')}{match.group('quote')}"
    # A connection URL is evidence: the host says which system was reached. Keep
    # that and drop the credential, rather than blanking the whole line.
    if "://" in value:
        return f"{prefix}{sanitize_url(value) or '<redacted>'}"
    return f"{prefix}<redacted>"


def _is_credential_material(value: str) -> bool:
    """Whether a value under a credential-named key could be the credential."""
    if len(value) < _MIN_SECRET_VALUE_LEN or _NON_SECRET_VALUE_RE.match(value):
        return False
    return not (_CREDENTIAL_IDENTIFIER_VALUE_RE.match(value) and env_key_is_credential(value))


def text_requires_redaction(value: object) -> bool:
    """Return whether canonical free-text redaction would alter sensitive data.

    Renderers use this exact predicate for their fast path. It intentionally
    shares the central patterns and credential-key classifier so a duplicated
    heuristic cannot drift into a redaction bypass.
    """
    text = str(value)
    if "http://" in text.lower() or "https://" in text.lower():
        return True
    if _EMAIL_RE.search(text) or _contains_value_credential(text):
        return True
    # The keyed-value grammar cannot match without an assignment delimiter.
    # Avoid starting its bounded-key regex at every character of large plain
    # model/output strings.
    if "=" not in text and ":" not in text:
        return False
    return any(
        env_key_is_credential(match.group("key")) and _is_credential_material(match.group("value"))
        for match in _TEXT_KEY_VALUE_RE.finditer(text)
    )


def _looks_sensitive_value(value: str) -> bool:
    return sanitize_env_vars({"ARG": value}).get("ARG") == "***REDACTED***"


def sanitize_command_args(args: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact secret-bearing command arguments while preserving launch shape."""
    sanitized: list[str] = []
    redact_next = False
    for raw_arg in args:
        arg = str(raw_arg)
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue

        if "=" in arg:
            key, _sep, raw_value = arg.partition("=")
            if any(re.search(pattern, key.lower()) for pattern in SENSITIVE_PATTERNS):
                sanitized.append(f"{key}=<redacted>")
                continue
            if "://" in raw_value:
                sanitized.append(f"{key}={sanitize_url(raw_value)}")
                continue
            if _looks_sensitive_value(raw_value):
                sanitized.append(f"{key}=<redacted>")
                continue

        if "://" in arg:
            sanitized.append(str(sanitize_url(arg) or ""))
            continue

        if _looks_sensitive_value(arg):
            sanitized.append("<redacted>")
            continue

        if arg.startswith("-") and any(re.search(pattern, arg.lower()) for pattern in SENSITIVE_PATTERNS):
            sanitized.append(arg)
            redact_next = True
            continue

        sanitized.append(arg)
    return sanitized


def sanitize_launch_command(command: object, args: list[Any] | tuple[Any, ...] | None = None, *, max_args: int | None = None) -> str:
    """Return a safe command label for display/export surfaces."""
    safe_command = sanitize_text(command, max_len=200)
    raw_args = list(args or [])
    if max_args is not None:
        raw_args = raw_args[:max_args]
    safe_args = sanitize_command_args(raw_args)
    return " ".join([part for part in [safe_command, *safe_args] if part]).strip()


def sanitize_security_warnings(values: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact warning text before persistence or UI/API export."""
    return [sanitize_text(value) for value in values if str(value or "").strip()]


def _key_looks_sensitive(key: object) -> bool:
    return any(re.search(pattern, str(key).lower()) for pattern in SENSITIVE_PATTERNS)


# Fields whose string members are credential *env-var names* — identifiers such
# as ``OPENAI_API_KEY`` — not secret values.  The key text ("credential…")
# matches SENSITIVE_PATTERNS, so without this exception every name would redact
# to ``***REDACTED***``; downstream the graph exporter mints node IDs from these
# labels and set-dedups them, collapsing distinct credentials into one phantom
# node and inventing cross-agent ``reaches_tool``/``exposes_cred`` edges.  Only
# the VALUE of a credential is sensitive, and values are never carried here.
_CREDENTIAL_IDENTIFIER_KEYS = frozenset(
    {
        "credential_env_vars",
        "credential_env_var",
        "credential_names",
        "credential_refs",
        "credentials_exposed",
        "exposed_credentials",
        "exposed_credential_names",
    }
)


def _key_is_credential_identifier(key: object) -> bool:
    return str(key or "").strip().lower().replace("-", "_") in _CREDENTIAL_IDENTIFIER_KEYS


def _key_looks_like_url(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in {"url", "uri", "endpoint", "webhook"} or key_text.endswith(("_url", "_uri", "_endpoint", "_webhook"))


def _key_looks_like_path(key: object) -> bool:
    key_text = str(key).lower()
    path_terms = ("path", "file", "dir", "directory", "cwd", "workspace", "config_path", "source_path")
    return any(term in key_text for term in path_terms)


def _looks_like_path_value(value: str) -> bool:
    if not value or "://" in value:
        return False
    return value.startswith("/") or value.startswith("~/") or bool(re.match(r"^[A-Za-z]:[\\/]", value))


_CLOUD_IDENTITY_KEYS = {
    "account_id",
    "arn",
    "cloud_principal",
    "endpoint_id",
    "location",
    "principal_arn",
    "project_id",
    "region",
    "resource_group",
    "resource_id",
    "resource_name",
    "service",
    "subscription_id",
    "tenant_id",
}


def _key_looks_like_cloud_identity(key: object) -> bool:
    key_text = str(key or "").strip().lower().replace("-", "_")
    return key_text in _CLOUD_IDENTITY_KEYS or key_text.endswith("_arn") or key_text.endswith("_resource_id")


def sanitize_path_label(value: object) -> str:
    """Return a non-revealing label for local filesystem paths."""
    text = sanitize_log_label(value, max_len=1000)
    if re.fullmatch(r"<path:[^<>]+>", text):
        return text
    basename = re.split(r"[\\/]+", text.rstrip("/\\"))[-1] if text else ""
    basename = sanitize_text(basename or "path", max_len=80)
    if not basename or _key_looks_sensitive(basename) or _looks_sensitive_value(basename):
        basename = "path"
    return f"<path:{basename}>"


_SANITIZE_PAYLOAD_CACHE_LIMIT = 262_144
_SANITIZE_PAYLOAD_CACHE_MISS = object()


def _sanitize_sensitive_string(value: str, *, key: object | None, max_str_len: int) -> object:
    """Redact one string while preserving the caller's field-sensitive rules."""
    # A credential env-var NAME is an identifier, not a secret value.  Keep
    # it intact so distinct credentials stay distinct graph nodes; still
    # redact defensively if the string itself looks like a leaked secret.
    if _key_is_credential_identifier(key) and not _looks_sensitive_value(value):
        return sanitize_text(value, max_len=max_str_len)
    if key is not None and _key_looks_sensitive(key):
        return "***REDACTED***"
    if key is not None and _key_looks_like_email(key):
        return mask_email(value)
    if key is not None and _key_looks_like_url(key):
        return sanitize_url(value)
    if key is not None and _key_looks_like_cloud_identity(key):
        if _looks_sensitive_value(value):
            return "***REDACTED***"
        return sanitize_text(value, max_len=max_str_len)
    # Graph edge identifiers are deterministic relationship coordinates,
    # not opaque credentials.  Their punctuation and length can otherwise
    # trip the entropy detector.  Keep the exception deliberately narrow:
    # only ID fields with the canonical ``source->relation->target`` shape,
    # and never values matching a known credential pattern.
    key_text = str(key or "").strip().lower().replace("-", "_")
    edge_parts = value.split("->")
    if (
        key_text in {"id", "canonical_id"}
        and _STRUCTURED_EDGE_ID_RE.fullmatch(value)
        and len(edge_parts) == 3
        and not _looks_sensitive_value(edge_parts[0])
        and not _looks_sensitive_value(edge_parts[2])
    ):
        return sanitize_text(value, max_len=max_str_len)
    if "://" in value:
        return sanitize_text(value, max_len=max_str_len)
    if key is not None and _key_looks_like_path(key) and _looks_like_path_value(value):
        return sanitize_path_label(value)
    if _looks_like_path_value(value):
        return sanitize_path_label(value)
    if not text_requires_redaction(value) and (
        len(value.strip()) < _HIGH_ENTROPY_MIN_LEN or any(character.isspace() for character in value)
    ):
        return sanitize_log_label(value, max_len=max_str_len)
    if _looks_sensitive_value(value):
        return "***REDACTED***"
    return sanitize_text(value, max_len=max_str_len)


def sanitize_sensitive_payload(
    value: object,
    *,
    key: object | None = None,
    max_str_len: int = 1000,
    depth: int = 0,
    _string_cache: dict[tuple[str | None, str, int], object] | None = None,
    _key_cache: dict[str, str] | None = None,
) -> object:
    """Recursively redact sensitive runtime/audit payloads before persistence/export.

    One report repeats the same immutable package fields across its inventory,
    agent, and AI-BOM contract views. Keep bounded caches for the duration of a
    single traversal so those values are redacted once, without retaining
    potentially sensitive strings globally between exports.
    """
    if _string_cache is None:
        _string_cache = {}
    if _key_cache is None:
        _key_cache = {}
    if depth >= 24:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        cache_key = (str(key) if key is not None else None, value, max_str_len)
        cached = _string_cache.get(cache_key, _SANITIZE_PAYLOAD_CACHE_MISS)
        if cached is not _SANITIZE_PAYLOAD_CACHE_MISS:
            return cached
        sanitized_value = _sanitize_sensitive_string(value, key=key, max_str_len=max_str_len)
        if len(_string_cache) < _SANITIZE_PAYLOAD_CACHE_LIMIT:
            _string_cache[cache_key] = sanitized_value
        return sanitized_value
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for raw_key, raw_value in value.items():
            raw_key_text = str(raw_key)
            clean_key = _key_cache.get(raw_key_text)
            if clean_key is None:
                clean_key = sanitize_text(raw_key, max_len=200)
                if len(_key_cache) < _SANITIZE_PAYLOAD_CACHE_LIMIT:
                    _key_cache[raw_key_text] = clean_key
            sanitized[clean_key] = sanitize_sensitive_payload(
                raw_value,
                key=clean_key,
                max_str_len=max_str_len,
                depth=depth + 1,
                _string_cache=_string_cache,
                _key_cache=_key_cache,
            )
        return sanitized
    if isinstance(value, list | tuple | set):
        return [
            sanitize_sensitive_payload(
                item,
                key=key,
                max_str_len=max_str_len,
                depth=depth + 1,
                _string_cache=_string_cache,
                _key_cache=_key_cache,
            )
            for item in list(value)
        ]
    return sanitize_text(value, max_len=max_str_len)


def validate_file_size(path: Path, max_size_bytes: int = 10 * 1024 * 1024) -> None:
    """
    Validate that a file is not too large (DoS prevention).

    Args:
        path: Path to file
        max_size_bytes: Maximum allowed file size (default 10MB)

    Raises:
        SecurityError: If file is too large
    """
    try:
        size = os.path.getsize(path)
        if size > max_size_bytes:
            raise SecurityError(f"File too large: {size} bytes (max: {max_size_bytes} bytes)")
        logger.debug(f"File size OK: {size} bytes")
    except OSError as e:
        raise SecurityError(f"Cannot check file size: {e}")


def validate_json_file(path: Path) -> dict:
    """
    Safely load and validate a JSON file.

    Args:
        path: Path to JSON file

    Returns:
        Parsed JSON data

    Raises:
        SecurityError: If file is invalid or too large
    """
    import json

    # Validate path
    path = validate_path(path, must_exist=True)

    # Check file size (DoS prevention)
    validate_file_size(path)

    # Load JSON safely (json.load is safe, doesn't execute code)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Successfully loaded JSON from {path}")
        return data
    except json.JSONDecodeError as e:
        raise SecurityError(f"Invalid JSON in {path}: {e}")
    except (OSError, UnicodeDecodeError) as e:
        raise SecurityError(f"Cannot read file {path}: {e}")


def validate_url(url: str, *, allowed_schemes: tuple[str, ...] = ("https",), allow_private: bool = False) -> None:
    """
    Validate a URL for safety, including DNS rebinding protection.

    Resolves hostnames to IPs and validates the resolved addresses against
    private/loopback/reserved/link-local ranges to prevent DNS rebinding
    attacks where a hostname initially resolves to a public IP but later
    resolves to an internal one.

    Args:
        url: URL to validate

    Raises:
        SecurityError: If URL is invalid or uses insecure protocol
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL '{url}': {e}")

    allow_private = allow_private or os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    http_private_override = allow_private and parsed.scheme == "http" and allowed_schemes == ("https",)

    if parsed.scheme not in allowed_schemes and not http_private_override:
        if allowed_schemes == ("https",):
            raise SecurityError(f"URL must use HTTPS; got: {parsed.scheme}")
        expected = ", ".join(f"{scheme}://" for scheme in allowed_schemes)
        raise SecurityError(f"URL must use one of {expected}; got: {parsed.scheme}")

    # Validate domain is not localhost or internal IP
    hostname = parsed.hostname or ""
    if not hostname:
        raise SecurityError("URL must include a hostname")
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # nosec B104 - checking FOR these values to reject them, not binding to them
        if not allow_private:
            raise SecurityError(f"Cannot connect to localhost/internal IPs: {hostname}")
        logger.warning("Private egress URL allowed by operator override")
        return

    # Block cloud metadata endpoints (AWS/GCP/Azure)
    if hostname in ("169.254.169.254", "metadata.google.internal"):
        raise SecurityError(f"Cannot connect to cloud metadata endpoint: {hostname}")

    # Check if hostname is already an IP literal
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            if not allow_private:
                raise SecurityError(f"Cannot connect to private/reserved IP: {hostname}")
            logger.warning("Private egress URL allowed by operator override")
            return
    except ValueError:
        pass  # hostname is a domain name — resolve below

    # DNS rebinding protection: resolve hostname and validate all resolved IPs
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise SecurityError(f"Cannot resolve hostname: {hostname}")

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        resolved_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(resolved_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                if not allow_private:
                    raise SecurityError(f"Hostname '{hostname}' resolves to private/reserved IP: {resolved_ip}")
                logger.warning("Private egress URL allowed by operator override")
                return
        except ValueError:
            continue

    if http_private_override:
        raise SecurityError("HTTP URLs are only allowed for private egress targets when AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS is enabled")

    # Static log — no user-controlled values to prevent both cleartext
    # credential logging and log injection (CodeQL py/clear-text-logging,
    # py/log-injection).
    logger.debug("URL validated successfully")


def validate_package_name(name: str, ecosystem: str) -> None:
    """
    Validate package name follows ecosystem conventions.

    Args:
        name: Package name
        ecosystem: Package ecosystem (npm, pypi, go, cargo)

    Raises:
        SecurityError: If package name is invalid
    """
    if not name or not isinstance(name, str):
        raise SecurityError(f"Invalid package name: {name}")

    # Ecosystem-specific validation
    if ecosystem == "npm":
        # npm: lowercase, alphanumeric, hyphens, underscores, @ for scoped
        if not re.match(r"^(@[a-z0-9-_]+/)?[a-z0-9-_]+$", name.lower()):
            raise SecurityError(f"Invalid npm package name: {name}")

    elif ecosystem == "pypi":
        # PyPI: alphanumeric, hyphens, underscores, dots
        if not re.match(r"^[a-zA-Z0-9-_.]+$", name):
            raise SecurityError(f"Invalid PyPI package name: {name}")

    elif ecosystem == "go":
        # Go: domain/path format
        if not re.match(r"^[a-zA-Z0-9-_.\/]+$", name):
            raise SecurityError(f"Invalid Go package name: {name}")

    elif ecosystem == "cargo":
        # Rust: alphanumeric, hyphens, underscores
        if not re.match(r"^[a-zA-Z0-9-_]+$", name):
            raise SecurityError(f"Invalid Cargo package name: {name}")

    logger.debug(f"Package name validated: {name} ({ecosystem})")


def create_safe_subprocess_env() -> dict[str, str]:
    """
    Create a minimal, safe environment for subprocess execution.

    Returns:
        Dictionary with minimal safe environment variables
    """
    # Only include essential environment variables
    safe_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # nosec B108 - safe fallback for subprocess when HOME not set
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    }

    # Add npm/node specific vars if present
    if "NPM_CONFIG_REGISTRY" in os.environ:
        safe_env["NPM_CONFIG_REGISTRY"] = os.environ["NPM_CONFIG_REGISTRY"]

    return safe_env


def validate_mcp_server_config(server_config: dict) -> None:
    """
    Validate an MCP server configuration for hygiene issues before launch.

    Checks launcher recognition, argument shape, and dangerous environment
    variables. These are misconfiguration guards, not isolation — a config
    that passes still runs with full host privileges unless container
    isolation (``agent_bom.proxy_sandbox``, ``--isolate``) is enabled.

    Args:
        server_config: MCP server configuration dictionary

    Raises:
        SecurityError: If configuration fails a hygiene check
    """
    # Check the launcher (remote/URL-based servers don't require a local command)
    command = server_config.get("command", "")
    has_url = bool(server_config.get("url") or server_config.get("uri"))
    if not has_url:
        require_recognized_launcher(command)

    # Validate arguments
    args = server_config.get("args", [])
    if not isinstance(args, list):
        raise SecurityError("Server args must be a list")
    validate_arguments(args)

    # Validate environment variables
    env = server_config.get("env", {})
    if not isinstance(env, dict):
        raise SecurityError("Server env must be a dictionary")
    validate_environment(env)

    logger.info("MCP server config validated: %s", sanitize_text(command or server_config.get("url", "unknown")))


# Docker/OCI image reference pattern — must start with alphanum, no shell metacharacters
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]+$")


def validate_image_ref(ref: str) -> str:
    """Validate a Docker/OCI image reference.

    Rejects references starting with ``-`` (argument injection) and those
    containing shell metacharacters.

    Returns:
        The validated reference string.

    Raises:
        SecurityError: If the reference is invalid.
    """
    if not ref or not _IMAGE_REF_RE.match(ref):
        raise SecurityError(f"Invalid image reference: {ref!r}")
    return ref


def sanitize_error(exc: Exception | str, generic: bool = False, *, max_length: int = 200) -> str:
    """Return a safe error message suitable for API consumers.

    Strips sensitive data (file paths, URLs) from exception messages while
    preserving safe, actionable text.  Set ``generic=True`` to always return
    a fixed non-diagnostic string regardless of the exception content.

    ``max_length`` caps arbitrary SDK/exception text so a pathological message
    cannot flood a response or a terminal. Callers passing text this codebase
    *authored* (curated remediation guidance, which is bounded by construction)
    may raise the cap so multi-sentence guidance is not chopped mid-word — the
    redaction above always still applies.
    """
    if generic:
        return "An internal error occurred. Please contact support."

    msg = str(exc)
    # Strip URLs first (before path regex matches the path portion)
    msg = re.sub(r"https?://[^\s\"']+", "<url>", msg)
    # Strip inline credential assignments commonly included in SDK error strings.
    msg = re.sub(
        r"(?i)\b(token|secret|password|passwd|api[_-]?key|access[_-]?key|session[_-]?token)\s*=\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=<redacted>",
        msg,
    )
    # Strip absolute file paths
    msg = re.sub(r"(/[^\s:\"']+)+", "<path>", msg)
    return msg[:max_length] if len(msg) > max_length else msg


# Export all validation functions
__all__ = [
    "SecurityError",
    "require_recognized_launcher",
    "validate_arguments",
    "validate_environment",
    "validate_path",
    "sanitize_env_vars",
    "sanitize_command_args",
    "sanitize_launch_command",
    "sanitize_security_warnings",
    "sanitize_sensitive_payload",
    "sanitize_path_label",
    "sanitize_text",
    "sanitize_url",
    "mask_email",
    "validate_file_size",
    "validate_json_file",
    "validate_url",
    "validate_package_name",
    "create_safe_subprocess_env",
    "validate_mcp_server_config",
    "validate_image_ref",
    "sanitize_error",
]
