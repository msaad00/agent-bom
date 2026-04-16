"""Policy and classification helpers for the MCP runtime proxy."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from agent_bom.permissions import classify_tool

logger = logging.getLogger(__name__)

_compiled_patterns: dict[str, re.Pattern] = {}
_PATH_ARG_KEYS = {
    "path",
    "file",
    "filepath",
    "filename",
    "source",
    "target",
    "destination",
    "cwd",
    "dir",
    "directory",
    "output",
    "input",
}
_URL_ARG_KEYS = {
    "url",
    "uri",
    "endpoint",
    "href",
    "link",
    "host",
    "domain",
    "base_url",
    "target_url",
}
_SECRET_PATH_PATTERNS = (
    ".env",
    ".npmrc",
    ".pypirc",
    ".aws/",
    ".ssh/",
    ".gnupg/",
    ".kube/config",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "authorized_keys",
    "known_hosts",
)
_NETWORK_KEYWORDS = ("http", "fetch", "web", "request", "url", "curl", "download", "upload", "post")


def _safe_compile(pattern: str) -> re.Pattern:
    if pattern not in _compiled_patterns:
        _compiled_patterns[pattern] = re.compile(pattern)
    return _compiled_patterns[pattern]


def _safe_regex_match(pattern: str, text: str) -> bool:
    if len(text) > 10_000:
        logger.warning("Skipping regex match on oversized input (%d chars)", len(text))
        return False
    return _safe_compile(pattern).match(text) is not None


def _safe_regex_search(pattern: str, text: str) -> bool:
    if len(text) > 10_000:
        logger.warning("Skipping regex search on oversized input (%d chars)", len(text))
        return False
    return _safe_compile(pattern).search(text) is not None


def _iter_argument_strings(value: object, key_hint: str = "") -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            pairs.extend(_iter_argument_strings(child, str(key)))
    elif isinstance(value, list):
        for child in value:
            pairs.extend(_iter_argument_strings(child, key_hint))
    elif isinstance(value, str):
        pairs.append((key_hint.lower(), value))
    return pairs


def _extract_argument_paths(arguments: dict) -> list[str]:
    paths: list[str] = []
    for key, value in _iter_argument_strings(arguments):
        lowered = value.lower()
        if key in _PATH_ARG_KEYS or "/" in value or "\\" in value or lowered.startswith("~"):
            paths.append(value)
    return paths


def _extract_argument_hosts(arguments: dict) -> list[str]:
    hosts: list[str] = []
    for key, value in _iter_argument_strings(arguments):
        candidate = value.strip()
        lowered = candidate.lower()
        if key not in _URL_ARG_KEYS and not lowered.startswith(("http://", "https://")):
            continue
        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        if parsed.hostname:
            hosts.append(parsed.hostname.lower())
    return hosts


def _matches_secret_path(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in _SECRET_PATH_PATTERNS)


def _classify_tool_classes(tool_name: str, arguments: dict) -> set[str]:
    classes = {classify_tool(tool_name)}
    combined = f"{tool_name} " + " ".join(str(v) for _, v in _iter_argument_strings(arguments))
    lowered = combined.lower()
    if any(keyword in lowered for keyword in _NETWORK_KEYWORDS) or _extract_argument_hosts(arguments):
        classes.add("network")
    if any(term in lowered for term in ("sql", "query", "database", "db", "postgres", "mysql")):
        classes.add("database")
    if any(term in lowered for term in ("file", "path", "directory", "filesystem")) or _extract_argument_paths(arguments):
        classes.add("filesystem")
    return classes


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    normalized = [entry.lower() for entry in allowed_hosts if entry]
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in normalized)


def resolve_rate_limit_threshold(policy: dict) -> int | None:
    """Return the strictest positive ``rate_limit`` configured in a policy bundle."""
    limits: list[int] = []
    for rule in policy.get("rules", []):
        limit = rule.get("rate_limit")
        if isinstance(limit, int) and limit > 0:
            limits.append(limit)
    return min(limits) if limits else None


def check_policy(policy: dict, tool_name: str, arguments: dict) -> tuple[bool, str]:
    """Evaluate runtime policy against a tools/call request."""
    rules = policy.get("rules", [])
    tool_classes = _classify_tool_classes(tool_name, arguments)
    argument_paths = _extract_argument_paths(arguments)
    argument_hosts = _extract_argument_hosts(arguments)

    for rule in rules:
        if rule.get("mode") != "allowlist":
            continue
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue
        allowed_tools = rule.get("allow_tools", [])
        if tool_name not in allowed_tools:
            return False, f"Tool '{tool_name}' not in allowlist for rule '{rule.get('id', '?')}'"
        break

    for rule in rules:
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue
        if rule.get("mode") == "allowlist":
            continue

        blocked = rule.get("block_tools", [])
        if blocked and tool_name in blocked:
            return False, f"Tool '{tool_name}' is blocked by rule '{rule.get('id', '?')}'"

        denied_classes = {str(item).lower() for item in rule.get("deny_tool_classes", [])}
        if denied_classes:
            matched_classes = sorted(tool_classes & denied_classes)
            if matched_classes:
                joined = ", ".join(matched_classes)
                return False, f"Tool '{tool_name}' matched denied tool class(es) {joined} in rule '{rule.get('id', '?')}'"

        if rule.get("read_only") and tool_classes & {"write", "execute", "destructive"}:
            return False, f"Tool '{tool_name}' violates read-only mode in rule '{rule.get('id', '?')}'"

        if rule.get("block_secret_paths"):
            matched_path = next((path for path in argument_paths if _matches_secret_path(path)), None)
            if matched_path:
                return False, f"Argument path '{matched_path}' matches a protected secret path in rule '{rule.get('id', '?')}'"

        if rule.get("block_unknown_egress"):
            allowed_hosts = [str(host) for host in rule.get("allowed_hosts", [])]
            unmatched_host = next((host for host in argument_hosts if not _host_allowed(host, allowed_hosts)), None)
            if unmatched_host:
                return False, f"Outbound host '{unmatched_host}' is not allowlisted in rule '{rule.get('id', '?')}'"

        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule.get('id', '?')}'"

        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if len(pattern) > 500:
                    logger.warning("Skipping oversized tool_name_pattern (%d chars)", len(pattern))
                elif _safe_regex_match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'"
            except re.error:
                pass

        arg_patterns = rule.get("arg_pattern", {})
        for arg_name, arg_regex in arg_patterns.items():
            arg_value = str(arguments.get(arg_name, ""))
            try:
                if len(arg_regex) > 500:
                    logger.warning("Skipping oversized arg_pattern for '%s' (%d chars)", arg_name, len(arg_regex))
                    continue
                if _safe_regex_search(arg_regex, arg_value):
                    return False, f"Argument '{arg_name}' matches blocked pattern '{arg_regex}'"
            except re.error:
                pass

    return True, ""
