"""Policy and classification helpers for the MCP runtime proxy."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
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
    # Screen-capture classification — matches browser / Playwright / Puppeteer
    # tool names. Policies can deny this class wholesale via
    # ``deny_tool_classes: ["screen_capture"]`` when an MCP has no business
    # producing pixels in the pilot environment (see issue #1568).
    if any(
        term in tool_name.lower()
        for term in ("screenshot", "screen_capture", "screencap", "capture_screen", "take_screenshot", "page_screenshot")
    ):
        classes.add("screen_capture")
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


def summarize_policy_bundle(policy: dict) -> dict[str, object]:
    """Summarize rollout posture and major controls for a runtime policy bundle."""
    raw_rules = policy.get("rules", [])
    rules = raw_rules if isinstance(raw_rules, list) else []

    total_rules = len(rules)
    blocking_rules = 0
    advisory_rules = 0
    allowlist_rules = 0
    default_deny_rules = 0
    read_only_rules = 0
    secret_path_rules = 0
    unknown_egress_rules = 0
    denied_tool_classes: set[str] = set()

    for raw_rule in rules:
        rule = raw_rule if isinstance(raw_rule, dict) else {}
        action = str(rule.get("action", "warn")).lower()
        is_blocking = action in ("block", "fail")
        if is_blocking:
            blocking_rules += 1
        else:
            advisory_rules += 1
        if str(rule.get("mode", "")).lower() == "allowlist":
            allowlist_rules += 1
            if is_blocking:
                default_deny_rules += 1
        if rule.get("read_only"):
            read_only_rules += 1
        if rule.get("block_secret_paths"):
            secret_path_rules += 1
        if rule.get("block_unknown_egress"):
            unknown_egress_rules += 1
        denied_tool_classes.update(str(item).lower() for item in rule.get("deny_tool_classes", []) if item)

    if total_rules == 0:
        rollout_mode = "disabled"
        summary = "No runtime policy rules configured."
    elif blocking_rules == 0:
        rollout_mode = "advisory_only"
        summary = "Policy matches are advisory only; runtime will not block."
    elif blocking_rules > 0 and advisory_rules > 0:
        rollout_mode = "mixed"
        summary = "Mixed rollout: some rules block while others remain advisory."
    elif default_deny_rules > 0:
        rollout_mode = "default_deny"
        summary = "Blocking allowlist enforcement is active for matched policy scope."
    else:
        rollout_mode = "blocking"
        summary = "Blocking runtime enforcement is active."

    return {
        "rollout_mode": rollout_mode,
        "summary": summary,
        "total_rules": total_rules,
        "blocking_rules": blocking_rules,
        "advisory_rules": advisory_rules,
        "allowlist_rules": allowlist_rules,
        "default_deny_rules": default_deny_rules,
        "read_only_rules": read_only_rules,
        "secret_path_rules": secret_path_rules,
        "unknown_egress_rules": unknown_egress_rules,
        "denied_tool_classes": sorted(denied_tool_classes),
        "blocks_requests": blocking_rules > 0,
        "advisory_only": total_rules > 0 and blocking_rules == 0,
        "default_deny": default_deny_rules > 0,
        "protects_secret_paths": secret_path_rules > 0,
        "restricts_unknown_egress": unknown_egress_rules > 0,
    }


def check_policy(policy: dict, tool_name: str, arguments: dict) -> tuple[bool, str]:
    """Evaluate runtime policy against a tools/call request.

    Returns ``(allowed, reason)``. For audit-trail callers that need the
    matched rule id, see :func:`check_policy_detail`.
    """
    allowed, reason, _rule_id = check_policy_detail(policy, tool_name, arguments)
    return allowed, reason


def check_policy_detail(policy: dict, tool_name: str, arguments: dict) -> tuple[bool, str, str | None]:
    """Evaluate runtime policy and return the matched rule id on deny.

    Same evaluation semantics as :func:`check_policy`; additionally returns
    the ``id`` of the rule that produced the deny reason (or ``None`` when
    the tool is allowed). Used by the gateway audit logger so every block
    is traceable to a specific rule even when the reason string only
    references a regex pattern (tool_name_pattern / arg_pattern).
    """
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
        rule_id = str(rule.get("id", "?"))
        if tool_name not in allowed_tools:
            return False, f"Tool '{tool_name}' not in allowlist for rule '{rule_id}'", rule_id
        break

    for rule in rules:
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue
        if rule.get("mode") == "allowlist":
            continue
        rule_id = str(rule.get("id", "?"))

        blocked = rule.get("block_tools", [])
        if blocked and ("*" in blocked or tool_name in blocked):
            return False, f"Tool '{tool_name}' is blocked by rule '{rule_id}'", rule_id

        denied_classes = {str(item).lower() for item in rule.get("deny_tool_classes", [])}
        if denied_classes:
            matched_classes = sorted(tool_classes & denied_classes)
            if matched_classes:
                joined = ", ".join(matched_classes)
                return (
                    False,
                    f"Tool '{tool_name}' matched denied tool class(es) {joined} in rule '{rule_id}'",
                    rule_id,
                )

        if rule.get("read_only") and tool_classes & {"write", "execute", "destructive"}:
            return False, f"Tool '{tool_name}' violates read-only mode in rule '{rule_id}'", rule_id

        if rule.get("block_secret_paths"):
            matched_path = next((path for path in argument_paths if _matches_secret_path(path)), None)
            if matched_path:
                return (
                    False,
                    f"Argument path '{matched_path}' matches a protected secret path in rule '{rule_id}'",
                    rule_id,
                )

        if rule.get("block_unknown_egress"):
            allowed_hosts = [str(host) for host in rule.get("allowed_hosts", [])]
            unmatched_host = next((host for host in argument_hosts if not _host_allowed(host, allowed_hosts)), None)
            if unmatched_host:
                return (
                    False,
                    f"Outbound host '{unmatched_host}' is not allowlisted in rule '{rule_id}'",
                    rule_id,
                )

        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule_id}'", rule_id

        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if len(pattern) > 500:
                    logger.warning("Skipping oversized tool_name_pattern (%d chars)", len(pattern))
                elif _safe_regex_match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'", rule_id
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
                    return (
                        False,
                        f"Argument '{arg_name}' matches blocked pattern '{arg_regex}'",
                        rule_id,
                    )
            except re.error:
                pass

    return True, "", None


def check_policy_warning(policy: dict, tool_name: str, arguments: dict) -> tuple[bool, str, str | None]:
    """Return the first advisory rule match without blocking the call."""
    advisory_rules: list[dict] = []
    for raw_rule in policy.get("rules", []):
        if not isinstance(raw_rule, dict):
            continue
        action = str(raw_rule.get("action", "warn")).lower()
        if action in ("fail", "block"):
            continue
        advisory_rule = dict(raw_rule)
        advisory_rule["action"] = "block"
        advisory_rules.append(advisory_rule)
    allowed, reason, rule_id = check_policy_detail({"rules": advisory_rules}, tool_name, arguments)
    if allowed:
        return False, "", None
    return True, reason, rule_id


# ─── Gateway policy-engine hardening ───────────────────────────────────────
# Three-tier decision state, declarative conditional access, an entry-points
# plugin registry for custom evaluators, and a deterministic OCSF event +
# SIEM/SOAR webhook fan-out. All of this is reused by the gateway relay; it is
# deterministic by construction (no inline clock / random in decision logic —
# the caller injects ``now``) so the same (agent, tool, request) under the same
# policy always yields the same decision and the same event id.


class GatewayDecision(str, Enum):
    """Three-tier gateway verdict. ``QUARANTINE`` sits between allow and deny:

    the call is blocked from the sensitive tool but the agent/session is flagged
    and heavily audited rather than hard-denied, so an operator can isolate a
    suspect agent while still observing it.
    """

    ALLOW = "allow"
    QUARANTINE = "quarantine"
    DENY = "deny"


# Env knobs (read by the gateway, surfaced here so the contract lives with the
# engine). Gateway policy failure is fail-closed by default; operators can still
# opt into explicit fail-open for local/dev compatibility.
GATEWAY_FAIL_MODE_ENV = "AGENT_BOM_GATEWAY_FAIL_MODE"
POLICY_WEBHOOK_URL_ENV = "AGENT_BOM_POLICY_WEBHOOK_URL"
POLICY_WEBHOOK_TOKEN_ENV = "AGENT_BOM_POLICY_WEBHOOK_TOKEN"
POLICY_PLUGINS_ENTRY_POINT_GROUP = "agent_bom.gateway_policy_evaluators"
_MAX_POLICY_PLUGINS = 32


def resolve_fail_mode(explicit: str | None = None) -> str:
    """Return ``"open"`` or ``"closed"`` for the missing/unloadable-policy path.

    Precedence: an explicit caller value, then ``AGENT_BOM_GATEWAY_FAIL_MODE``,
    then the secure default ``"closed"``. Any unrecognised value falls back to
    ``"closed"`` with a warning so a typo never silently disables enforcement.
    """
    raw = (explicit if explicit is not None else os.environ.get(GATEWAY_FAIL_MODE_ENV, "")).strip().lower()
    if not raw:
        return "closed"
    if raw in ("open", "closed"):
        return raw
    logger.warning("Unrecognised gateway fail mode %r; defaulting to 'closed'", raw)
    return "closed"


@dataclass(frozen=True)
class DecisionContext:
    """Deterministic inputs for one gateway decision.

    ``now`` is injected (epoch seconds) so events are reproducible — decision
    logic never calls ``time.time()`` / ``datetime.now()`` itself. ``risk_score``
    and ``attributes`` feed conditional-access gates; all are optional so a
    default context reproduces today's behaviour.
    """

    tenant_id: str = "default"
    source_agent: str = ""
    tool_name: str = ""
    now: float = 0.0
    risk_score: float | None = None
    weekday: int | None = None  # 0=Monday … 6=Sunday (UTC), injected for determinism
    minute_of_day: int | None = None  # 0..1439 (UTC)
    environment: str = ""
    source_ip: str = ""
    # Device / group / client ABAC attributes (empty = not supplied → a policy
    # that constrains one fails closed).
    device_id: str = ""
    groups: tuple[str, ...] = ()
    client_id: str = ""
    attributes: dict[str, str] = field(default_factory=dict)


def context_from_now(
    *,
    tenant_id: str = "default",
    source_agent: str = "",
    tool_name: str = "",
    now: float,
    risk_score: float | None = None,
    environment: str = "",
    source_ip: str = "",
    device_id: str = "",
    groups: tuple[str, ...] | list[str] | None = None,
    client_id: str = "",
    attributes: dict[str, str] | None = None,
) -> DecisionContext:
    """Build a :class:`DecisionContext`, deriving weekday / minute-of-day from
    the injected ``now`` so the time-window gate is deterministic for a fixed
    timestamp (UTC). Callers pass a stable ``now`` instead of letting the engine
    read the clock."""
    moment = datetime.fromtimestamp(now, tz=timezone.utc)
    return DecisionContext(
        tenant_id=tenant_id,
        source_agent=source_agent,
        tool_name=tool_name,
        now=now,
        risk_score=risk_score,
        weekday=moment.weekday(),
        minute_of_day=moment.hour * 60 + moment.minute,
        environment=environment,
        source_ip=source_ip,
        device_id=device_id,
        groups=tuple(groups or ()),
        client_id=client_id,
        attributes=dict(attributes or {}),
    )


def _coerce_minute(value: Any) -> int | None:
    """Parse ``"HH:MM"`` or an int minute-of-day; return None when unset/invalid."""
    if value is None:
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 1439 else None
    text = str(value).strip()
    if ":" in text:
        try:
            hh, mm = text.split(":", 1)
            minute = int(hh) * 60 + int(mm)
        except ValueError:
            return None
        return minute if 0 <= minute <= 1439 else None
    try:
        minute = int(text)
    except ValueError:
        return None
    return minute if 0 <= minute <= 1439 else None


def evaluate_conditions(conditions: dict[str, Any], ctx: DecisionContext) -> tuple[bool, str]:
    """Evaluate a declarative conditional-access block against the context.

    Returns ``(satisfied, reason)``. When ``satisfied`` is False the rule's
    condition gate is not met and the call should be quarantined/denied per the
    rule action. Supported keys (all optional, ANDed, deterministic):

    * ``time_window``: ``{"start": "HH:MM", "end": "HH:MM"}`` (UTC, inclusive
      start, exclusive end; wrap-around windows where start > end are allowed).
    * ``weekdays``: list of allowed weekday ints (0=Mon … 6=Sun, UTC).
    * ``min_risk_score`` / ``max_risk_score``: numeric bounds on ``risk_score``.
    * ``required_attributes``: ``{key: expected}`` — every key must match
      ``ctx.attributes`` (string-compared).
    * ``allowed_devices`` / ``allowed_groups`` / ``allowed_clients``: ABAC
      allow-lists on the calling device, the caller's directory groups
      (membership), and the MCP client application. A request that does not
      supply the constrained attribute fails closed (the condition is not met),
      so a device/group/client guardrail denies rather than waving the call
      through.

    An empty / non-dict block is satisfied (no constraint), preserving the
    behaviour of rules that carry no conditions.
    """
    if not isinstance(conditions, dict) or not conditions:
        return True, ""

    window = conditions.get("time_window")
    if isinstance(window, dict) and ctx.minute_of_day is not None:
        start = _coerce_minute(window.get("start"))
        end = _coerce_minute(window.get("end"))
        if start is not None and end is not None:
            minute = ctx.minute_of_day
            in_window = (start <= minute < end) if start <= end else (minute >= start or minute < end)
            if not in_window:
                return False, "request outside the permitted time window"

    weekdays = conditions.get("weekdays")
    if isinstance(weekdays, list) and weekdays and ctx.weekday is not None:
        allowed_days = {int(d) for d in weekdays if isinstance(d, (int, float))}
        if allowed_days and ctx.weekday not in allowed_days:
            return False, "request on a day outside the permitted weekday window"

    min_risk = conditions.get("min_risk_score")
    if isinstance(min_risk, (int, float)):
        if ctx.risk_score is None or ctx.risk_score < min_risk:
            return False, f"risk score below required minimum {min_risk}"

    max_risk = conditions.get("max_risk_score")
    if isinstance(max_risk, (int, float)):
        if ctx.risk_score is not None and ctx.risk_score > max_risk:
            return False, f"risk score above permitted maximum {max_risk}"

    required = conditions.get("required_attributes")
    if isinstance(required, dict) and required:
        for key, expected in required.items():
            if str(ctx.attributes.get(str(key), "")) != str(expected):
                return False, f"required context attribute '{key}' not satisfied"

    allowed_devices = conditions.get("allowed_devices")
    if isinstance(allowed_devices, list) and allowed_devices:
        if not ctx.device_id or ctx.device_id not in {str(d) for d in allowed_devices}:
            return False, "request device is not in the permitted device allow-list"

    allowed_groups = conditions.get("allowed_groups")
    if isinstance(allowed_groups, list) and allowed_groups:
        if not (set(ctx.groups) & {str(g) for g in allowed_groups}):
            return False, "caller is not a member of a permitted group"

    allowed_clients = conditions.get("allowed_clients")
    if isinstance(allowed_clients, list) and allowed_clients:
        if not ctx.client_id or ctx.client_id not in {str(c) for c in allowed_clients}:
            return False, "request client application is not in the permitted client allow-list"

    return True, ""


def evaluate_conditional_rules(policy: dict, ctx: DecisionContext) -> tuple[GatewayDecision, str, str | None]:
    """Apply conditional-access rules to a decision context.

    A rule participates when it carries a ``conditions`` block; its ``action``
    selects the verdict when the conditions are NOT satisfied:

    * ``action: "block"``/``"fail"`` → :data:`GatewayDecision.DENY`
    * ``action: "quarantine"``       → :data:`GatewayDecision.QUARANTINE`

    The first unsatisfied conditional rule wins (deny outranks quarantine when a
    deny rule is encountered first). Returns ``(ALLOW, "", None)`` when every
    conditional rule is satisfied (or none are present).
    """
    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        return GatewayDecision.ALLOW, "", None
    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            continue
        conditions = raw_rule.get("conditions")
        if not isinstance(conditions, dict) or not conditions:
            continue
        scope_tool = raw_rule.get("tool_name")
        if scope_tool and scope_tool != ctx.tool_name:
            continue
        satisfied, reason = evaluate_conditions(conditions, ctx)
        if satisfied:
            continue
        rule_id = str(raw_rule.get("id", "?"))
        action = str(raw_rule.get("action", "block")).lower()
        if action == "quarantine":
            return GatewayDecision.QUARANTINE, f"{reason} (rule '{rule_id}')", rule_id
        return GatewayDecision.DENY, f"{reason} (rule '{rule_id}')", rule_id
    return GatewayDecision.ALLOW, "", None


# ─── Plugin policy/detector registry (entry-points) ────────────────────────


@dataclass(frozen=True)
class PluginDecision:
    """Verdict returned by a third-party policy evaluator plugin."""

    decision: GatewayDecision
    reason: str = ""


# A plugin evaluator is ``Callable[[DecisionContext, dict], PluginDecision|None]``
# where the dict is the active policy. Returning ``None`` / ALLOW means "no
# opinion". Plugins are discovered via the ``agent_bom.gateway_policy_evaluators``
# entry-point group (opt-in through AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS, the
# same switch the rest of the project uses) and any plugin that raises is
# isolated — logged and skipped — never fatal to the relay.
PolicyEvaluator = Callable[[DecisionContext, dict], "PluginDecision | None"]

_REGISTERED_EVALUATORS: dict[str, PolicyEvaluator] = {}
_ENTRYPOINT_EVALUATORS_LOADED = False
_EVALUATOR_WARNINGS: list[str] = []


def register_policy_evaluator(name: str, evaluator: PolicyEvaluator) -> None:
    """Register a custom policy evaluator in-process (tests / embedding)."""
    _REGISTERED_EVALUATORS[name] = evaluator


def _load_entrypoint_evaluators() -> None:
    global _ENTRYPOINT_EVALUATORS_LOADED
    if _ENTRYPOINT_EVALUATORS_LOADED:
        return
    _ENTRYPOINT_EVALUATORS_LOADED = True
    try:
        from agent_bom.extensions import (
            entrypoint_extensions_enabled,
            iter_entry_point_registrations,
            sanitize_registry_warning,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("policy evaluator entry-point discovery unavailable: %s", exc)
        return
    if not entrypoint_extensions_enabled():
        return

    def _coerce(value: Any, entry_point_name: str) -> tuple[str, PolicyEvaluator]:
        name = str(getattr(value, "name", entry_point_name)).strip() or entry_point_name
        evaluator = getattr(value, "evaluate", value)
        if not callable(evaluator):
            raise ValueError(f"policy evaluator '{name}' is not callable")
        return name, evaluator

    try:
        registrations = iter_entry_point_registrations(
            group=POLICY_PLUGINS_ENTRY_POINT_GROUP,
            coerce=_coerce,
            warnings=_EVALUATOR_WARNINGS,
            max_entry_points=_MAX_POLICY_PLUGINS,
        )
    except Exception as exc:  # noqa: BLE001
        _EVALUATOR_WARNINGS.append(sanitize_registry_warning(f"policy evaluator discovery failed: {exc}"))
        return
    for name, evaluator in registrations:
        _REGISTERED_EVALUATORS.setdefault(name, evaluator)


def evaluate_policy_plugins(
    ctx: DecisionContext,
    policy: dict,
    *,
    fail_closed: bool = False,
) -> tuple[GatewayDecision, str, str | None]:
    """Compose all registered policy-evaluator plugins into one verdict.

    Each plugin is isolated. In explicit fail-open mode a raising plugin is
    logged and skipped for local/dev compatibility. In fail-closed mode a
    raising plugin produces a DENY so a broken evaluator cannot silently disable
    gateway enforcement. DENY outranks QUARANTINE outranks ALLOW; the strictest
    verdict across plugins wins, with the first plugin producing that verdict
    named.
    """
    _load_entrypoint_evaluators()
    if not _REGISTERED_EVALUATORS:
        return GatewayDecision.ALLOW, "", None
    worst = GatewayDecision.ALLOW
    worst_reason = ""
    worst_name: str | None = None
    _rank = {GatewayDecision.ALLOW: 0, GatewayDecision.QUARANTINE: 1, GatewayDecision.DENY: 2}
    for name in sorted(_REGISTERED_EVALUATORS):
        evaluator = _REGISTERED_EVALUATORS[name]
        try:
            verdict = evaluator(ctx, policy)
        except Exception as exc:  # noqa: BLE001 — isolate a misbehaving plugin
            logger.warning("policy evaluator plugin %r raised: %s", name, exc)
            if fail_closed:
                return GatewayDecision.DENY, "policy evaluator unavailable; fail-closed mode denies", name
            continue
        if verdict is None:
            continue
        decision = verdict.decision if isinstance(verdict, PluginDecision) else GatewayDecision.ALLOW
        if _rank.get(decision, 0) > _rank[worst]:
            worst = decision
            worst_reason = verdict.reason if isinstance(verdict, PluginDecision) else ""
            worst_name = name
    return worst, worst_reason, worst_name


def policy_evaluator_warnings() -> list[str]:
    """Return sanitized non-fatal plugin discovery warnings."""
    _load_entrypoint_evaluators()
    return list(_EVALUATOR_WARNINGS)


def _reset_policy_evaluators_for_tests() -> None:
    global _ENTRYPOINT_EVALUATORS_LOADED
    _REGISTERED_EVALUATORS.clear()
    _EVALUATOR_WARNINGS.clear()
    _ENTRYPOINT_EVALUATORS_LOADED = False


# ─── Deterministic OCSF event + SIEM/SOAR webhook fan-out ──────────────────

# OCSF Detection Finding (class_uid 2004) severity ids.
_OCSF_DECISION_SEVERITY = {
    GatewayDecision.DENY: (5, "Critical"),
    GatewayDecision.QUARANTINE: (4, "High"),
    GatewayDecision.ALLOW: (1, "Informational"),
}


def policy_event_id(
    *,
    tenant_id: str,
    source_agent: str,
    tool_name: str,
    decision: GatewayDecision,
    reason: str,
    now: float,
) -> str:
    """Derive a stable, deterministic event id from the decision inputs.

    Same (tenant, agent, tool, decision, reason, now) → same id, every time.
    This is also the webhook idempotency key, so a retried delivery never
    double-records downstream. No ``uuid4()`` / ``random`` — pure hash of inputs.
    """
    digest = hashlib.sha256(
        "\x1f".join(
            (
                tenant_id,
                source_agent,
                tool_name,
                decision.value,
                reason,
                repr(now),
            )
        ).encode("utf-8")
    ).hexdigest()
    return f"gwpol-{digest[:32]}"


def build_policy_ocsf_event(
    *,
    decision: GatewayDecision,
    reason: str,
    ctx: DecisionContext,
    policy_source: str = "gateway",
    product_version: str = "0.0.0",
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build a normalized OCSF Detection Finding for a deny/quarantine.

    Deterministic: the ``time`` field and ``uid`` derive from the injected
    ``ctx.now`` rather than the wall clock, so the same decision reproduces an
    identical event (verified by the determinism test).
    """
    severity_id, severity_name = _OCSF_DECISION_SEVERITY.get(decision, (1, "Informational"))
    uid = event_id or policy_event_id(
        tenant_id=ctx.tenant_id,
        source_agent=ctx.source_agent,
        tool_name=ctx.tool_name,
        decision=decision,
        reason=reason,
        now=ctx.now,
    )
    finding = {
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "severity_id": severity_id,
        "severity": severity_name,
        "time": int(ctx.now * 1000),
        "finding_info": {
            "title": f"Gateway policy {decision.value}",
            "desc": reason or f"Gateway policy {decision.value}",
            "types": [policy_source],
            "uid": uid,
        },
        "evidences": [
            {
                "data": json.dumps(
                    {
                        "tenant_id": ctx.tenant_id,
                        "source_agent": ctx.source_agent,
                        "tool_name": ctx.tool_name,
                        "decision": decision.value,
                        "policy_source": policy_source,
                        "environment": ctx.environment,
                    },
                    sort_keys=True,
                )
            }
        ],
        "metadata": {
            "product": {"name": "agent-bom", "vendor_name": "msaad00", "version": product_version},
            "version": "1.1.0",
            "log_name": "agent-bom-gateway-policy",
            "uid": uid,
        },
        "status_id": 1,
        "status": "New",
        # Idempotency key surfaced at top level so SIEM/SOAR de-dupe on retry.
        "idempotency_key": uid,
    }
    return finding


def _webhook_backoff_seconds(attempt: int, *, base: float, rng: random.Random) -> float:
    """Exponential backoff with full jitter for webhook retries (deterministic
    when a seeded ``rng`` is injected, so the retry test is reproducible)."""
    ceiling = base * (2**attempt)
    return rng.uniform(0.0, ceiling)


def deliver_policy_webhook(
    event: dict[str, Any],
    *,
    url: str | None = None,
    token: str | None = None,
    max_attempts: int = 3,
    base_backoff_seconds: float = 0.5,
    poster: Callable[[str, dict[str, Any], dict[str, str]], int] | None = None,
    sleep: Callable[[float], None] | None = None,
    rng: random.Random | None = None,
) -> bool:
    """POST an OCSF policy event to a SIEM/SOAR webhook, fail-safe.

    Never blocks or crashes the relay: webhook errors are handled with bounded
    retries (exponential backoff + jitter) for transient/rate-limit failures,
    then dropped with a clear operator-facing warning naming WHAT failed, the
    STATUS, and what to CHECK (URL / credential / rate). Returns True on a 2xx
    delivery, False when no webhook is configured or every attempt is exhausted.

    The request carries the event's ``idempotency_key`` as a header so a retried
    delivery never double-records downstream. ``poster``/``sleep``/``rng`` are
    injectable for tests; in production a small httpx POST is used.
    """
    target = url if url is not None else os.environ.get(POLICY_WEBHOOK_URL_ENV, "").strip()
    if not target:
        return False
    auth = token if token is not None else os.environ.get(POLICY_WEBHOOK_TOKEN_ENV, "").strip()
    idempotency_key = str(event.get("idempotency_key") or event.get("metadata", {}).get("uid") or "")
    headers = {"Content-Type": "application/json"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
        headers["X-Agent-Bom-Idempotency-Key"] = idempotency_key
    if auth:
        headers["Authorization"] = f"Bearer {auth}"

    _rng = rng or random.Random()
    _sleep = sleep or time.sleep
    _poster = poster or _default_webhook_poster
    attempts = max(1, max_attempts)

    for attempt in range(attempts):
        try:
            status = _poster(target, event, headers)
        except Exception as exc:  # noqa: BLE001 — connection/DNS/timeout
            if attempt + 1 < attempts:
                _sleep(_webhook_backoff_seconds(attempt, base=base_backoff_seconds, rng=_rng))
                continue
            logger.warning(
                "policy webhook delivery failed after %d attempt(s): connection error %s. "
                "Check the AGENT_BOM_POLICY_WEBHOOK_URL is reachable; event %s dropped (relay unaffected).",
                attempts,
                exc,
                idempotency_key or "?",
            )
            return False
        if 200 <= status < 300:
            return True
        if status in (401, 403):
            logger.warning(
                "policy webhook rejected with HTTP %d (auth). Check the AGENT_BOM_POLICY_WEBHOOK_TOKEN "
                "credential/scope; event %s dropped (relay unaffected).",
                status,
                idempotency_key or "?",
            )
            return False
        if status == 429 or status >= 500:
            if attempt + 1 < attempts:
                _sleep(_webhook_backoff_seconds(attempt, base=base_backoff_seconds, rng=_rng))
                continue
            kind = "rate limited" if status == 429 else "server error"
            logger.warning(
                "policy webhook %s with HTTP %d after %d attempt(s). Check the endpoint %s "
                "(rate limits / availability); event %s dropped (relay unaffected).",
                kind,
                status,
                attempts,
                "rate" if status == 429 else "URL",
                idempotency_key or "?",
            )
            return False
        logger.warning(
            "policy webhook returned unexpected HTTP %d. Check the AGENT_BOM_POLICY_WEBHOOK_URL "
            "target; event %s dropped (relay unaffected).",
            status,
            idempotency_key or "?",
        )
        return False
    return False


def _default_webhook_poster(url: str, event: dict[str, Any], headers: dict[str, str]) -> int:
    import httpx

    response = httpx.post(url, json=event, headers=headers, timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0))
    return response.status_code
