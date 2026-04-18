"""MCP tool-schema validation rules — OWASP-mapped catalog.

The product previously detected schema-level capability hints
(`shell-execution-capability`, `network-egress-capability`, etc.) via
the heuristic linter in :mod:`agent_bom.mcp_introspect`. That surfaced
the *signal* but did not give operators a rule ID they could route to
a compliance control.

This module turns those hints — plus a few additional schema patterns
we care about for OWASP LLM Top 10 (LLM01–LLM10) and the OWASP MCP
Top 10 — into structured rule findings. Each rule carries:

- a stable ``rule_id`` (e.g. ``MCP-TOOL-01-shell-input``) so dashboards
  and SIEM filters can pin behavior
- a ``severity`` aligned with the canonical :class:`Severity` ladder
- ``owasp_tags`` and ``owasp_mcp_tags`` so the compliance-report
  endpoint and ``BlastRadius`` can route the finding to the right
  control without a separate tag-assignment pass
- ``message`` + ``evidence`` so the operator can act without re-running
  the analyzer

Rules are intentionally narrow: only fire when the underlying schema
shape genuinely matches the threat. False positives here become alert
fatigue and erode trust in the catalog. New rules require a test in
``tests/test_mcp_tool_rules.py`` that verifies the rule fires on a
representative bad schema and stays silent on a clean one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import MCPTool


# ─── Hint regexes ──────────────────────────────────────────────────────────────
# Reused from mcp_introspect to keep the two analyzers in sync.

_PATH_HINT_RE = re.compile(r"(path|file|dir|cwd|workspace)", re.IGNORECASE)
_URL_HINT_RE = re.compile(r"(url|uri|endpoint|host|domain|webhook)", re.IGNORECASE)
_SHELL_HINT_RE = re.compile(r"(cmd|command|shell|exec|script)", re.IGNORECASE)
_SQL_HINT_RE = re.compile(r"(query|sql|statement|stmt)", re.IGNORECASE)
_PROMPT_HINT_RE = re.compile(r"(prompt|instruction|system|markdown|html|svg)", re.IGNORECASE)
_CRED_HINT_RE = re.compile(r"(token|secret|password|credential|api[_-]?key|access[_-]?key)", re.IGNORECASE)


@dataclass(frozen=True)
class MCPRuleFinding:
    """A single rule violation against an MCP tool input schema."""

    rule_id: str
    severity: str  # "low" | "medium" | "high" | "critical"
    title: str
    message: str
    evidence: str
    tool_name: str
    property_name: str | None = None
    owasp_tags: tuple[str, ...] = field(default_factory=tuple)
    owasp_mcp_tags: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "evidence": self.evidence,
            "tool_name": self.tool_name,
            "property_name": self.property_name,
            "owasp_tags": list(self.owasp_tags),
            "owasp_mcp_tags": list(self.owasp_mcp_tags),
            "cwe_ids": list(self.cwe_ids),
        }


# ─── Rule definitions ─────────────────────────────────────────────────────────
#
# Each rule is a pure function of (tool, prop_name, prop_schema) → list of
# findings. Returning an empty list means the rule did not fire.


def _is_freeform_string(prop_schema: dict) -> bool:
    """A string property with no enum, no maxLength, and no pattern is freeform."""
    return (
        prop_schema.get("type") == "string"
        and not prop_schema.get("enum")
        and not prop_schema.get("maxLength")
        and not prop_schema.get("pattern")
    )


def _rule_shell_input(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-01 — tool accepts an unbounded string named like a shell command."""
    if not _SHELL_HINT_RE.search(prop_name):
        return []
    if not _is_freeform_string(prop_schema):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-01-shell-input",
            severity="critical",
            title="MCP tool accepts unbounded shell-style input",
            message=(
                f"Tool `{tool_name}` accepts a freeform string parameter `{prop_name}` whose name "
                "implies command execution. Without an enum or pattern an attacker can pivot the "
                "tool into arbitrary shell execution via prompt injection."
            ),
            evidence=f"property `{prop_name}` has type=string with no enum, maxLength, or pattern",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM02-Insecure-Output-Handling", "LLM06-Sensitive-Information-Disclosure"),
            owasp_mcp_tags=("MCP01-Untrusted-Tool-Inputs", "MCP04-Excessive-Capability"),
            cwe_ids=("CWE-78",),  # OS Command Injection
        )
    ]


def _rule_path_traversal(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-02 — tool accepts an unbounded path with no allow-list."""
    if not _PATH_HINT_RE.search(prop_name):
        return []
    if not _is_freeform_string(prop_schema):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-02-path-traversal",
            severity="high",
            title="MCP tool accepts unbounded file path",
            message=(
                f"Tool `{tool_name}` accepts a freeform string parameter `{prop_name}` that names "
                "a file/path target. Without an allow-list pattern, an attacker can read or write "
                "outside the intended scope via `..` traversal or absolute paths."
            ),
            evidence=f"property `{prop_name}` has type=string with no pattern constraint",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM02-Insecure-Output-Handling",),
            owasp_mcp_tags=("MCP01-Untrusted-Tool-Inputs", "MCP05-Insecure-Defaults"),
            cwe_ids=("CWE-22",),  # Path Traversal
        )
    ]


def _rule_ssrf(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-03 — tool accepts an unbounded URL/host with no allow-list."""
    if not _URL_HINT_RE.search(prop_name):
        return []
    if not _is_freeform_string(prop_schema):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-03-ssrf",
            severity="high",
            title="MCP tool accepts unbounded URL or host",
            message=(
                f"Tool `{tool_name}` accepts a freeform string parameter `{prop_name}` that names "
                "a network destination. Without an allow-list, an attacker can pivot the tool into "
                "SSRF against cloud metadata, internal services, or arbitrary external destinations."
            ),
            evidence=f"property `{prop_name}` has type=string with no enum or pattern",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM02-Insecure-Output-Handling",),
            owasp_mcp_tags=("MCP01-Untrusted-Tool-Inputs", "MCP04-Excessive-Capability"),
            cwe_ids=("CWE-918",),  # SSRF
        )
    ]


def _rule_sql_injection(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-04 — tool accepts an unbounded string named like a SQL statement."""
    if not _SQL_HINT_RE.search(prop_name):
        return []
    if not _is_freeform_string(prop_schema):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-04-sql-injection",
            severity="high",
            title="MCP tool accepts unbounded SQL-style input",
            message=(
                f"Tool `{tool_name}` accepts a freeform string parameter `{prop_name}` whose name "
                "implies a SQL statement. Without parameterization or an enum of allowed shapes, "
                "the tool can be steered into injection via prompt-driven query rewriting."
            ),
            evidence=f"property `{prop_name}` has type=string with no enum or pattern",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM02-Insecure-Output-Handling",),
            owasp_mcp_tags=("MCP01-Untrusted-Tool-Inputs",),
            cwe_ids=("CWE-89",),  # SQL Injection
        )
    ]


def _rule_credential_in_input(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-05 — tool accepts a credential as an input parameter."""
    if not _CRED_HINT_RE.search(prop_name):
        return []
    if prop_schema.get("type") not in (None, "string"):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-05-credential-in-input",
            severity="medium",
            title="MCP tool accepts credential-shaped input",
            message=(
                f"Tool `{tool_name}` accepts parameter `{prop_name}` whose name implies a "
                "credential. Credentials passed through tool calls flow through prompt history, "
                "logs, and audit trails — they should be injected via the server environment, "
                "not the LLM-controlled input surface."
            ),
            evidence=f"property name `{prop_name}` matches credential pattern",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM06-Sensitive-Information-Disclosure",),
            owasp_mcp_tags=("MCP02-Credential-Leakage",),
            cwe_ids=("CWE-522",),  # Insufficiently Protected Credentials
        )
    ]


def _rule_prompt_passthrough(tool_name: str, prop_name: str, prop_schema: dict) -> list[MCPRuleFinding]:
    """MCP-TOOL-06 — tool accepts a property described as a prompt or instruction."""
    desc = (prop_schema.get("description") or "").strip()
    if not desc or not _PROMPT_HINT_RE.search(desc):
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-06-prompt-passthrough",
            severity="medium",
            title="MCP tool input passes a prompt-shaped value",
            message=(
                f"Tool `{tool_name}` parameter `{prop_name}` description names it as a prompt / "
                "instruction. Prompt-shaped tool inputs are a primary OWASP LLM01 injection vector "
                "when the tool composes the value into another LLM call without sanitization."
            ),
            evidence=f"description references prompt/instruction/system: \"{desc[:80]}\"",
            tool_name=tool_name,
            property_name=prop_name,
            owasp_tags=("LLM01-Prompt-Injection",),
            owasp_mcp_tags=("MCP01-Untrusted-Tool-Inputs",),
            cwe_ids=("CWE-94",),  # Code Injection
        )
    ]


def _rule_weak_description(tool_name: str, prop_name: str | None, prop_schema: dict, *, tool_desc: str) -> list[MCPRuleFinding]:
    """MCP-TOOL-07 — tool description is missing or trivially short.

    Operates at the tool level, not per-property. The function still takes
    ``prop_name``/``prop_schema`` to keep the rule signature uniform with the
    per-property rules so the dispatcher does not branch.
    """
    if prop_name is not None:
        return []
    if tool_desc and len(tool_desc.strip()) >= 12:
        return []
    return [
        MCPRuleFinding(
            rule_id="MCP-TOOL-07-weak-description",
            severity="low",
            title="MCP tool description is missing or trivially short",
            message=(
                f"Tool `{tool_name}` has no usable description. LLMs route tool selection by "
                "description; an empty or trivial description encourages the model to pick the "
                "tool indiscriminately and lets a malicious server hide intent from the agent."
            ),
            evidence=f"tool description length is {len(tool_desc.strip()) if tool_desc else 0}",
            tool_name=tool_name,
            property_name=None,
            owasp_tags=("LLM05-Improper-Output-Handling",),
            owasp_mcp_tags=("MCP07-Confusing-Tool-Surface",),
            cwe_ids=(),
        )
    ]


_PROPERTY_RULES = (
    _rule_shell_input,
    _rule_path_traversal,
    _rule_ssrf,
    _rule_sql_injection,
    _rule_credential_in_input,
    _rule_prompt_passthrough,
)


def evaluate_tool(tool: "MCPTool") -> list[MCPRuleFinding]:
    """Evaluate every rule against an MCP tool and return the firing findings.

    The dispatcher walks ``input_schema.properties`` once; each property is
    fed into every per-property rule. Tool-level rules (currently just
    weak-description) run separately.
    """
    findings: list[MCPRuleFinding] = []

    findings.extend(_rule_weak_description(tool.name, None, {}, tool_desc=tool.description or ""))

    schema = tool.input_schema or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if not isinstance(properties, dict):
        return findings

    for prop_name, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            continue
        for rule in _PROPERTY_RULES:
            findings.extend(rule(tool.name, prop_name, prop_schema))

    return findings


def evaluate_server_tools(tools: list["MCPTool"]) -> list[MCPRuleFinding]:
    """Evaluate every rule across a server's tool inventory."""
    out: list[MCPRuleFinding] = []
    for tool in tools:
        out.extend(evaluate_tool(tool))
    return out
