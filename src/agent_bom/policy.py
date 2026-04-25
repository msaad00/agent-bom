"""Policy-as-code engine for agent-bom.

Allows teams to define declarative security rules that are evaluated against
scan results and produce structured violations. Rules are loaded from a JSON
or YAML policy file and evaluated against BlastRadius findings.

Supports two rule styles:

1. **Declarative conditions** (existing, backwards-compatible):
   Each field is a discrete condition. All conditions are ANDed.

2. **Expression-based conditions** (new in v0.58.0):
   Use the ``condition`` field with a safe expression language supporting
   comparisons, boolean operators, and field access.

Example policy file (policy.json):
{
  "version": "2",
  "name": "production-security-policy",
  "rules": [
    {
      "id": "no-critical",
      "description": "No critical vulnerabilities allowed",
      "severity_gte": "CRITICAL",
      "action": "fail"
    },
    {
      "id": "high-epss-with-creds",
      "description": "High EPSS score with exposed credentials",
      "condition": "epss_score > 0.7 and has_credentials and severity >= HIGH",
      "action": "fail"
    },
    {
      "id": "risky-ai-package",
      "description": "AI packages with low scorecard or KEV status",
      "condition": "ai_risk and (is_kev or scorecard_score < 3.0)",
      "action": "fail"
    }
  ]
}
"""

from __future__ import annotations

import json
import operator
import re
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}
RISK_LEVEL_ORDER = {"high": 3, "medium": 2, "low": 1}


# ─── Expression engine ─────────────────────────────────────────────────────
# A safe, minimal expression evaluator for policy conditions.
# Supports: field access, comparisons (>, <, >=, <=, ==, !=),
#           boolean operators (and, or, not), parentheses, literals.
# NO arbitrary code execution — only whitelisted fields and operators.

_COMPARISON_OPS = {
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

# Token types for the expression lexer
_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (\d+\.\d+|\d+)          |  # number literal
        "((?:[^"\\]|\\.)*)"     |  # double-quoted string
        '((?:[^'\\]|\\.)*)'     |  # single-quoted string
        (>=|<=|!=|==|>|<)       |  # comparison operator
        (\(|\))                 |  # parentheses
        (and|or|not)\b          |  # boolean operators
        (true|false)\b          |  # boolean literals
        ([a-zA-Z_][a-zA-Z0-9_]*)  # identifier
    )\s*
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(expr: str) -> list[tuple[str, str]]:
    """Tokenize an expression string into (type, value) pairs."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            rest = expr[pos:].strip()
            if not rest:
                break
            raise ValueError(f"Invalid token in expression at position {pos}: {rest[:20]!r}")
        if m.group(1) is not None:
            tokens.append(("NUMBER", m.group(1)))
        elif m.group(2) is not None:
            tokens.append(("STRING", m.group(2)))
        elif m.group(3) is not None:
            tokens.append(("STRING", m.group(3)))
        elif m.group(4) is not None:
            tokens.append(("CMP", m.group(4)))
        elif m.group(5) is not None:
            tokens.append(("PAREN", m.group(5)))
        elif m.group(6) is not None:
            tokens.append(("BOOL_OP", m.group(6).lower()))
        elif m.group(7) is not None:
            tokens.append(("BOOL_LIT", m.group(7).lower()))
        elif m.group(8) is not None:
            tokens.append(("IDENT", m.group(8)))
        pos = m.end()
    return tokens


def _extract_field(br, name: str):
    """Extract a field value from a BlastRadius object for expression evaluation.

    Only whitelisted fields are accessible — no arbitrary attribute access.
    """
    field_map = {
        # Vulnerability fields
        "severity": lambda b: SEVERITY_ORDER.get(b.vulnerability.severity.value.upper(), 0),
        "cvss_score": lambda b: b.vulnerability.cvss_score or 0.0,
        "epss_score": lambda b: b.vulnerability.epss_score or 0.0,
        "is_kev": lambda b: bool(b.vulnerability.is_kev),
        "has_fix": lambda b: bool(b.vulnerability.fixed_version),
        "vuln_id": lambda b: b.vulnerability.id,
        # Package fields
        "package_name": lambda b: b.package.name,
        "ecosystem": lambda b: b.package.ecosystem,
        "scorecard_score": lambda b: b.package.scorecard_score if b.package.scorecard_score is not None else 0.0,
        "is_malicious": lambda b: getattr(b.package, "is_malicious", False),
        # Blast radius fields
        "risk_score": lambda b: b.risk_score,
        "agent_count": lambda b: len(b.affected_agents),
        "server_count": lambda b: len(b.affected_servers),
        "tool_count": lambda b: len(b.exposed_tools),
        "credential_count": lambda b: len(b.exposed_credentials),
        "has_credentials": lambda b: bool(b.exposed_credentials),
        "ai_risk": lambda b: bool(b.ai_risk_context),
        # Tags
        "owasp_tags": lambda b: getattr(b, "owasp_tags", []),
        "owasp_mcp_tags": lambda b: getattr(b, "owasp_mcp_tags", []),
        "owasp_agentic_tags": lambda b: getattr(b, "owasp_agentic_tags", []),
        "nist_csf_tags": lambda b: getattr(b, "nist_csf_tags", []),
        "nist_ai_rmf_tags": lambda b: getattr(b, "nist_ai_rmf_tags", []),
        "nist_800_53_tags": lambda b: getattr(b, "nist_800_53_tags", []),
        "atlas_tags": lambda b: getattr(b, "atlas_tags", []),
        "attack_tags": lambda b: getattr(b, "attack_tags", []),
        "iso_27001_tags": lambda b: getattr(b, "iso_27001_tags", []),
        "soc2_tags": lambda b: getattr(b, "soc2_tags", []),
        "cis_tags": lambda b: getattr(b, "cis_tags", []),
        "cmmc_tags": lambda b: getattr(b, "cmmc_tags", []),
        "eu_ai_act_tags": lambda b: getattr(b, "eu_ai_act_tags", []),
        "fedramp_tags": lambda b: getattr(b, "fedramp_tags", []),
    }

    # Severity name comparisons: resolve "HIGH", "CRITICAL" etc. to ordinal
    if name.upper() in SEVERITY_ORDER:
        return SEVERITY_ORDER[name.upper()]

    getter = field_map.get(name)
    if getter is None:
        raise ValueError(f"Unknown field in policy expression: {name!r}")
    return getter(br)


class _ExprParser:
    """Recursive descent parser for policy expressions.

    Grammar:
        expr     → or_expr
        or_expr  → and_expr ("or" and_expr)*
        and_expr → not_expr ("and" not_expr)*
        not_expr → "not" not_expr | cmp_expr
        cmp_expr → primary (CMP primary)?
        primary  → "(" expr ")" | NUMBER | STRING | BOOL_LIT | IDENT
    """

    _MAX_TOKENS = 200  # Guard against overly complex expressions

    def __init__(self, tokens: list[tuple[str, str]], br):
        if len(tokens) > self._MAX_TOKENS:
            raise ValueError(f"Expression too complex ({len(tokens)} tokens, max {self._MAX_TOKENS})")
        self.tokens = tokens
        self.pos = 0
        self.br = br
        self._depth = 0

    def peek(self) -> tuple[str, str] | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> tuple[str, str]:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> bool:
        result = self._or_expr()
        if self.pos < len(self.tokens):
            raise ValueError(f"Unexpected token: {self.tokens[self.pos]}")
        return bool(result)

    def _or_expr(self):
        left = self._and_expr()
        while self.peek() and self.peek()[0] == "BOOL_OP" and self.peek()[1] == "or":  # type: ignore[index]
            self.consume()
            right = self._and_expr()
            left = left or right
        return left

    def _and_expr(self):
        left = self._not_expr()
        while self.peek() and self.peek()[0] == "BOOL_OP" and self.peek()[1] == "and":  # type: ignore[index]
            self.consume()
            right = self._not_expr()
            left = left and right
        return left

    def _not_expr(self):
        if self.peek() and self.peek()[0] == "BOOL_OP" and self.peek()[1] == "not":  # type: ignore[index]
            self.consume()
            return not self._not_expr()
        return self._cmp_expr()

    def _cmp_expr(self):
        left = self._primary()
        if self.peek() and self.peek()[0] == "CMP":  # type: ignore[index]
            _, op_str = self.consume()
            right = self._primary()
            op_func = _COMPARISON_OPS[op_str]
            return op_func(left, right)
        return left

    def _primary(self):
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")

        if tok[0] == "PAREN" and tok[1] == "(":
            self._depth += 1
            if self._depth > 20:
                raise ValueError("Expression nesting too deep (max 20 levels)")
            self.consume()
            result = self._or_expr()
            closing = self.peek()
            if not closing or closing[0] != "PAREN" or closing[1] != ")":
                raise ValueError("Missing closing parenthesis")
            self.consume()
            self._depth -= 1
            return result

        if tok[0] == "NUMBER":
            self.consume()
            return float(tok[1]) if "." in tok[1] else int(tok[1])

        if tok[0] == "STRING":
            self.consume()
            return tok[1]

        if tok[0] == "BOOL_LIT":
            self.consume()
            return tok[1] == "true"

        if tok[0] == "IDENT":
            self.consume()
            return _extract_field(self.br, tok[1])

        raise ValueError(f"Unexpected token: {tok}")


def evaluate_expression(expr: str, br) -> bool:
    """Evaluate a policy expression against a BlastRadius finding.

    Returns True if the expression matches (rule should trigger).
    """
    tokens = _tokenize(expr)
    if not tokens:
        return False
    parser = _ExprParser(tokens, br)
    return parser.parse()


POLICY_TEMPLATE = {
    "version": "2",
    "name": "my-security-policy",
    "rules": [
        {
            "id": "no-kev",
            "description": "CISA Known Exploited Vulnerabilities must be fixed immediately",
            "is_kev": True,
            "action": "fail",
        },
        {
            "id": "no-critical",
            "description": "No critical vulnerabilities allowed",
            "severity_gte": "CRITICAL",
            "action": "fail",
        },
        {
            "id": "no-ai-creds-high",
            "description": "AI framework packages with exposed credentials must not have high+ vulnerabilities",
            "ai_risk": True,
            "has_credentials": True,
            "severity_gte": "HIGH",
            "action": "fail",
        },
        {
            "id": "high-epss-with-creds",
            "description": "High exploit probability with exposed credentials",
            "condition": "epss_score > 0.7 and has_credentials",
            "action": "fail",
        },
        {
            "id": "risky-ai-or-kev",
            "description": "AI packages that are either KEV or have poor maintainer reputation",
            "condition": "ai_risk and (is_kev or scorecard_score < 3.0)",
            "action": "fail",
        },
        {
            "id": "warn-high-with-creds",
            "description": "High vulnerabilities in servers with credentials trigger a warning",
            "has_credentials": True,
            "severity_gte": "HIGH",
            "action": "warn",
        },
        {
            "id": "warn-medium",
            "description": "Medium vulnerabilities generate advisory warnings",
            "severity_gte": "MEDIUM",
            "action": "warn",
        },
        {
            "id": "no-unverified-high",
            "description": "Unverified MCP servers with high+ vulnerabilities are blocked",
            "unverified_server": True,
            "severity_gte": "HIGH",
            "action": "fail",
        },
        {
            "id": "warn-excessive-agency",
            "description": "Servers with >5 tools and any CVE trigger excessive agency warning",
            "condition": "tool_count > 5",
            "action": "warn",
        },
        {
            "id": "no-high-risk-server-cve",
            "description": "High-risk registry servers must not have critical CVEs",
            "registry_risk_gte": "high",
            "severity_gte": "CRITICAL",
            "action": "fail",
        },
        {
            "id": "wide-blast-radius",
            "description": "Vulnerabilities affecting 3+ agents with credentials",
            "condition": "agent_count >= 3 and credential_count > 0 and severity >= MEDIUM",
            "action": "fail",
        },
    ],
}


def load_policy(path: str) -> dict:
    """Load a policy file (JSON or YAML).

    Raises ValueError with a clear message if the file is invalid.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    text = p.read_text()

    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml

            data = yaml.safe_load(text)
        except ImportError:
            raise ImportError("PyYAML is required for YAML policy files: pip install pyyaml")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in policy file: {e}")

    _validate_policy(data)
    return data


def _validate_policy(policy: dict) -> None:
    """Validate policy structure and condition syntax at load time.

    Catches invalid conditions immediately rather than at evaluation time,
    giving operators clear feedback on misconfigured policies.
    """
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    if "rules" not in policy:
        raise ValueError("Policy must have a 'rules' array")
    if not isinstance(policy["rules"], list):
        raise ValueError("Policy 'rules' must be an array")
    for i, rule in enumerate(policy["rules"]):
        if "id" not in rule:
            raise ValueError(f"Rule at index {i} missing 'id'")
        if rule.get("action") not in ("fail", "warn", "jira", None):
            raise ValueError(f"Rule '{rule['id']}' action must be 'fail', 'warn', or 'jira'")
        # Validate condition expression syntax at load time (fail-fast)
        condition = rule.get("condition")
        if condition and isinstance(condition, str):
            try:
                _tokenize(condition)
            except ValueError as e:
                raise ValueError(f"Rule '{rule['id']}' has invalid condition syntax: {e}") from e

        # Validate declarative field types
        rid = rule.get("id", f"index-{i}")
        int_fields = ("min_agents", "min_tools")
        float_fields = ("max_epss_score", "min_scorecard_score")
        str_fields = ("severity_gte", "ecosystem", "package_name_contains", "owasp_tag", "owasp_mcp_tag", "registry_risk_gte")
        bool_fields = ("is_kev", "ai_risk", "has_credentials", "unverified_server", "has_fix")
        for f in int_fields:
            if f in rule and not isinstance(rule[f], int):
                raise ValueError(f"Rule '{rid}' field '{f}' must be an integer")
        for f in float_fields:
            if f in rule and not isinstance(rule[f], (int, float)):
                raise ValueError(f"Rule '{rid}' field '{f}' must be a number")
        for f in str_fields:
            if f in rule and not isinstance(rule[f], str):
                raise ValueError(f"Rule '{rid}' field '{f}' must be a string")
        for f in bool_fields:
            if f in rule and not isinstance(rule[f], bool):
                raise ValueError(f"Rule '{rid}' field '{f}' must be a boolean")
        if "severity_gte" in rule and rule["severity_gte"].upper() not in SEVERITY_ORDER:
            raise ValueError(f"Rule '{rid}' severity_gte '{rule['severity_gte']}' is not valid. Use: CRITICAL, HIGH, MEDIUM, LOW, NONE")
        if "registry_risk_gte" in rule and rule["registry_risk_gte"].lower() not in RISK_LEVEL_ORDER:
            raise ValueError(f"Rule '{rid}' registry_risk_gte '{rule['registry_risk_gte']}' is not valid. Use: high, medium, low")


def _rule_matches(rule: dict, br) -> bool:
    """Check if a BlastRadius finding matches a policy rule.

    Supports two modes:
    - **Expression mode**: ``"condition": "epss_score > 0.7 and severity >= HIGH"``
    - **Declarative mode**: individual fields ANDed together (backwards-compatible)

    When both ``condition`` and declarative fields are present, ALL must match.
    """
    # Expression-based condition (new in v0.58.0)
    if "condition" in rule:
        try:
            if not evaluate_expression(rule["condition"], br):
                return False
        except ValueError:
            # Invalid expression = rule doesn't match (fail-safe)
            return False

    # severity_gte: severity must be >= this level
    if "severity_gte" in rule:
        threshold = SEVERITY_ORDER.get(rule["severity_gte"].upper(), 0)
        actual = SEVERITY_ORDER.get(br.vulnerability.severity.value.upper(), 0)
        if actual < threshold:
            return False

    # is_kev: finding must be in CISA KEV catalog
    if rule.get("is_kev"):
        if not br.vulnerability.is_kev:
            return False

    # ai_risk: finding must have AI risk context (AI framework package)
    if rule.get("ai_risk"):
        if not br.ai_risk_context:
            return False

    # has_credentials: affected servers must expose credentials
    if rule.get("has_credentials"):
        if not br.exposed_credentials:
            return False

    # ecosystem: package must be from this ecosystem
    if "ecosystem" in rule:
        if br.package.ecosystem != rule["ecosystem"]:
            return False

    # package_name_contains: package name must contain this substring
    if "package_name_contains" in rule:
        if rule["package_name_contains"].lower() not in br.package.name.lower():
            return False

    # min_agents: finding must affect at least N agents
    if "min_agents" in rule:
        if len(br.affected_agents) < rule["min_agents"]:
            return False

    # min_tools: server must expose at least N tools (excessive agency)
    if "min_tools" in rule:
        if len(br.exposed_tools) < rule["min_tools"]:
            return False

    # unverified_server: package must come from an unverified registry entry
    if rule.get("unverified_server"):
        from agent_bom.parsers import get_registry_entry

        is_unverified = False
        for server in br.affected_servers:
            reg = get_registry_entry(server)
            if reg and not reg.get("verified", False):
                is_unverified = True
                break
        if not is_unverified:
            return False

    # registry_risk_gte: registry risk level must be >= threshold (low < medium < high)
    if "registry_risk_gte" in rule:
        from agent_bom.parsers import get_registry_entry

        threshold = RISK_LEVEL_ORDER.get(rule["registry_risk_gte"].lower(), 0)
        any_match = False
        for server in br.affected_servers:
            reg = get_registry_entry(server)
            if reg:
                actual = RISK_LEVEL_ORDER.get(reg.get("risk_level", "low"), 0)
                if actual >= threshold:
                    any_match = True
                    break
        if not any_match:
            return False

    # owasp_tag: finding must have this OWASP LLM Top 10 tag
    if "owasp_tag" in rule:
        tags = getattr(br, "owasp_tags", [])
        if rule["owasp_tag"] not in tags:
            return False

    # owasp_mcp_tag: finding must have this OWASP MCP Top 10 tag
    if "owasp_mcp_tag" in rule:
        tags = getattr(br, "owasp_mcp_tags", [])
        if rule["owasp_mcp_tag"] not in tags:
            return False

    # is_malicious: finding's package is flagged as malicious
    if rule.get("is_malicious"):
        if not getattr(br.package, "is_malicious", False):
            return False

    # min_scorecard_score: package's OpenSSF Scorecard score must be below threshold
    # (i.e. rule triggers when scorecard is WORSE than threshold)
    if "min_scorecard_score" in rule:
        pkg_score = getattr(br.package, "scorecard_score", None)
        if pkg_score is None or pkg_score >= rule["min_scorecard_score"]:
            return False

    # max_epss_score: vulnerability EPSS must be above threshold to trigger
    if "max_epss_score" in rule:
        epss = br.vulnerability.epss_score
        if epss is None or epss < rule["max_epss_score"]:
            return False

    # has_kev_with_no_fix: KEV vulnerabilities without a known fix
    if rule.get("has_kev_with_no_fix"):
        if not (br.vulnerability.is_kev and not br.vulnerability.fixed_version):
            return False

    return True


def evaluate_policy(policy: dict, blast_radii: list, *, dry_run: bool = False) -> dict:
    """Evaluate policy rules against blast radius findings.

    Args:
        policy: Parsed policy dict with ``rules`` list.
        blast_radii: List of BlastRadius objects to evaluate.
        dry_run: If True, evaluate rules but treat all 'fail' actions as
                 'warn' — violations are reported but the scan will not
                 fail.  Useful for testing new policies before enforcing.

    Returns a dict with:
      violations  – list of {rule, finding, action} for matching rules
      failures    – subset of violations where action == 'fail'
      warnings    – subset of violations where action == 'warn'
      passed      – True if no 'fail' violations
      dry_run     – whether dry-run mode was active
    """
    violations = []
    from agent_bom.vex import active_blast_radii

    active_findings = active_blast_radii(blast_radii)

    for rule in policy.get("rules", []):
        action = rule.get("action", "fail")
        for br in active_findings:
            if _rule_matches(rule, br):
                violations.append(
                    {
                        "rule_id": rule["id"],
                        "rule_description": rule.get("description", ""),
                        "action": action,
                        "vulnerability_id": br.vulnerability.id,
                        "severity": br.vulnerability.severity.value,
                        "package": f"{br.package.name}@{br.package.version}",
                        "ecosystem": br.package.ecosystem,
                        "affected_agents": [a.name for a in br.affected_agents],
                        "affected_servers": [s.name for s in br.affected_servers],
                        "exposed_credentials": br.exposed_credentials,
                        "is_kev": br.vulnerability.is_kev,
                        "ai_risk_context": br.ai_risk_context,
                        # Fields used by Jira ticket creation
                        "fixed_version": br.vulnerability.fixed_version,
                        "owasp_tags": getattr(br, "owasp_tags", []),
                        "owasp_mcp_tags": getattr(br, "owasp_mcp_tags", []),
                    }
                )

    failures = [v for v in violations if v["action"] == "fail"]
    warnings = [v for v in violations if v["action"] == "warn"]
    jira_violations = [v for v in violations if v["action"] == "jira"]

    # In dry-run mode, demote failures to warnings — report but don't block
    if dry_run:
        for v in failures:
            v["original_action"] = "fail"
            v["action"] = "warn"
        warnings = warnings + failures
        failures = []

    return {
        "policy_name": policy.get("name", "unnamed"),
        "violations": violations,
        "failures": failures,
        "warnings": warnings,
        "jira_violations": jira_violations,
        "passed": len(failures) == 0,
        "dry_run": dry_run,
    }


def fire_policy_jira_actions(
    policy_result: dict,
    jira_url: str,
    email: str,
    api_token: str,
    project_key: str,
    issue_type: str = "Bug",
) -> int:
    """Create Jira tickets for policy violations with ``action: "jira"``.

    Reads ``jira_violations`` from the result of :func:`evaluate_policy` and
    opens one Jira ticket per violation.  Tickets are deduplicated within the
    same scan run by skipping violations whose ``vulnerability_id`` + ``package``
    pair has already been ticketed.

    Args:
        policy_result: Return value of :func:`evaluate_policy`.
        jira_url: Jira instance URL (e.g. ``https://company.atlassian.net``).
        email: Jira user email for basic auth.
        api_token: Jira API token.
        project_key: Jira project key (e.g. ``SEC``).
        issue_type: Jira issue type (default: ``Bug``).

    Returns:
        Number of tickets successfully created.
    """
    import asyncio

    from agent_bom.integrations.jira import create_jira_ticket

    violations = policy_result.get("jira_violations", [])
    if not violations:
        return 0

    seen: set[str] = set()
    created = 0

    async def _run() -> int:
        nonlocal created
        for violation in violations:
            dedup_key = f"{violation.get('vulnerability_id', '')}::{violation.get('package', '')}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            ticket = await create_jira_ticket(
                jira_url=jira_url,
                email=email,
                api_token=api_token,
                project_key=project_key,
                finding=violation,
                issue_type=issue_type,
            )
            if ticket:
                created += 1
        return created

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _run())
                return future.result()
        else:
            return asyncio.run(_run())
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning("Policy Jira action failed: %s", exc)
        return 0
