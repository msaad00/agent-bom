"""Behavioral and code-block scanners for skill security audits."""

from __future__ import annotations

import ast
import logging
import re
from typing import Any, NamedTuple

from agent_bom.parsers.skill_audit_types import SkillFinding

logger = logging.getLogger(__name__)

# ── Shell / dangerous keywords ───────────────────────────────────────────────

_SHELL_COMMANDS = {"sh", "bash", "cmd", "powershell", "zsh"}

_DANGEROUS_ARG_KEYWORDS = {
    "--allow-exec",
    "exec",
    "shell",
    "--dangerous",
    "--yolo",
}

_DANGEROUS_SERVER_NAME_KEYWORDS = {"exec", "shell", "terminal", "command"}


# ── Behavioral risk pattern definitions ──────────────────────────────────────


class _BehavioralPattern(NamedTuple):
    """A regex-based behavioral risk pattern to detect in skill file prose/code.

    ``pattern`` is the high-confidence signal (an imperative directive, a
    concrete dangerous flag, or an actual command invocation). ``weak_pattern``
    is an optional lower-confidence heuristic — a bare feature name appearing in
    prose (e.g. "subagent", "delegation") that, on its own, is descriptive
    rather than evidence of malicious behavior. A weak-only match is downgraded
    to ``weak_severity`` with ``confidence="low"`` so a single descriptive
    keyword in a legitimate instruction file cannot escalate the file's verdict.
    """

    category: str  # e.g. "credential_file_access"
    severity: str  # "critical" | "high" | "medium" | "low"
    title: str  # Human-readable finding title
    pattern: re.Pattern  # Compiled regex (high-confidence signal)
    description: str  # Recommendation text
    weak_pattern: re.Pattern | None = None  # optional low-confidence keyword regex
    weak_severity: str = "low"  # severity to use when only weak_pattern matches


_BEHAVIORAL_PATTERNS: list[_BehavioralPattern] = [
    # ── CRITICAL ──────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="credential_file_access",
        severity="critical",
        title="Credential/secret file access",
        pattern=re.compile(
            r"""
            \b op \s+ (signin|vault|item|read)          # 1Password CLI
            | \b security \s+ find-generic-password       # macOS Keychain
            | cat \s+ ~/? \. (config|ssh|aws|gnupg)       # dotfile credential dirs
            | \b vault \s+ (kv|read|write) \s             # HashiCorp Vault
            | \b aws \s+ secretsmanager                   # AWS Secrets Manager
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Review and remove direct credential/secret file access. Use scoped environment variables instead.",
    ),
    _BehavioralPattern(
        category="credential_exfiltration",
        severity="critical",
        title="Natural-language credential exfiltration",
        # Prose-level exfiltration: a concrete sensitive credential/secret path
        # COMBINED (in either order, within a short window) with an action that
        # sends it to an external URL. Requiring BOTH the path and the
        # send-to-URL action keeps benign skills that merely mention
        # "credentials" or cite a docs URL from matching.
        pattern=re.compile(
            r"(?:"
            r"(?:~?/?\.aws/credentials|~?/?\.aws/config|~?/\.ssh/id_[a-z0-9_]+|~?/\.ssh/id_rsa|~?/\.ssh/id_ed25519"
            r"|~?/\.netrc|~?/\.config/gcloud|~?/\.kube/config|~?/\.docker/config\.json|/etc/shadow"
            r"|(?<![\w.])\.env(?![\w])|Cookies(?:\.sqlite)?|Login\s+Data)"
            r"[\s\S]{0,240}?"
            r"(?:upload|exfiltrat\w*|post(?:ing|ed)?|send(?:ing)?|curl|wget|fetch(?:ing)?|transmit\w*|push(?:ing)?|leak)"
            r"[\s\S]{0,120}?https?://"
            r"|"
            r"(?:upload|exfiltrat\w*|post(?:ing|ed)?|send(?:ing)?|curl|wget|fetch(?:ing)?|transmit\w*|leak)"
            r"[\s\S]{0,120}?https?://[\s\S]{0,240}?"
            r"(?:~?/?\.aws/credentials|~?/?\.aws/config|~?/\.ssh/id_[a-z0-9_]+|~?/\.ssh/id_rsa|~?/\.ssh/id_ed25519"
            r"|~?/\.netrc|~?/\.config/gcloud|~?/\.kube/config|~?/\.docker/config\.json|/etc/shadow"
            r"|(?<![\w.])\.env(?![\w])|Cookies(?:\.sqlite)?|Login\s+Data)"
            r")",
            re.IGNORECASE,
        ),
        description=(
            "This skill instructs reading a credential/secret file and sending it to an external URL — "
            "credential exfiltration. Remove the instruction; never transmit local secrets off-host."
        ),
    ),
    _BehavioralPattern(
        category="remote_code_execution",
        severity="high",
        title="Remote script piped to a shell",
        # `curl <url> | bash` / `wget <url> | sh` — fetch-and-execute of remote
        # code. High-confidence: the pipe-into-shell is the dangerous signal.
        pattern=re.compile(
            r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?)\b",
            re.IGNORECASE,
        ),
        description=(
            "Piping a remotely-fetched script straight into a shell runs unreviewed remote code. "
            "Download, inspect, and pin the script instead of executing it inline."
        ),
    ),
    _BehavioralPattern(
        category="confirmation_bypass",
        severity="critical",
        title="Safety confirmation bypass",
        pattern=re.compile(
            r"""
            --yolo \b                                     # Codex --yolo
            | --full-auto \b                              # Full auto mode
            | --no-sandbox \b                             # Sandbox disable
            | --dangerously-skip-permissions \b           # Claude Code skip perms
            | \b elevated \s* [:=] \s* true \b            # Elevated mode
            | \b auto_approve \s* [:=] \s* true \b        # Auto-approve
            | --no-verify \b                              # Git no-verify
            | \b allowedTools \s* [:=] \s* \[? \s* \*     # Wildcard tool allow
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Remove safety bypasses. Never disable confirmation prompts or sandbox protections.",
    ),
    # ── HIGH ──────────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="prompt_coercion",
        severity="high",
        title="Prompt coercion or guardrail override",
        pattern=re.compile(
            r"""
            ignore \s+ (?:all \s+)? previous \s+ instructions
            | override \s+ (?:the \s+)? system \s+ prompt
            | reveal \s+ (?:the \s+)? system \s+ prompt
            | bypass \s+ (?:the \s+)? guardrails?
            | developer \s+ mode
            | jailbreak
            | do \s+ not \s+ mention \s+ (?:the \s+)? policy
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description=(
            "Prompt coercion patterns try to override system instructions or hide policy checks. Remove or rewrite these instructions."
        ),
    ),
    _BehavioralPattern(
        category="messaging_capability",
        severity="high",
        title="Messaging/impersonation capability",
        pattern=re.compile(
            r"""
            \b imsg \s+ send \b                           # iMessage CLI
            | \b wacli \s+ send \b                        # WhatsApp CLI
            | \b slack \s+ (sendMessage|chat\.postMessage) # Slack API
            | \b discord \s+ send \b                      # Discord
            | \b twilio \s+ messages \b                   # Twilio SMS
            | \b sendgrid \b                              # SendGrid email
            | \b send[-_]?email \b                        # Generic email send
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Messaging capabilities let the agent impersonate the user. Require explicit confirmation for every message.",
    ),
    _BehavioralPattern(
        category="voice_telephony",
        severity="high",
        title="Voice/telephony capability",
        pattern=re.compile(
            r"""
            \b voicecall \s+ call \b                      # Voice call CLI
            | \b twilio \s+ calls \b                      # Twilio voice
            | \b telnyx \b                                # Telnyx telephony
            | \b plivo \b                                 # Plivo telephony
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Voice/telephony lets the agent make calls as the user. Remove or require human-in-the-loop.",
    ),
    _BehavioralPattern(
        category="agent_delegation",
        severity="high",
        title="Sub-agent delegation/spawning",
        pattern=re.compile(
            r"""
            \b codex \s+ (exec|--yolo) \b                 # Codex execution
            | \b claude \s+ (exec|--dangerously) \b       # Claude Code execution
            | \b spawn \s+ agent \b                       # Generic agent spawn
            | \b Task \s* \( .*? subagent                 # SDK Task() with subagent
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Sub-agent delegation can bypass safety controls. Ensure child agents inherit permission restrictions.",
        # A bare "subagent"/"sub-agent"/"delegation" mention in prose (as in a
        # legitimate CLAUDE.md/AGENTS.md describing normal agent features) is a
        # descriptive keyword, not evidence of an actual spawn directive.
        weak_pattern=re.compile(
            r"""
            \b sub[-_]?agent s? \b                        # Sub-agent reference
            | \b agent \s+ delegation \b                  # Delegation reference
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        weak_severity="low",
    ),
    _BehavioralPattern(
        category="input_injection",
        severity="high",
        title="Keystroke/input injection",
        pattern=re.compile(
            r"""
            \b tmux \s+ send-keys \b                      # tmux injection
            | \b xdotool \s+ (key|type) \b                # X11 input injection
            | \b osascript .* keystroke \b                 # macOS keystroke
            | \b xdg-open \b                              # Open arbitrary URLs
            | \b AppleScript .* activate \b               # macOS app control
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Input injection can control other applications. Remove keystroke/input simulation capabilities.",
    ),
    _BehavioralPattern(
        category="surveillance_access",
        severity="high",
        title="Camera/screen surveillance access",
        pattern=re.compile(
            r"""
            \b camsnap \b                                 # Camera snapshot
            | \b rtsp://                                  # RTSP camera stream
            | \b imagesnap \b                             # macOS camera
            | \b screencapture \b                         # macOS screenshot
            | \b ffmpeg .* /dev/video                     # Linux webcam
            | \b screenshot \s+ capture \b                # Generic screenshot
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Surveillance access can capture sensitive visual data. Remove camera/screen capture capabilities.",
    ),
    _BehavioralPattern(
        category="privilege_escalation",
        severity="high",
        title="Privilege escalation",
        pattern=re.compile(
            r"""
            \b sudo \s+ \S                               # sudo with command
            | \b su \s+ -                                 # Switch user
            | \b doas \s+ \S                              # OpenBSD doas
            | \b chmod \s+ u\+s \b                        # Set SUID bit
            | \b chown \s+ root \b                        # Change owner to root
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Privilege escalation grants root/admin access. Never run agents with elevated privileges.",
    ),
    _BehavioralPattern(
        category="financial_transaction",
        severity="high",
        title="Financial transaction capability",
        pattern=re.compile(
            r"""
            \b reorder \s+ --confirm \b                   # Auto-reorder
            | \b stripe \s+ charges \s+ create \b         # Stripe charge
            | \b paypal \s+ send \b                       # PayPal transfer
            | \b transfer[-_]?funds \b                    # Generic fund transfer
            | \b purchase[-_]?order \b                    # Purchase order
            | \b bitcoin[-_]?send \b                      # Crypto send
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Financial transactions should never be automated without human approval. Add confirmation gates.",
    ),
    # ── MEDIUM ────────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="network_exposure",
        severity="medium",
        title="Network exposure (bind to all interfaces)",
        pattern=re.compile(
            r"""
            --host \s+ 0\.0\.0\.0                         # Bind all interfaces
            | \b bind \s+ 0\.0\.0\.0                      # Socket bind all
            | \b ngrok \b                                 # ngrok tunnel
            | \b localtunnel \b                           # localtunnel
            | \b cloudflared \s+ tunnel \b                # Cloudflare tunnel
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Binding to 0.0.0.0 or tunneling exposes local services to the network. Use 127.0.0.1 instead.",
    ),
    _BehavioralPattern(
        category="data_exfiltration",
        severity="medium",
        title="Data exfiltration / private data access",
        pattern=re.compile(
            r"""
            \b imsg \s+ history \b                        # iMessage history
            | \b read[-_]?contacts \b                     # Contact list access
            | \b sqlite3 .* (History|Cookies|Login)       # Browser data
            | \b chat[-_]?history \b                      # Chat history access
            | \b export[-_]?contacts \b                   # Contact export
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Accessing private data (messages, contacts, browser history) is a privacy risk. Remove data access commands.",
    ),
    _BehavioralPattern(
        category="persistence_mechanism",
        severity="medium",
        title="Persistence mechanism (cron/launchd/systemd)",
        pattern=re.compile(
            r"""
            \b crontab \s+ -[ei] \b                       # Edit crontab
            | \*/\d+ \s+ \*                               # Cron schedule pattern
            | \b launchctl \s+ load \b                    # macOS launchd
            | \b systemctl \s+ enable \b                  # Linux systemd
            | \b schtasks \s+ /create \b                  # Windows task scheduler
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Persistence mechanisms let agents run unattended. Remove scheduled task creation capabilities.",
    ),
    _BehavioralPattern(
        category="memory_poisoning",
        severity="medium",
        title="Agent memory/config poisoning",
        pattern=re.compile(
            r"""
            \b (write|append|echo|cat\s*>) .* MEMORY\.md  # Claude memory
            | \b (write|append|echo|cat\s*>) .* CLAUDE\.md # Claude config
            | \b (write|append|echo|cat\s*>) .* \.cursorrules # Cursor config
            | \b (write|append|echo|cat\s*>) .* AGENTS\.md # Agents config
            | \b (write|append|echo|cat\s*>) .* \.windsurfrules # Windsurf config
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Writing to agent config files can poison future sessions. Never allow skills to modify agent memory.",
    ),
    _BehavioralPattern(
        category="repository_modification",
        severity="medium",
        title="Repository modification (push/merge)",
        pattern=re.compile(
            r"""
            \b git \s+ push \b (?! .* --dry-run)          # git push (not dry-run)
            | \b git \s+ push \s+ --force \b              # Force push
            | \b gh \s+ pr \s+ merge \b                   # GitHub PR merge
            | \b git \s+ commit \b                        # git commit
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Repository modifications can ship unreviewed code. Require human review before push/merge.",
    ),
    _BehavioralPattern(
        category="destructive_action",
        severity="medium",
        title="Destructive system action",
        pattern=re.compile(
            r"""
            \b rm \s+ -r?f \b                             # rm -rf / rm -f
            | \b kill \s+ -9 \b                           # Force kill process
            | \b DROP \s+ TABLE \b                        # SQL drop table
            | \b TRUNCATE \s+ TABLE \b                    # SQL truncate
            | \b shred \b                                 # Secure file deletion
            | \b mkfs \b                                  # Format filesystem
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Destructive actions can cause data loss. Add confirmation prompts before any delete/destroy operation.",
    ),
]

_PYTHON_FENCED_BLOCK_RE = re.compile(r"```(?:python|py)\s*\n([\s\S]*?)```", re.IGNORECASE)
_JS_TS_FENCED_BLOCK_RE = re.compile(
    r"```(?P<language>javascript|js|typescript|ts|tsx|jsx)\s*\n(?P<code>[\s\S]*?)```",
    re.IGNORECASE,
)

_DYNAMIC_CODE_CALLS = {"eval", "exec", "compile", "__import__"}
_SUBPROCESS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
_FILE_MUTATION_CALLS = {
    "open",
    "Path.write_text",
    "Path.write_bytes",
    "Path.touch",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
}
_JS_DYNAMIC_CODE_CALLS = {"eval", "Function"}
_JS_SUBPROCESS_CALLS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
    "child_process.exec",
    "child_process.execSync",
    "child_process.spawn",
    "child_process.spawnSync",
    "child_process.fork",
}
_JS_FILE_MUTATION_CALLS = {
    "fs.writeFile",
    "fs.writeFileSync",
    "fs.appendFile",
    "fs.appendFileSync",
    "fs.unlink",
    "fs.unlinkSync",
    "fs.rm",
    "fs.rmSync",
    "fs.rename",
    "fs.renameSync",
    "fs.promises.writeFile",
    "fs.promises.appendFile",
    "fs.promises.unlink",
    "fs.promises.rm",
    "fs.promises.rename",
    "Bun.write",
    "Deno.writeTextFile",
    "Deno.writeFile",
    "Deno.remove",
    "Deno.rename",
}
_JS_CALL_RE = re.compile(r"\b(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*\s*\(")
_JS_IMPORT_NAMED_RE = re.compile(
    r"""import\s*\{\s*([^}]+)\}\s*from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_IMPORT_NAMESPACE_RE = re.compile(
    r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_IMPORT_DEFAULT_RE = re.compile(
    r"""import\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_REQUIRE_NAMED_RE = re.compile(
    r"""(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)""",
    re.IGNORECASE,
)
_JS_REQUIRE_DEFAULT_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']\s*\)""",
    re.IGNORECASE,
)
_JS_IMPORTABLE_SUBPROCESS_CALLS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
}
_JS_IMPORTABLE_FILE_MUTATION_CALLS = {
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rename",
    "renameSync",
    "writeTextFile",
    "writeFile",
    "remove",
    "rename",
}


# ── Behavioral scanning function ─────────────────────────────────────────────


# ── Prohibition / policy context guard ──────────────────────────────────────
#
# Instruction files legitimately *enumerate* dangerous flags and commands in
# order to forbid them ("## Never — `git push --force`, `--no-verify`, …",
# "Do not disable the sandbox"). Matching the literal token there flags the
# repository's own governance docs as malicious. A behavioral match is treated
# as policy prose — and skipped — when it sits under a prohibition heading or a
# prohibition cue ("never", "do not", "without explicit approval", …) governs it
# nearby. The cue must be *proximate* to the match (same list item / paragraph),
# so a real dangerous instruction elsewhere in the file is still detected and an
# attacker cannot neutralise an injection by dropping a stray "never" far away.

_PROHIBITION_HEADING_RE = re.compile(
    r"^\s{0,3}#{1,6}\s+.*\b(?:never|don'?ts?|do\s+not|avoid|prohibit\w*|"
    r"forbidden|forbid|disallow\w*|anti[-\s]?patterns?|red\s+flags?)\b",
    re.IGNORECASE,
)

_PROHIBITION_CUE_RE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|must\s+never|shall\s+not|"
    r"should\s+not|cannot|can'?t|avoid|prohibit\w*|forbid\w*|forbidden|"
    r"disallow\w*|not\s+allowed|not\s+permitted|"
    r"without\s+(?:(?:an?|prior|explicit|the)\s+){0,4}"
    r"(?:explicit|prior|human|user|written|manual)|"
    r"(?:require[sd]?|need(?:s|ed)?|after|only\s+after|upon|following|pending|once)"
    r"\s+(?:(?:an?|explicit|prior|human|user|manual|written|the)\s+){0,4}"
    r"(?:review|approval|confirmation|consent|sign[-\s]?off|request)|"
    r"reject\w*|refus\w*)\b",
    re.IGNORECASE,
)

_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")

# How far (characters) from a match a prohibition cue may sit and still be read
# as governing it, clamped to the match's own list item / paragraph.
_PROHIBITION_PROXIMITY = 90


def _nearest_heading_is_prohibition(lines: list[str], line_idx: int) -> bool:
    """Return True when the closest preceding markdown heading forbids behavior."""
    for j in range(min(line_idx, len(lines) - 1), -1, -1):
        if lines[j].lstrip().startswith("#"):
            return bool(_PROHIBITION_HEADING_RE.match(lines[j]))
    return False


def _block_bounds(lines: list[str], line_idx: int) -> tuple[int, int]:
    """Return the (start, end) line indices of the list item / paragraph block."""
    start = line_idx
    while (
        start > 0
        and lines[start].startswith((" ", "\t"))
        and lines[start].strip()
        and not _LIST_ITEM_RE.match(lines[start])
    ):
        start -= 1
    end = line_idx
    while (
        end + 1 < len(lines)
        and lines[end + 1].startswith((" ", "\t"))
        and lines[end + 1].strip()
        and not _LIST_ITEM_RE.match(lines[end + 1])
    ):
        end += 1
    return start, end


def _is_prohibition_context(content: str, match_start: int, match_end: int) -> bool:
    """Return True when a behavioral match is forbidden/policy prose, not a directive."""
    lines = content.split("\n")
    line_idx = content.count("\n", 0, match_start)
    if _nearest_heading_is_prohibition(lines, line_idx):
        return True
    start_line, end_line = _block_bounds(lines, line_idx)
    block_start = sum(len(line) + 1 for line in lines[:start_line])
    block_end = block_start + sum(len(lines[i]) + 1 for i in range(start_line, end_line + 1))
    lo = max(block_start, match_start - _PROHIBITION_PROXIMITY)
    hi = min(block_end, match_end + _PROHIBITION_PROXIMITY)
    return bool(_PROHIBITION_CUE_RE.search(content[lo:hi]))


def _first_actionable_match(pattern: re.Pattern, content: str) -> re.Match | None:
    """Return the first pattern match that is not forbidden/policy prose."""
    for candidate in pattern.finditer(content):
        if _is_prohibition_context(content, candidate.start(), candidate.end()):
            continue
        return candidate
    return None


def _scan_behavioral_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan full skill file text for behavioral risk patterns.

    Args:
        raw_content: Mapping of filename → full text content.

    Returns:
        List of SkillFinding with context="behavioral".
    """
    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()

        for bp in _BEHAVIORAL_PATTERNS:
            if bp.category in seen_categories:
                continue

            match = _first_actionable_match(bp.pattern, content)
            severity = bp.severity
            confidence = "high" if bp.severity in {"critical", "high"} else "medium"

            if match is None and bp.weak_pattern is not None:
                # Only a low-confidence keyword/heuristic matched. Keep the
                # finding visible but demote it so a lone descriptive keyword
                # cannot dominate the file's trust verdict.
                match = _first_actionable_match(bp.weak_pattern, content)
                if match is not None:
                    severity = bp.weak_severity
                    confidence = "low"

            if match:
                seen_categories.add(bp.category)
                snippet = match.group(0).strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                line, column = _line_column(content, match.start())

                findings.append(
                    SkillFinding(
                        severity=severity,
                        category=bp.category,
                        title=bp.title,
                        detail=(f'Detected in {filename}: "{snippet}". {bp.description}'),
                        source_file=filename,
                        recommendation=bp.description,
                        context="behavioral",
                        evidence_source="static_text",
                        confidence=confidence,
                        source_line=line,
                        source_column=column,
                    )
                )

    return findings


def _line_column(content: str, offset: int) -> tuple[int, int]:
    """Return 1-based line and column for an offset."""
    line = content.count("\n", 0, offset) + 1
    last_newline = content.rfind("\n", 0, offset)
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def _call_name(node: ast.AST) -> str:
    """Return a dotted call name when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _open_mode_is_mutating(call: ast.Call) -> bool:
    """Return True when open(...) uses a mutating mode."""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return any(flag in call.args[1].value for flag in ("w", "a", "+"))
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return any(flag in keyword.value.value for flag in ("w", "a", "+"))
    return False


def _scan_python_ast_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan Python fenced code blocks for semantic risk patterns."""
    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()
        for block_match in _PYTHON_FENCED_BLOCK_RE.finditer(content):
            block = block_match.group(1)
            block_start_line, _block_column = _line_column(content, block_match.start(1))
            try:
                tree = ast.parse(block)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                call_name = _call_name(node.func)
                if not call_name:
                    continue

                if call_name in _DYNAMIC_CODE_CALLS and "ast_dynamic_code_execution" not in seen_categories:
                    seen_categories.add("ast_dynamic_code_execution")
                    findings.append(
                        SkillFinding(
                            severity="high",
                            category="ast_dynamic_code_execution",
                            title="Python AST detected dynamic code execution",
                            detail=(
                                f"Detected `{call_name}` in a Python code block in {filename}. "
                                "Dynamic evaluation makes instruction surfaces harder to review and can hide unsafe behavior."
                            ),
                            source_file=filename,
                            recommendation="Remove dynamic code execution or replace it with explicit, statically reviewable logic.",
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

                if call_name in _SUBPROCESS_CALLS and "ast_shell_execution" not in seen_categories:
                    seen_categories.add("ast_shell_execution")
                    findings.append(
                        SkillFinding(
                            severity="high",
                            category="ast_shell_execution",
                            title="Python AST detected shell/process execution",
                            detail=(
                                f"Detected `{call_name}` in a Python code block in {filename}. "
                                "Subprocess execution expands the skill's authority and increases command-injection risk."
                            ),
                            source_file=filename,
                            recommendation=(
                                "Avoid spawning shells or subprocesses from skills unless the action "
                                "is narrowly scoped and explicitly reviewed."
                            ),
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

                is_file_mutation = call_name in _FILE_MUTATION_CALLS and (call_name != "open" or _open_mode_is_mutating(node))
                if is_file_mutation and "ast_file_mutation" not in seen_categories:
                    seen_categories.add("ast_file_mutation")
                    findings.append(
                        SkillFinding(
                            severity="medium",
                            category="ast_file_mutation",
                            title="Python AST detected file mutation",
                            detail=(
                                f"Detected mutating file operation `{call_name}` in a Python code block in {filename}. "
                                "File writes and deletions can change agent memory, repo state, or local trust boundaries."
                            ),
                            source_file=filename,
                            recommendation=(
                                "Require explicit review for file mutations and avoid write/delete flows in reusable skill instructions."
                            ),
                            context="code_block",
                            evidence_source="ast_python",
                            confidence="high",
                            source_line=block_start_line + getattr(node, "lineno", 1) - 1,
                            source_column=getattr(node, "col_offset", 0) + 1,
                        )
                    )

    return findings


def _strip_js_strings_and_comments(code: str) -> str:
    """Remove JS/TS strings and comments while preserving call structure."""
    result: list[str] = []
    i = 0
    length = len(code)
    state = "code"
    quote = ""

    while i < length:
        char = code[i]
        nxt = code[i + 1] if i + 1 < length else ""

        if state == "code":
            if char == "/" and nxt == "/":
                state = "line_comment"
                result.extend("  ")
                i += 2
                continue
            if char == "/" and nxt == "*":
                state = "block_comment"
                result.extend("  ")
                i += 2
                continue
            if char in {"'", '"', "`"}:
                state = "string"
                quote = char
                result.append(" ")
                i += 1
                continue
            result.append(char)
            i += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                result.extend("  ")
                i += 2
            else:
                result.append("\n" if char == "\n" else " ")
                i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < length:
                result.extend("  ")
                i += 2
                continue
            if char == quote:
                state = "code"
                quote = ""
                result.append(" ")
            else:
                result.append("\n" if char == "\n" else " ")
            i += 1
            continue

    return "".join(result)


def _normalize_js_module_name(module_name: str) -> str:
    module_name = module_name.strip()
    if module_name.startswith("node:"):
        module_name = module_name[5:]
    return module_name


def _canonical_js_function_call(module_name: str, imported_name: str) -> str | None:
    module_name = _normalize_js_module_name(module_name)
    imported_name = imported_name.strip()
    if module_name == "child_process" and imported_name in _JS_IMPORTABLE_SUBPROCESS_CALLS:
        return f"child_process.{imported_name}"
    if module_name == "fs" and imported_name in _JS_IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.{imported_name}"
    if module_name == "fs/promises" and imported_name in _JS_IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.promises.{imported_name}"
    if module_name == "fs/promises" and imported_name == "default":
        return "fs.promises"
    return None


def _canonical_js_namespace(module_name: str) -> str | None:
    module_name = _normalize_js_module_name(module_name)
    if module_name == "child_process":
        return "child_process"
    if module_name == "fs":
        return "fs"
    if module_name == "fs/promises":
        return "fs.promises"
    return None


def _split_js_import_spec(spec: str) -> tuple[str, str]:
    if " as " in spec:
        imported, alias = spec.split(" as ", 1)
        return imported.strip(), alias.strip()
    if ":" in spec:
        imported, alias = spec.split(":", 1)
        return imported.strip(), alias.strip()
    spec = spec.strip()
    return spec, spec


def _collect_js_aliases(code: str) -> tuple[dict[str, str], dict[str, str]]:
    function_aliases: dict[str, str] = {}
    namespace_aliases: dict[str, str] = {}

    for match in _JS_IMPORT_NAMED_RE.finditer(code):
        specs, module_name = match.groups()
        for raw_spec in specs.split(","):
            imported, alias = _split_js_import_spec(raw_spec)
            canonical = _canonical_js_function_call(module_name, imported)
            if canonical:
                function_aliases[alias] = canonical

    for match in _JS_REQUIRE_NAMED_RE.finditer(code):
        specs, module_name = match.groups()
        for raw_spec in specs.split(","):
            imported, alias = _split_js_import_spec(raw_spec)
            canonical = _canonical_js_function_call(module_name, imported)
            if canonical:
                function_aliases[alias] = canonical

    for match in _JS_IMPORT_NAMESPACE_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    for match in _JS_IMPORT_DEFAULT_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    for match in _JS_REQUIRE_DEFAULT_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    return function_aliases, namespace_aliases


def _canonicalize_js_call_name(call_name: str, function_aliases: dict[str, str], namespace_aliases: dict[str, str]) -> str:
    call_name = call_name.strip()
    if call_name in function_aliases:
        return function_aliases[call_name]

    if "." not in call_name:
        return call_name

    base, remainder = call_name.split(".", 1)
    if base in namespace_aliases:
        return f"{namespace_aliases[base]}.{remainder}"
    return call_name


def _collect_js_ts_call_names(block: str, *, language_hint: str) -> set[str]:
    """Collect JS/TS call names via tree-sitter when available, otherwise regex fallback."""
    analyze_js_ts_block: Any | None = None
    ast_unavailable_error: type[Exception] = RuntimeError
    try:
        from agent_bom.js_ts_ast import JSTSAstUnavailableError
        from agent_bom.js_ts_ast import analyze_js_ts_block as analyze_js_ts_block_impl

        analyze_js_ts_block = analyze_js_ts_block_impl
        ast_unavailable_error = JSTSAstUnavailableError
    except Exception:  # pragma: no cover - defensive import guard
        pass

    if analyze_js_ts_block is not None:
        try:
            return analyze_js_ts_block(block, language_hint=language_hint).call_names
        except ast_unavailable_error:
            logger.debug("tree-sitter JS/TS runtime unavailable; falling back to regex analysis")
        except Exception:
            logger.debug("tree-sitter JS/TS analysis failed; falling back to regex analysis", exc_info=True)

    function_aliases, namespace_aliases = _collect_js_aliases(block)
    normalized = _strip_js_strings_and_comments(block)
    call_names = {
        _canonicalize_js_call_name(match.group(0).rstrip("(").strip(), function_aliases, namespace_aliases)
        for match in _JS_CALL_RE.finditer(normalized)
    }
    if re.search(r"\bnew\s+Function\s*\(", normalized):
        call_names.add("Function")
    return call_names


def _scan_js_ts_semantic_risks(raw_content: dict[str, str]) -> list[SkillFinding]:
    """Scan JS/TS fenced code blocks for semantic risk patterns."""
    findings: list[SkillFinding] = []

    for filename, content in raw_content.items():
        seen_categories: set[str] = set()
        for match in _JS_TS_FENCED_BLOCK_RE.finditer(content):
            language_hint = match.group("language").lower()
            block = match.group("code")
            block_start_line, _block_column = _line_column(content, match.start("code"))
            call_names = _collect_js_ts_call_names(block, language_hint=language_hint)

            if _JS_DYNAMIC_CODE_CALLS & call_names and "ast_js_dynamic_code_execution" not in seen_categories:
                call_name = sorted(_JS_DYNAMIC_CODE_CALLS & call_names)[0]
                seen_categories.add("ast_js_dynamic_code_execution")
                findings.append(
                    SkillFinding(
                        severity="high",
                        category="ast_js_dynamic_code_execution",
                        title="JS/TS code analysis detected dynamic code execution",
                        detail=(
                            f"Detected `{call_name}` in a JS/TS code block in {filename}. "
                            "Dynamic evaluation makes instruction surfaces harder to review and can hide unsafe behavior."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Remove dynamic code execution from skill code blocks or replace it with explicit, reviewable logic."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

            if _JS_SUBPROCESS_CALLS & call_names and "ast_js_shell_execution" not in seen_categories:
                call_name = sorted(_JS_SUBPROCESS_CALLS & call_names)[0]
                seen_categories.add("ast_js_shell_execution")
                findings.append(
                    SkillFinding(
                        severity="high",
                        category="ast_js_shell_execution",
                        title="JS/TS code analysis detected shell/process execution",
                        detail=(
                            f"Detected `{call_name}` in a JS/TS code block in {filename}. "
                            "Process execution expands the skill's authority and increases command-injection risk."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Avoid child-process execution in reusable skills unless the action is narrowly scoped and explicitly reviewed."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

            if _JS_FILE_MUTATION_CALLS & call_names and "ast_js_file_mutation" not in seen_categories:
                call_name = sorted(_JS_FILE_MUTATION_CALLS & call_names)[0]
                seen_categories.add("ast_js_file_mutation")
                findings.append(
                    SkillFinding(
                        severity="medium",
                        category="ast_js_file_mutation",
                        title="JS/TS code analysis detected file mutation",
                        detail=(
                            f"Detected mutating file operation `{call_name}` in a JS/TS code block in {filename}. "
                            "File writes and deletions can change agent memory, repo state, or local trust boundaries."
                        ),
                        source_file=filename,
                        recommendation=(
                            "Require explicit review for JS/TS file mutations and avoid write/delete flows in reusable skill instructions."
                        ),
                        context="code_block",
                        evidence_source="ast_js",
                        confidence="high",
                        source_line=block_start_line,
                        source_column=1,
                    )
                )

    return findings


_BEHAVIOR_FAMILIES: dict[str, str] = {
    "shell_access": "code_execution",
    "dangerous_tool": "code_execution",
    "agent_delegation": "code_execution",
    "privilege_escalation": "code_execution",
    "repository_modification": "code_execution",
    "destructive_action": "code_execution",
    "financial_transaction": "code_execution",
    "ast_dynamic_code_execution": "code_execution",
    "ast_shell_execution": "code_execution",
    "ast_file_mutation": "code_execution",
    "ast_js_dynamic_code_execution": "code_execution",
    "ast_js_shell_execution": "code_execution",
    "ast_js_file_mutation": "code_execution",
    "external_url": "network_access",
    "network_exposure": "network_access",
    "messaging_capability": "network_access",
    "voice_telephony": "network_access",
    "surveillance_access": "network_access",
    "undocumented_network": "network_access",
    "prompt_coercion": "prompt_coercion",
    "confirmation_bypass": "prompt_coercion",
    "memory_poisoning": "prompt_coercion",
    "input_injection": "prompt_coercion",
    "credential_file_access": "data_access",
    "data_exfiltration": "data_access",
    "credential_exfiltration": "data_access",
    "remote_code_execution": "code_execution",
    "excessive_permissions": "data_access",
    "persistence_mechanism": "persistence",
    "missing_capability_declaration": "data_access",
    "incomplete_capability_declaration": "data_access",
}


def _summarize_behavioral_findings(findings: list[SkillFinding]) -> dict[str, object]:
    """Summarize findings into stable review-oriented behavior families."""
    family_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    high_or_critical = 0

    for finding in findings:
        family = _BEHAVIOR_FAMILIES.get(finding.category)
        if not family:
            continue
        family_counts[family] = family_counts.get(family, 0) + 1
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        if finding.severity in {"critical", "high"}:
            high_or_critical += 1

    top_categories = [category for category, _count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))[:5]]
    return {
        "families": family_counts,
        "top_categories": top_categories,
        "high_or_critical": high_or_critical,
    }
