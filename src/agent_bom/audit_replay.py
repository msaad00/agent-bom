"""Audit log viewer and replay tool for agent-bom proxy JSONL logs.

Parses audit JSONL files written by ``agent-bom proxy --log <file>`` and
renders an interactive Rich terminal view with:

- Summary statistics (calls, blocked, alerts, relay errors, latency)
- Per-entry table with colour-coded policy, severity, and type
- Filters: ``--tool``, ``--type``, ``--blocked-only``, ``--alerts-only``
- HMAC verification when ``--sign-key`` is provided
- Exits 1 if any blocked calls or relay errors are found (useful in CI)

CLI::

    agent-bom audit-replay audit.jsonl
    agent-bom audit-replay audit.jsonl --blocked-only
    agent-bom audit-replay audit.jsonl --tool read_file --type tools/call
    agent-bom audit-replay audit.jsonl --sign-key $MY_SECRET --verify-hmac
    agent-bom audit-replay audit.jsonl --json          # machine-readable output
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─── Entry dataclasses ────────────────────────────────────────────────────────


@dataclass
class ToolCallEntry:
    ts: str
    tool: str
    policy: str  # "allowed" | "blocked"
    reason: str
    agent_id: str
    args: dict
    payload_sha256: str
    message_id: object


@dataclass
class AlertEntry:
    ts: str
    detector: str
    severity: str  # "critical" | "high" | "medium" | "low"
    message: str
    tool: str
    raw: dict


@dataclass
class RelayErrorEntry:
    ts: str
    error: str
    error_type: str


@dataclass
class ResponseHMACEntry:
    ts: str
    message_id: object
    hmac_sha256: str


@dataclass
class SummaryEntry:
    ts: str
    uptime_seconds: float
    total_tool_calls: int
    total_blocked: int
    calls_by_tool: dict
    blocked_by_reason: dict
    latency: dict
    replay_rejections: int
    relay_errors: int
    runtime_alerts: int
    runtime_alerts_by_severity: dict = field(default_factory=dict)
    runtime_alerts_by_detector: dict = field(default_factory=dict)
    blocked_runtime_alerts: int = 0
    latest_runtime_alert_at: str = ""


@dataclass
class AuditLog:
    tool_calls: list[ToolCallEntry] = field(default_factory=list)
    alerts: list[AlertEntry] = field(default_factory=list)
    relay_errors: list[RelayErrorEntry] = field(default_factory=list)
    hmac_entries: list[ResponseHMACEntry] = field(default_factory=list)
    summary: Optional[SummaryEntry] = None
    unknown: list[dict] = field(default_factory=list)


# ─── Parser ───────────────────────────────────────────────────────────────────


def parse_audit_log(path: Path) -> AuditLog:
    """Parse a proxy JSONL audit log into structured entries."""
    log = AuditLog()
    for lineno, raw_line in enumerate(path.read_text().splitlines(), 1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        entry_type = entry.get("type", "")

        if entry_type == "tools/call":
            log.tool_calls.append(
                ToolCallEntry(
                    ts=entry.get("ts", ""),
                    tool=entry.get("tool", "unknown"),
                    policy=entry.get("policy", "allowed"),
                    reason=entry.get("reason", ""),
                    agent_id=entry.get("agent_id", ""),
                    args=entry.get("args", {}),
                    payload_sha256=entry.get("payload_sha256", ""),
                    message_id=entry.get("message_id"),
                )
            )

        elif entry_type == "relay_error":
            log.relay_errors.append(
                RelayErrorEntry(
                    ts=entry.get("ts", ""),
                    error=entry.get("error", ""),
                    error_type=entry.get("error_type", ""),
                )
            )

        elif entry_type == "response_hmac":
            log.hmac_entries.append(
                ResponseHMACEntry(
                    ts=entry.get("ts", ""),
                    message_id=entry.get("id"),
                    hmac_sha256=entry.get("hmac_sha256", ""),
                )
            )

        elif entry_type == "proxy_summary":
            log.summary = SummaryEntry(
                ts=entry.get("ts", ""),
                uptime_seconds=entry.get("uptime_seconds", 0.0),
                total_tool_calls=entry.get("total_tool_calls", 0),
                total_blocked=entry.get("total_blocked", 0),
                calls_by_tool=entry.get("calls_by_tool", {}),
                blocked_by_reason=entry.get("blocked_by_reason", {}),
                latency=entry.get("latency", {}),
                replay_rejections=entry.get("replay_rejections", 0),
                relay_errors=entry.get("relay_errors", 0),
                runtime_alerts=entry.get("runtime_alerts", 0),
                runtime_alerts_by_severity=entry.get("runtime_alerts_by_severity", {}),
                runtime_alerts_by_detector=entry.get("runtime_alerts_by_detector", {}),
                blocked_runtime_alerts=entry.get("blocked_runtime_alerts", 0),
                latest_runtime_alert_at=entry.get("latest_runtime_alert_at", ""),
            )

        elif "severity" in entry and "detector" in entry:
            # Runtime detector alert
            log.alerts.append(
                AlertEntry(
                    ts=entry.get("ts", ""),
                    detector=entry.get("detector", entry.get("type", "unknown")),
                    severity=entry.get("severity", "medium"),
                    message=entry.get("message", entry.get("detail", "")),
                    tool=entry.get("tool", ""),
                    raw=entry,
                )
            )

        else:
            log.unknown.append(entry)

    return log


# ─── HMAC verification ────────────────────────────────────────────────────────


def verify_hmac_entries(log: AuditLog, sign_key: str) -> tuple[int, int]:
    """Verify HMAC entries against corresponding tool call payloads.

    Returns (verified_count, failed_count).
    """
    # Build a map of message_id → ToolCallEntry for correlation
    call_map: dict[object, ToolCallEntry] = {tc.message_id: tc for tc in log.tool_calls if tc.message_id is not None}

    verified = 0
    failed = 0
    for hmac_entry in log.hmac_entries:
        tc = call_map.get(hmac_entry.message_id)
        if tc is None:
            continue  # response for a non-tool-call message (tools/list etc.)
        # Recompute expected HMAC from the stored payload hash — we can only
        # verify the audit record itself here since we don't have the raw
        # wire payload. This confirms the log wasn't tampered with.
        raw_hash = tc.payload_sha256
        expected = hmac.new(
            sign_key.encode("utf-8"),
            raw_hash.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        # Compare constant-time
        if hmac.compare_digest(expected, hmac_entry.hmac_sha256[:64]):
            verified += 1
        else:
            failed += 1
    return verified, failed


def verify_hash_chain(path: Path) -> tuple[int, int]:
    """Verify prev-hash chaining across JSONL audit records.

    Returns ``(verified_count, tampered_count)``.
    """
    verified = 0
    tampered = 0
    previous_hash = ""

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            tampered += 1
            continue
        if not isinstance(entry, dict):
            tampered += 1
            continue

        actual_prev = str(entry.get("prev_hash", ""))
        actual_hash = str(entry.get("record_hash", ""))
        payload = {k: v for k, v in entry.items() if k not in {"prev_hash", "record_hash"}}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(f"{actual_prev}|{canonical}".encode("utf-8")).hexdigest()

        if actual_prev == previous_hash and actual_hash and hmac.compare_digest(actual_hash, expected_hash):
            verified += 1
        else:
            tampered += 1

        previous_hash = actual_hash or previous_hash

    return verified, tampered


# ─── Rich display ─────────────────────────────────────────────────────────────


def _severity_style(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }.get(severity.lower(), "white")


def _policy_style(policy: str) -> str:
    return "bold red" if policy == "blocked" else "green"


def display_rich(
    log: AuditLog,
    *,
    tool_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    blocked_only: bool = False,
    alerts_only: bool = False,
    verify_hmac_key: Optional[str] = None,
    verify_chain_result: tuple[int, int] | None = None,
) -> int:
    """Render audit log to terminal using Rich. Returns exit code (1 if issues found)."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    exit_code = 0

    # ── Summary panel ──────────────────────────────────────────────────────
    s = log.summary
    if s:
        blocked_style = "bold red" if s.total_blocked > 0 else "green"
        alert_style = "bold yellow" if s.runtime_alerts > 0 else "green"
        relay_style = "bold red" if s.relay_errors > 0 else "green"

        lat = s.latency
        lat_str = (
            f"p50={lat.get('p50_ms', '—')}ms  p95={lat.get('p95_ms', '—')}ms  avg={lat.get('avg_ms', '—')}ms" if lat else "no latency data"
        )

        summary_lines = [
            f"[bold]Uptime:[/bold] {s.uptime_seconds:.1f}s   "
            f"[bold]Calls:[/bold] {s.total_tool_calls}   "
            f"[{blocked_style}][bold]Blocked:[/bold] {s.total_blocked}[/{blocked_style}]   "
            f"[{alert_style}][bold]Alerts:[/bold] {s.runtime_alerts}[/{alert_style}]   "
            f"[{relay_style}][bold]Relay errors:[/bold] {s.relay_errors}[/{relay_style}]",
            f"[bold]Latency:[/bold] {lat_str}",
        ]
        if s.replay_rejections:
            summary_lines.append(f"[bold yellow]Replay rejections:[/bold yellow] {s.replay_rejections}")
        if s.calls_by_tool:
            top = sorted(s.calls_by_tool.items(), key=lambda x: -x[1])[:5]
            summary_lines.append("[bold]Top tools:[/bold] " + "  ".join(f"{t}×{c}" for t, c in top))
        if s.blocked_by_reason:
            summary_lines.append("[bold red]Blocked by:[/bold red] " + "  ".join(f"{r}×{c}" for r, c in s.blocked_by_reason.items()))
        if s.runtime_alerts_by_severity:
            summary_lines.append(
                "[bold yellow]Alert severities:[/bold yellow] "
                + "  ".join(f"{severity}×{count}" for severity, count in s.runtime_alerts_by_severity.items())
            )
        if s.latest_runtime_alert_at:
            summary_lines.append(f"[bold]Latest alert:[/bold] {s.latest_runtime_alert_at[:19].replace('T', ' ')}")

        console.print(
            Panel(
                "\n".join(summary_lines),
                title="[bold cyan]agent-bom proxy session[/bold cyan]",
                border_style="cyan",
            )
        )

    if s and (s.total_blocked > 0 or s.relay_errors > 0):
        exit_code = 1

    # ── Tool call table ─────────────────────────────────────────────────────
    if not alerts_only:
        calls = log.tool_calls
        if tool_filter:
            calls = [c for c in calls if tool_filter.lower() in c.tool.lower()]
        if blocked_only:
            calls = [c for c in calls if c.policy == "blocked"]

        if calls:
            tbl = Table(
                title="Tool Calls",
                box=box.SIMPLE_HEAVY,
                show_lines=False,
                highlight=True,
            )
            tbl.add_column("Time", style="dim", no_wrap=True, max_width=26)
            tbl.add_column("Tool", style="bold")
            tbl.add_column("Policy", no_wrap=True)
            tbl.add_column("Agent", style="dim", max_width=20)
            tbl.add_column("Reason / Args", max_width=60)

            for c in calls:
                policy_markup = f"[{_policy_style(c.policy)}]{c.policy}[/{_policy_style(c.policy)}]"
                detail = c.reason if c.policy == "blocked" else (", ".join(f"{k}={str(v)[:40]}" for k, v in c.args.items()) or "—")
                tbl.add_row(
                    c.ts[:19].replace("T", " "),
                    c.tool,
                    policy_markup,
                    c.agent_id[:20] or "—",
                    detail[:80],
                )
            console.print(tbl)

    # ── Alerts table ───────────────────────────────────────────────────────
    alerts = log.alerts
    if tool_filter:
        alerts = [a for a in alerts if tool_filter.lower() in a.tool.lower()]

    if alerts:
        atbl = Table(title="Runtime Alerts", box=box.SIMPLE_HEAVY, show_lines=False, highlight=True)
        atbl.add_column("Time", style="dim", no_wrap=True, max_width=26)
        atbl.add_column("Severity", no_wrap=True)
        atbl.add_column("Detector", style="bold")
        atbl.add_column("Tool", max_width=20)
        atbl.add_column("Message", max_width=70)

        for a in sorted(alerts, key=lambda x: x.severity):
            style = _severity_style(a.severity)
            atbl.add_row(
                a.ts[:19].replace("T", " "),
                f"[{style}]{a.severity.upper()}[/{style}]",
                a.detector,
                a.tool or "—",
                a.message[:120],
            )
        console.print(atbl)

    # ── Relay errors ───────────────────────────────────────────────────────
    if log.relay_errors:
        etbl = Table(title="[bold red]Relay Errors[/bold red]", box=box.SIMPLE_HEAVY)
        etbl.add_column("Time", style="dim")
        etbl.add_column("Error Type")
        etbl.add_column("Error")
        for e in log.relay_errors:
            etbl.add_row(e.ts[:19].replace("T", " "), e.error_type, e.error[:120])
        console.print(etbl)
        exit_code = 1

    # ── HMAC entries ───────────────────────────────────────────────────────
    if log.hmac_entries and not alerts_only:
        console.print(f"[dim]Response HMACs recorded: {len(log.hmac_entries)} (use --verify-hmac with --sign-key to verify)[/dim]")

    if verify_hmac_key:
        verified, failed = verify_hmac_entries(log, verify_hmac_key)
        if failed:
            console.print(f"[bold red]HMAC verification FAILED for {failed} entries![/bold red]")
            exit_code = 1
        elif verified:
            console.print(f"[green]HMAC verification passed for {verified} entries[/green]")

    if verify_chain_result is not None:
        verified_chain, tampered_chain = verify_chain_result
        if tampered_chain:
            console.print(f"[bold red]Audit chain verification FAILED for {tampered_chain} entries![/bold red]")
            exit_code = 1
        elif verified_chain:
            console.print(f"[green]Audit chain verification passed for {verified_chain} entries[/green]")

    # ── Nothing to show ────────────────────────────────────────────────────
    total_entries = len(log.tool_calls) + len(log.alerts) + len(log.relay_errors) + len(log.hmac_entries)
    if total_entries == 0 and not log.summary:
        console.print("[dim]No audit entries found in log.[/dim]")

    return exit_code


def display_json(log: AuditLog, *, chain_verification: tuple[int, int] | None = None) -> int:
    """Output structured JSON summary (for CI/scripting)."""
    s = log.summary
    out = {
        "tool_calls": len(log.tool_calls),
        "blocked": sum(1 for c in log.tool_calls if c.policy == "blocked"),
        "alerts": len(log.alerts),
        "relay_errors": len(log.relay_errors),
        "hmac_entries": len(log.hmac_entries),
        "summary": {
            "uptime_seconds": s.uptime_seconds,
            "total_tool_calls": s.total_tool_calls,
            "total_blocked": s.total_blocked,
            "runtime_alerts": s.runtime_alerts,
            "relay_errors": s.relay_errors,
            "replay_rejections": s.replay_rejections,
            "latency": s.latency,
            "calls_by_tool": s.calls_by_tool,
            "blocked_by_reason": s.blocked_by_reason,
            "runtime_alerts_by_severity": s.runtime_alerts_by_severity,
            "runtime_alerts_by_detector": s.runtime_alerts_by_detector,
            "blocked_runtime_alerts": s.blocked_runtime_alerts,
            "latest_runtime_alert_at": s.latest_runtime_alert_at,
        }
        if s
        else None,
        "alert_details": [{"severity": a.severity, "detector": a.detector, "tool": a.tool, "message": a.message} for a in log.alerts],
    }
    if chain_verification is not None:
        out["chain_verification"] = {
            "verified": chain_verification[0],
            "tampered": chain_verification[1],
        }
    sys.stdout.write(json.dumps(out, indent=2))
    sys.stdout.write("\n")
    blocked = out["blocked"]
    errors = out["relay_errors"]
    tampered = chain_verification[1] if chain_verification is not None else 0
    return 1 if (blocked or errors or tampered) else 0


# ─── Public entry point ───────────────────────────────────────────────────────


def replay(
    log_path: str,
    *,
    tool: Optional[str] = None,
    entry_type: Optional[str] = None,
    blocked_only: bool = False,
    alerts_only: bool = False,
    sign_key: Optional[str] = None,
    verify_hmac: bool = False,
    verify_chain: bool = False,
    as_json: bool = False,
) -> int:
    """Parse and display an audit log. Returns exit code (0 = clean, 1 = issues)."""
    path = Path(log_path)
    if not path.exists():
        sys.stderr.write(f"Error: audit log not found: {log_path}\n")
        return 2

    log = parse_audit_log(path)
    chain_result = verify_hash_chain(path) if verify_chain else None

    if as_json:
        return display_json(log, chain_verification=chain_result)

    return display_rich(
        log,
        tool_filter=tool,
        type_filter=entry_type,
        blocked_only=blocked_only,
        alerts_only=alerts_only,
        verify_hmac_key=sign_key if verify_hmac else None,
        verify_chain_result=chain_result,
    )
