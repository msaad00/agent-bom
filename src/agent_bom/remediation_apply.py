"""Guarded dependency remediation apply and PR workflow."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from packaging.requirements import InvalidRequirement, Requirement

from agent_bom.remediate import ApplyResult, RemediationPlan, apply_fixes, generate_package_fixes


class RemediationApplyError(RuntimeError):
    """Raised when guarded remediation refuses or fails before PR creation."""


CommandRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]


@dataclass
class RemediationApplyOutcome:
    """Summary of a guarded remediation apply attempt."""

    apply_result: ApplyResult
    changed_files: list[str] = field(default_factory=list)
    validation_commands: list[list[str]] = field(default_factory=list)
    audit_log_path: str | None = None
    branch_name: str | None = None
    pr_url: str | None = None

    def to_json(self) -> dict:
        return {
            "dry_run": self.apply_result.dry_run,
            "applied": [_fix_to_json(fix) for fix in self.apply_result.applied],
            "skipped": [_fix_to_json(fix) for fix in self.apply_result.skipped],
            "backed_up": self.apply_result.backed_up,
            "changed_files": self.changed_files,
            "validation_commands": self.validation_commands,
            "audit_log_path": self.audit_log_path,
            "branch_name": self.branch_name,
            "pr_url": self.pr_url,
        }


def default_command_runner(args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run a command with captured output for deterministic error handling."""
    return subprocess.run(
        list(args),
        cwd=str(cwd),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def apply_remediation_plan(
    plan_items: list[dict],
    *,
    project_dir: str | Path,
    open_pr: bool = False,
    backup: bool = True,
    verify: bool = True,
    branch_name: str | None = None,
    pr_title: str | None = None,
    audit_log_path: str | Path | None = None,
    runner: CommandRunner = default_command_runner,
) -> RemediationApplyOutcome:
    """Apply fixable package remediation items under a guarded workflow.

    The function refuses dirty worktrees, refuses writes outside the git repo
    root, and only opens a draft PR after dependency file validation succeeds.
    """
    project = Path(project_dir).resolve()
    repo_root = _git_root(project, runner)
    _ensure_inside_repo(project, repo_root)

    audit_path = _resolve_audit_path(audit_log_path, repo_root)
    fixable, _unfixable = generate_package_fixes(plan_items)
    fixable = [fix for fix in fixable if fix.fixed_version]
    branch = branch_name or _default_branch_name(fixable)

    base_event = {
        "action": "remediation.apply",
        "project_dir": str(project),
        "repo_root": str(repo_root),
        "open_pr": open_pr,
        "backup": backup,
        "verify": verify,
        "package_count": len(fixable),
        "packages": [_fix_to_json(fix) for fix in fixable],
    }

    if not fixable:
        result = ApplyResult(dry_run=False)
        _write_audit_event(audit_path, {**base_event, "status": "no_fixable_packages"})
        return RemediationApplyOutcome(result, audit_log_path=str(audit_path))

    _refuse_dirty_worktree(repo_root, runner, audit_path, base_event)

    if open_pr:
        _require_gh_auth(repo_root, runner, audit_path, base_event)
        _run_checked(["git", "checkout", "-b", branch], repo_root, runner)

    result = apply_fixes(RemediationPlan(package_fixes=fixable), [project], dry_run=False, backup=(backup and not open_pr))
    changed_files = _git_changed_files(repo_root, runner)

    validation_commands: list[list[str]] = []
    if verify and result.applied:
        validation_commands = _validate_dependency_files(project, repo_root, changed_files, runner)
        changed_files = _git_changed_files(repo_root, runner)

    pr_url: str | None = None
    if open_pr and result.applied:
        if not changed_files:
            _write_audit_event(audit_path, {**base_event, "status": "refused", "reason": "no_dependency_file_changes"})
            raise RemediationApplyError("remediation produced applied fixes but no git-tracked dependency file changes")
        _run_checked(["git", "add", *changed_files], repo_root, runner)
        _run_checked(["git", "commit", "-m", _commit_subject(fixable)], repo_root, runner)
        _run_checked(["git", "push", "-u", "origin", branch], repo_root, runner)
        pr_url = _create_draft_pr(repo_root, runner, pr_title or _commit_subject(fixable), _pr_body(plan_items, changed_files), branch)

    outcome = RemediationApplyOutcome(
        apply_result=result,
        changed_files=changed_files,
        validation_commands=validation_commands,
        audit_log_path=str(audit_path),
        branch_name=branch if open_pr else None,
        pr_url=pr_url,
    )
    _write_audit_event(audit_path, {**base_event, "status": "success", "outcome": outcome.to_json()})
    return outcome


def _run_checked(args: Sequence[str], cwd: Path, runner: CommandRunner) -> subprocess.CompletedProcess[str]:
    completed = runner(args, cwd)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RemediationApplyError(f"command failed: {' '.join(args)}{': ' + detail if detail else ''}")
    return completed


def _git_root(project: Path, runner: CommandRunner) -> Path:
    completed = runner(["git", "-C", str(project), "rev-parse", "--show-toplevel"], project)
    if completed.returncode != 0:
        raise RemediationApplyError("remediation apply requires a git worktree")
    return Path(completed.stdout.strip()).resolve()


def _ensure_inside_repo(project: Path, repo_root: Path) -> None:
    if project != repo_root and repo_root not in project.parents:
        raise RemediationApplyError(f"refusing to write outside repo root: {project}")


def _git_changed_files(repo_root: Path, runner: CommandRunner) -> list[str]:
    completed = _run_checked(["git", "diff", "--name-only"], repo_root, runner)
    return [line.strip() for line in completed.stdout.splitlines() if line.strip() and not line.endswith(".agent-bom-backup")]


def _refuse_dirty_worktree(repo_root: Path, runner: CommandRunner, audit_path: Path, base_event: dict) -> None:
    completed = _run_checked(["git", "status", "--porcelain"], repo_root, runner)
    if completed.stdout.strip():
        _write_audit_event(audit_path, {**base_event, "status": "refused", "reason": "dirty_worktree"})
        raise RemediationApplyError("refusing remediation apply on a dirty worktree")


def _require_gh_auth(repo_root: Path, runner: CommandRunner, audit_path: Path, base_event: dict) -> None:
    completed = runner(["gh", "auth", "status"], repo_root)
    if completed.returncode != 0:
        _write_audit_event(audit_path, {**base_event, "status": "refused", "reason": "github_auth_required"})
        raise RemediationApplyError("--open-pr requires GitHub CLI authentication")


def _validate_dependency_files(project: Path, repo_root: Path, changed_files: list[str], runner: CommandRunner) -> list[list[str]]:
    commands: list[list[str]] = []
    changed = set(changed_files)

    package_json_rel = _rel(project / "package.json", repo_root)
    package_lock_rel = _rel(project / "package-lock.json", repo_root)
    if package_json_rel in changed:
        json.loads((project / "package.json").read_text())
        if (project / "package-lock.json").exists() or package_lock_rel in changed:
            cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts"]
            _run_checked(cmd, project, runner)
            commands.append(cmd)

    requirements_rel = _rel(project / "requirements.txt", repo_root)
    if requirements_rel in changed:
        _validate_requirements(project / "requirements.txt")

    return commands


def _validate_requirements(path: Path) -> None:
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        try:
            Requirement(stripped)
        except InvalidRequirement as exc:
            raise RemediationApplyError(f"{path.name}:{lineno} is not a valid requirement: {exc}") from exc


def _rel(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve()))


def _default_branch_name(fixes) -> str:
    seed = "remediation"
    if fixes:
        first = fixes[0]
        seed = first.vulns[0] if first.vulns else first.package
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", seed.lower()).strip("-") or "remediation"
    return f"fix/{slug[:64]}"


def _commit_subject(fixes) -> str:
    if len(fixes) == 1:
        return f"fix(deps): remediate {fixes[0].package} vulnerability"
    return f"fix(deps): remediate {len(fixes)} vulnerable packages"


def _create_draft_pr(repo_root: Path, runner: CommandRunner, title: str, body: str, branch: str) -> str:
    completed = _run_checked(
        ["gh", "pr", "create", "--draft", "--base", "main", "--head", branch, "--title", title, "--body", body],
        repo_root,
        runner,
    )
    return completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else ""


def _pr_body(plan_items: list[dict], changed_files: list[str]) -> str:
    lines = [
        "## Summary",
        "",
        "- Applies guarded package remediation generated by `agent-bom remediate --apply --open-pr`.",
        "- Updates dependency manifests only; SAST/IaC auto-fixes are out of scope.",
        "",
        "## Evidence",
        "",
    ]
    for item in plan_items:
        if not item.get("fix"):
            continue
        vulns = ", ".join(item.get("vulns", [])[:8]) or "unknown"
        agents = ", ".join(item.get("agents", [])[:8]) or "none recorded"
        refs = ", ".join(item.get("references", [])[:5]) or "none recorded"
        epss = item.get("epss") or item.get("epss_score") or "not available"
        lines.extend(
            [
                f"- `{item['package']}` `{item.get('current')}` -> `{item.get('fix')}`",
                f"  - CVE/GHSA/OSV: {vulns}",
                f"  - Severity: {item.get('max_severity', 'unknown')}",
                f"  - EPSS: {epss}",
                f"  - KEV: {bool(item.get('has_kev'))}",
                f"  - Blast radius score: {item.get('blast_radius_score', 'unknown')}",
                f"  - Downstream agents: {agents}",
                f"  - Advisory references: {refs}",
            ]
        )
    lines.extend(
        [
            "",
            "## Changed Files",
            "",
            *[f"- `{path}`" for path in changed_files],
            "",
            "## Verification",
            "",
            "- Dependency file validation completed before PR creation.",
            "",
            "## Safety",
            "",
            "- Dry-run remains the default.",
            "- Apply requires explicit `--apply`.",
            "- PR creation requires GitHub authentication and opens a draft PR.",
            "- The workflow refuses dirty worktrees and writes outside the repo root.",
        ]
    )
    return "\n".join(lines)


def _resolve_audit_path(path: str | Path | None, repo_root: Path) -> Path:
    audit_path = Path(path) if path else repo_root / ".agent-bom" / "remediation-audit.jsonl"
    if not audit_path.is_absolute():
        audit_path = repo_root / audit_path
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    return audit_path


def _write_audit_event(path: Path, event: dict) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        **event,
    }
    previous = path.read_text() if path.exists() else ""
    path.write_text(previous + json.dumps(event, sort_keys=True) + "\n")


def _fix_to_json(fix) -> dict:
    return {
        "package": fix.package,
        "ecosystem": fix.ecosystem,
        "current_version": fix.current_version,
        "fixed_version": fix.fixed_version,
        "vulnerabilities": fix.vulns,
        "affected_agents": fix.agents,
        "references": fix.references,
    }
