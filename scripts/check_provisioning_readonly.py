#!/usr/bin/env python3
"""Trust-contract guard: keep agent-bom's cloud-connect provisioning read-only.

agent-bom connects to customer clouds with a strictly read-only grant. The
Terraform connect modules under ``deploy/terraform/connect-*`` mint those grants
and must therefore stay read-only forever. The ONE deliberate exception is the
agentless EBS side-scan, whose snapshot/volume lifecycle lives in a *separate*,
explicitly flagged, tag-scoped module (``connect-aws-sidescan``).

This check enforces that contract in CI so it cannot silently regress:

  1. Read-only connect modules (``connect-aws``/``-azure``/``-gcp``/``-snowflake``)
     may grant ONLY read-only IAM. Any write/mutate action fails the check.
  2. Privileged modules on a named allowlist (``connect-aws-sidescan``) may carry
     ONLY snapshot/volume lifecycle actions, and every mutating statement must be
     tag-conditioned (``aws:ResourceTag`` / ``aws:RequestTag``).
  3. No surprises: any Terraform module under ``deploy/terraform`` that grants a
     write action and is NOT on the privileged allowlist (or the explicitly
     enumerated operational-infra allowlist) fails with a clear message —
     "beyond-read-only capability must be a separate, flagged, scoped module".

Exit 0 = contract holds. Exit 1 = a violation (offending file + action named).
No third-party deps; pure stdlib so it runs anywhere in CI.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_ROOT = REPO_ROOT / "deploy" / "terraform"

# Read-only connect modules: directory name -> human label. These mint the
# customer-cloud grant and must stay read-only.
READONLY_CONNECT_MODULES = {
    "connect-aws",
    "connect-azure",
    "connect-gcp",
    "connect-snowflake",
}

# Beyond-read-only modules that are ALLOWED to mutate, but only within the
# snapshot/volume lifecycle and only when tag-scoped. Adding a new privileged
# capability means adding it here on purpose (the point of the allowlist).
PRIVILEGED_MODULES = {
    "connect-aws-sidescan",
}

# Operational/self-hosted-deployment modules. These provision agent-bom's OWN
# infrastructure (Terraform-state backend bucket, EKS cluster, ingestion AKS),
# NOT a grant into a customer's cloud. They are out of the read-only *connect*
# trust contract, but enumerated explicitly so a brand-new write-granting module
# can't sneak in unnoticed — it would fail rule 3 until added here on purpose.
OPERATIONAL_MODULES = {
    "aws/baseline",
    "platform-eks",
    "azure/ingestion",
}

# AWS write/mutate verbs. Read-only connect modules may use none of these.
AWS_WRITE_ACTION_RE = re.compile(
    r"\b[a-z0-9-]+:(Create|Delete|Put|Update|Write|Attach|Detach|Modify|Run|"
    r"Add|Remove|Set|Associate|Disassociate|Enable|Disable|Start|Stop|Reboot|"
    r"Terminate|Replace|Register|Deregister|Authorize|Revoke|Accept|Reject|"
    r"Cancel|Copy|Import|Restore|Assign|Unassign|Tag|Untag|Send|Reset)[A-Za-z]*",
)
# Any service:Action-shaped IAM action string (to find every action statement).
AWS_ACTION_RE = re.compile(r'"([a-z0-9-]+:[A-Za-z0-9*]+)"')
# An ``actions = [ ... ]`` HCL block (Terraform aws_iam_policy_document / inline
# JSON). We only treat strings inside these blocks as IAM *actions*; a bare
# "service:Name" elsewhere (e.g. a `variable = "ec2:CreateAction"` condition key)
# is NOT a grant and must not be scanned as one.
ACTIONS_BLOCK_RE = re.compile(r"actions\s*=\s*\[(.*?)\]", re.DOTALL)
# Read-only AWS verbs allowed inline in connect modules.
AWS_READONLY_PREFIXES = ("Describe", "List", "Get", "View", "BatchGet", "Lookup")

# Wildcard grant — never allowed in a connect module.
WILDCARD_ACTION_RE = re.compile(r'"\*"|"[a-z0-9-]+:\*"|"\*:\*"')

# AWS-managed policy ARNs that are read-only and explicitly blessed.
AWS_READONLY_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
    "arn:aws:iam::aws:policy/ReadOnlyAccess",
}
AWS_MANAGED_POLICY_RE = re.compile(r'"(arn:aws[a-z-]*:iam::aws:policy/[^"]+)"')

# Azure built-in roles that are read-only. "Key Vault Reader" reads key/secret
# METADATA only (never secret values); "AcrPull" is a data-plane image *pull*
# (read). Both are read-only deep-scan content grants — no mutation.
AZURE_READONLY_ROLES = {
    "reader",
    "security reader",
    "monitoring reader",
    "key vault reader",
    "acrpull",
}
AZURE_ROLE_RE = re.compile(r'role_definition_name\s*=\s*"([^"]+)"')

# GCP predefined roles that are read-only (viewer-family + securityReviewer).
GCP_WRITE_ROLE_RE = re.compile(r'role\s*=\s*"(roles/[^"]+)"')
GCP_READONLY_ROLES = {
    "roles/viewer",
    "roles/iam.securityreviewer",
    "roles/browser",
    "roles/iam.workloaduser",  # impersonation binding, not a data-plane write
    "roles/iam.workloadidentityuser",
    "roles/artifactregistry.reader",  # read-only image pull (downloadArtifacts)
}

# Snowflake privileges that mutate. Read-only role may grant only the read set.
SNOWFLAKE_PRIV_RE = re.compile(r"privileges\s*=\s*\[([^\]]*)\]")
SNOWFLAKE_READONLY_PRIVS = {
    "IMPORTED PRIVILEGES",
    "MONITOR USAGE",
    "MONITOR",
    "USAGE",
    "REFERENCE_USAGE",
    "SELECT",
    "APPLYBUDGET",  # read of budget, no mutation
}

# Snapshot/volume lifecycle actions a privileged side-scan module may use.
SIDESCAN_ALLOWED_ACTIONS = {
    "ec2:CreateSnapshot",
    "ec2:CreateVolume",
    "ec2:DeleteSnapshot",
    "ec2:DeleteVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:CreateTags",
}
# Tag-scoping condition keys a mutating side-scan statement must reference.
TAG_CONDITION_KEYS = ("aws:ResourceTag", "aws:RequestTag", "ec2:CreateAction")


@dataclass
class Result:
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, module: str, fil: Path, msg: str) -> None:
        rel = fil.relative_to(REPO_ROOT)
        self.failures.append(f"[{module}] {rel}: {msg}")

    def note(self, msg: str) -> None:
        self.notes.append(msg)


def module_key(module_dir: Path) -> str:
    """deploy/terraform/connect-aws -> 'connect-aws'; nested -> 'aws/baseline'."""
    return module_dir.relative_to(TERRAFORM_ROOT).as_posix()


def iter_module_dirs() -> list[Path]:
    """Every directory under deploy/terraform that contains a .tf file."""
    dirs = {f.parent for f in TERRAFORM_ROOT.rglob("*.tf")}
    return sorted(dirs, key=lambda p: module_key(p))


def read_tf(module_dir: Path) -> dict[Path, str]:
    return {f: f.read_text(encoding="utf-8") for f in sorted(module_dir.glob("*.tf"))}


def iter_iam_actions(text: str):
    """Yield every IAM action string that appears inside an ``actions = [...]``
    block. Restricting to those blocks avoids treating condition keys
    (``variable = "ec2:CreateAction"``) or condition values as grants."""
    for block in ACTIONS_BLOCK_RE.finditer(text):
        for m in AWS_ACTION_RE.finditer(block.group(1)):
            yield m.group(1)


def strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        # Drop trailing inline comments (best-effort; ignores '#' inside strings,
        # which our IAM action strings never contain).
        for marker in (" #", "\t#"):
            idx = line.find(marker)
            if idx != -1 and line.count('"', 0, idx) % 2 == 0:
                line = line[:idx]
                break
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rule 1 — read-only connect modules
# ---------------------------------------------------------------------------
def check_readonly_connect(module: str, files: dict[Path, str], res: Result) -> None:
    for fil, raw in files.items():
        text = strip_comments(raw)

        for m in WILDCARD_ACTION_RE.finditer(text):
            # A bare "*" can appear as an IAM *resource* ("resources = [\"*\"]"),
            # which is fine for read-only Describe*. Only flag wildcards used as
            # actions or service:* grants.
            token = m.group(0)
            if token == '"*"':
                continue  # resource wildcard, not an action wildcard
            res.fail(module, fil, f"wildcard action {token} — connect modules must be read-only")

        for action in iter_iam_actions(text):
            service, _, verb = action.partition(":")
            if verb == "*":
                res.fail(module, fil, f'wildcard action "{action}" in a read-only connect module')
                continue
            if AWS_WRITE_ACTION_RE.search(f'"{action}"') and not verb.startswith(AWS_READONLY_PREFIXES):
                res.fail(
                    module,
                    fil,
                    f'write/mutate IAM action "{action}" in a read-only connect module',
                )

        # AWS managed policies must be on the read-only blessed set.
        for m in AWS_MANAGED_POLICY_RE.finditer(text):
            arn = m.group(1)
            if arn not in AWS_READONLY_MANAGED_POLICIES:
                res.fail(module, fil, f"non-read-only AWS managed policy attached: {arn}")

        # Azure RBAC role assignments must be read-only built-ins.
        for m in AZURE_ROLE_RE.finditer(text):
            role = m.group(1)
            if role.lower() not in AZURE_READONLY_ROLES:
                res.fail(module, fil, f'non-read-only Azure role "{role}" assigned')

        # GCP IAM role bindings must be read-only predefined roles.
        for m in GCP_WRITE_ROLE_RE.finditer(text):
            role = m.group(1)
            if role.lower() not in GCP_READONLY_ROLES:
                res.fail(module, fil, f'non-read-only GCP role "{role}" bound')

        # Snowflake grants must be in the read-only privilege set.
        for m in SNOWFLAKE_PRIV_RE.finditer(text):
            privs = [p.strip().strip('"').upper() for p in m.group(1).split(",") if p.strip()]
            for priv in privs:
                if priv and priv not in SNOWFLAKE_READONLY_PRIVS:
                    res.fail(module, fil, f"non-read-only Snowflake privilege granted: {priv}")


# ---------------------------------------------------------------------------
# Rule 2 — privileged (allowlisted) modules
# ---------------------------------------------------------------------------
def check_privileged(module: str, files: dict[Path, str], res: Result) -> None:
    for fil, raw in files.items():
        text = strip_comments(raw)

        for m in WILDCARD_ACTION_RE.finditer(text):
            if m.group(0) == '"*"':
                continue
            res.fail(module, fil, f"wildcard action {m.group(0)} in a privileged module — enumerate exact actions")

        # Collect mutating actions; every one must be in the snapshot/volume set.
        mutating_actions = []
        for action in iter_iam_actions(text):
            _, _, verb = action.partition(":")
            if AWS_WRITE_ACTION_RE.search(f'"{action}"') and not verb.startswith(AWS_READONLY_PREFIXES):
                mutating_actions.append(action)
                if action not in SIDESCAN_ALLOWED_ACTIONS:
                    res.fail(
                        module,
                        fil,
                        f'privileged action "{action}" exceeds the allowed snapshot/volume lifecycle',
                    )

        # If this file mutates, the policy document must carry a tag-scoping
        # condition. We require the condition to be present in the same file as
        # the mutating actions (these modules keep the policy in one .tf).
        if mutating_actions and not any(key in text for key in TAG_CONDITION_KEYS):
            res.fail(
                module,
                fil,
                "privileged mutating actions present but NO tag-scoping condition "
                f"({' / '.join(TAG_CONDITION_KEYS)}) found — mutations must be "
                "scoped to agent-bom-created resources",
            )


# ---------------------------------------------------------------------------
# Rule 3 — no surprises
# ---------------------------------------------------------------------------
def module_has_write(files: dict[Path, str]) -> str | None:
    for fil, raw in files.items():
        text = strip_comments(raw)
        for action in iter_iam_actions(text):
            _, _, verb = action.partition(":")
            if verb == "*":
                return f'{fil.name}: "{action}"'
            if AWS_WRITE_ACTION_RE.search(f'"{action}"') and not verb.startswith(AWS_READONLY_PREFIXES):
                return f'{fil.name}: "{action}"'
        for m in AWS_MANAGED_POLICY_RE.finditer(text):
            if m.group(1) not in AWS_READONLY_MANAGED_POLICIES:
                return f"{fil.name}: managed policy {m.group(1)}"
        for m in AZURE_ROLE_RE.finditer(text):
            if m.group(1).lower() not in AZURE_READONLY_ROLES:
                return f"{fil.name}: Azure role {m.group(1)}"
        for m in GCP_WRITE_ROLE_RE.finditer(text):
            if m.group(1).lower() not in GCP_READONLY_ROLES:
                return f"{fil.name}: GCP role {m.group(1)}"
        for m in SNOWFLAKE_PRIV_RE.finditer(text):
            privs = [p.strip().strip('"').upper() for p in m.group(1).split(",") if p.strip()]
            for priv in privs:
                if priv and priv not in SNOWFLAKE_READONLY_PRIVS:
                    return f"{fil.name}: Snowflake privilege {priv}"
    return None


def main() -> int:
    if not TERRAFORM_ROOT.is_dir():
        print(f"FAIL: terraform root not found: {TERRAFORM_ROOT}", file=sys.stderr)
        return 1

    res = Result()

    for module_dir in iter_module_dirs():
        module = module_key(module_dir)
        files = read_tf(module_dir)
        if not files:
            continue

        if module in READONLY_CONNECT_MODULES:
            check_readonly_connect(module, files, res)
        elif module in PRIVILEGED_MODULES:
            check_privileged(module, files, res)
        elif module in OPERATIONAL_MODULES:
            res.note(f"operational (self-hosted) module, outside connect trust contract: {module}")
        else:
            # Rule 3: an unknown module. If it grants any write, it must be a
            # separate, flagged, scoped module on the allowlist.
            write = module_has_write(files)
            if write:
                res.fail(
                    module,
                    module_dir / write.split(":")[0],
                    f"beyond-read-only capability must be a separate, flagged, scoped module on the privileged allowlist (found {write})",
                )
            else:
                res.note(f"unlisted module with no write actions (read-only OK): {module}")

    print("Trust-contract provisioning guard — deploy/terraform")
    print(f"  read-only connect modules : {sorted(READONLY_CONNECT_MODULES)}")
    print(f"  privileged allowlist      : {sorted(PRIVILEGED_MODULES)}")
    print(f"  operational allowlist     : {sorted(OPERATIONAL_MODULES)}")
    print(f"  modules scanned           : {len(iter_module_dirs())}")
    for note in res.notes:
        print(f"  note: {note}")

    if res.failures:
        print(f"\nFAIL: {len(res.failures)} trust-contract violation(s):")
        for f in res.failures:
            print(f"  - {f}")
        print(
            "\nThe read-only connect modules must stay read-only. Any "
            "beyond-read-only capability must be a separate, flagged, "
            "least-privilege, tag-scoped module on the privileged allowlist."
        )
        return 1

    print("\nPASS: all connect modules are read-only; privileged modules are scoped + tag-conditioned; no unflagged write capability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
