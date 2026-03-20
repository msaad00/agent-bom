"""agent-iac — Infrastructure-as-code security scanning.

Scans Dockerfiles, Kubernetes manifests, Terraform, CloudFormation,
and Helm charts for security misconfigurations. 89 built-in rules
mapped to CIS, NIST, and OWASP frameworks.

Entry point: ``agent-iac`` (registered in pyproject.toml).
"""

from __future__ import annotations

import sys
from collections import OrderedDict

import click

from agent_bom import __version__
from agent_bom.cli._entry import make_entry_point
from agent_bom.cli._grouped_help import GroupedGroup

# ── Help categories ──────────────────────────────────────────────────────────

IAC_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        ("Scanning", ["scan"]),
        ("Policy", ["policy", "validate"]),
    ]
)

# ── Click group ──────────────────────────────────────────────────────────────


@click.group(
    cls=GroupedGroup,
    command_categories=IAC_CATEGORIES,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(
    version=__version__,
    prog_name="agent-iac",
    message=(f"agent-iac {__version__}\nPython {sys.version.split()[0]} · {sys.platform}\nPart of: https://github.com/msaad00/agent-bom"),
)
def iac():
    """agent-iac — Infrastructure-as-code security scanning.

    \b
    Scans IaC files for security misconfigurations:
    · Dockerfile (20 rules)       · Kubernetes YAML
    · Terraform (50 rules)        · CloudFormation
    · Helm charts (7 rules)

    \b
    Quick start:
      agent-iac scan Dockerfile k8s/ infra/main.tf
      agent-iac scan --format sarif --output results.sarif
      agent-iac policy template --output .agent-bom-policy.yaml
      agent-iac validate inventory.json

    \b
    Docs: https://github.com/msaad00/agent-bom
    """
    pass


# ── Register commands (reuse existing, zero duplication) ─────────────────────

from agent_bom.cli._focused_commands import iac_cmd  # noqa: E402
from agent_bom.cli._inventory import validate  # noqa: E402
from agent_bom.cli._policy_group import policy_group  # noqa: E402

iac.add_command(iac_cmd, "scan")
iac.add_command(policy_group, "policy")
iac.add_command(validate, "validate")

# ── Entry point ──────────────────────────────────────────────────────────────

iac_main = make_entry_point(iac, "agent-iac")
