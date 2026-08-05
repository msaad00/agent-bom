"""Findings from every scanner the product ships, not just the posture one.

:mod:`agent_bom.demo_estate.enterprise_findings` raises CIS control failures over
the estate. Every one of its findings was a CIS check, so the estate's risk grew
with *control coverage* rather than with the estate — 439 findings across 2,068
assets, none of them a vulnerability, a leaked credential, an infrastructure-as-
code defect or a runtime policy violation. A security product whose demo shows
one scanner is demonstrating one scanner.

Four lanes are added here, and three decisions keep them honest.

**Real advisories, not invented ones.** Vulnerability findings are built from
:mod:`agent_bom.demo_advisories` — the curated catalog of genuine published
CVE/GHSA ids with their real CWE, CVSS and KEV status that the bundled demo
already uses. Inventing a CVE number, or pairing a real one with a version it
does not affect, produces a demo that a reviewer can disprove in one lookup.

**Production converters, then one explicit re-binding.** Each lane goes through
the same function a live scan uses — :func:`blast_radius_to_finding`,
:func:`secret_dict_to_finding`, :func:`iac_finding_to_finding` — so severity,
compliance classification and remediation are whatever production does. Those
converters key the asset on a *code-layer* identity (a purl, a ``file:line``),
which is correct for a repository scan and wrong for an estate: #4637 requires
one id scheme, and a finding whose asset id is a file path cannot join the
inventory. :func:`bind_to_inventory` re-points it at the estate asset the file
provisions or the image contains, keeping the code-layer location as evidence.
It is one function, applied identically by every lane, so there is no second
spelling to reconcile.

**A finding never invents its target.** Every lane iterates the inventory, so
the asset exists before the finding does. There is no path here that
materialises a stub.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from typing import Any

from agent_bom.demo_advisories import DEMO_ADVISORIES, DemoAdvisory
from agent_bom.demo_estate.enterprise import EnterpriseEstate, EstateAsset
from agent_bom.demo_estate.enterprise_ai import AI_LANE_TAG
from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    blast_radius_to_finding,
    iac_finding_to_finding,
    secret_dict_to_finding,
    stable_id,
)

ESTATE_RISK_VERSION = "enterprise_risk.v1"


def _seed(*parts: str) -> int:
    return int.from_bytes(hashlib.sha256("|".join(parts).encode("utf-8")).digest()[:4], "big")


def vulnerable_version_for(advisory: DemoAdvisory) -> str:
    """A version the advisory's own range says is affected.

    The catalog records ``introduced="0"`` and a fixed version, so *any* release
    below the fix is in range. Deriving one by stepping the fixed version's last
    component down is therefore correct by construction — and does not require
    asserting that some specific historical release existed, which is the kind
    of detail a demo gets wrong and a reviewer notices.
    """
    parts = advisory.fixed.split(".")
    for index in range(len(parts) - 1, -1, -1):
        try:
            value = int(parts[index])
        except ValueError:
            continue
        if value > 0:
            parts[index] = str(value - 1)
            # Keep every component. Truncating turned ``9.0.0`` into ``8``,
            # which is still in range but reads as a version nobody ships.
            return ".".join(parts)
    return advisory.fixed


def advisory_catalog() -> tuple[tuple[str, str, str, DemoAdvisory], ...]:
    """``(ecosystem, package, affected_version, advisory)`` for every curated row."""
    return tuple((advisory.ecosystem, advisory.package, vulnerable_version_for(advisory), advisory) for advisory in DEMO_ADVISORIES)


def _epss_for(advisory: DemoAdvisory) -> float:
    """A deterministic exploit-probability score for the synthetic estate.

    Anchored on the advisory's own severity and KEV status so the ordering is
    defensible — a KEV entry outranks a medium — while the exact value is
    synthetic and is labelled as such in the finding's evidence. The estate does
    not claim to publish real EPSS.
    """
    base = {"critical": 0.55, "high": 0.28, "medium": 0.09, "low": 0.02}.get(advisory.severity, 0.03)
    jitter = (_seed("epss", advisory.vuln_id) % 1000) / 10000.0
    score = base + jitter + (0.3 if advisory.is_kev else 0.0)
    return round(min(score, 0.97), 4)


# One ``Asset.asset_type`` per estate asset, for every lane.
#
# ``Asset.canonical_id`` is ``stable_id(asset_type, identifier)``, so two lanes
# that describe the SAME inventoried row with different asset_types mint two
# canonical ids for one asset — and the findings list, the graph and the exports
# stop joining. The posture lane goes through ``cloud_cis_check_to_finding``,
# which always writes ``cloud_resource``; anything the posture lane can also
# reach must therefore say ``cloud_resource`` too. This map holds only the rows
# posture never touches.
_ASSET_TYPE_OVERRIDES: dict[str, str] = {
    "package": "package",
    "container_image": "container",
    "repository": "repository",
    "workflow": "ci_job",
    "server": "mcp_server",
    "tool": "mcp_tool",
    "agent": "agent",
    "deployment": "workload",
    "hosted_model": "model",
    "model_artifact": "model",
}

_CLOUD_ASSET_TYPE = "cloud_resource"


def estate_asset_type(asset: EstateAsset) -> str:
    """The one ``Asset.asset_type`` every lane must use for this estate row."""
    return _ASSET_TYPE_OVERRIDES.get(asset.resource_type, _CLOUD_ASSET_TYPE)


def _classify(finding: Finding) -> Finding:
    """Run the product's own framework selection over a finding.

    Some converters call this internally and some do not. Applying it here for
    the ones that do not is what keeps every lane visible in the compliance hub
    posture instead of only the lanes whose converter happened to be written
    after the hub existed.
    """
    from agent_bom.compliance_hub import apply_hub_classification

    return apply_hub_classification(finding)


def bind_to_inventory(finding: Finding, asset: EstateAsset, estate: EnterpriseEstate, *, location: str = "") -> Finding:
    """Re-point a converter's finding at the inventoried asset it concerns.

    The production converters name the artifact they read — a purl, a
    ``file:line`` — which is the right identity for a repository scan and the
    wrong one for an estate, where every finding must resolve to a row the
    inventory already holds (#4637). The artifact identity is not discarded: it
    stays in ``evidence`` and in ``asset.location``, so the chain still shows
    *which file* and *which package*, it just hangs off the asset that owns them.

    One function, used by every lane, so there is exactly one spelling of the
    estate's finding-to-asset edge.
    """
    from agent_bom.finding_scope import normalize_account_ref

    account_ref = normalize_account_ref(asset.provider, asset.account_scope)
    finding.asset = Asset(
        name=asset.display_name,
        asset_type=estate_asset_type(asset),
        identifier=asset.asset_id,
        location=location or finding.asset.location or asset.native_id,
        provider=asset.provider,
        account_ref=account_ref,
        region=asset.region or None,
        environment=asset.environment or None,
    )
    finding.provider = asset.provider
    finding.account_ref = account_ref
    finding.region = asset.region or None
    finding.environment = asset.environment or None
    finding.evidence.update(
        {
            "resource_id": asset.asset_id,
            "resource_name": asset.display_name,
            "resource_type": asset.resource_type,
            "tenant_id": estate.tenant_id,
            "synthetic": True,
            "fictional": True,
            "disclosure": estate.disclosure,
            "estate_id": estate.estate_id,
            "data_classifications": list(asset.data_classifications),
        }
    )
    return finding


# ── Vulnerabilities ──────────────────────────────────────────────────────────


def build_vulnerability_evidence(estate: EnterpriseEstate) -> tuple[tuple[Any, Finding], ...]:
    """One CVE per inventoried package that a curated advisory actually covers.

    The package rows were generated *from* the advisory catalog, so the join is
    total by construction: a package with no matching advisory would mean the
    inventory and the catalog had drifted, and it is skipped rather than given an
    invented vulnerability.
    """
    from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
    from agent_bom.scanners.package_scan import apply_framework_tags

    by_key = {(row[0], row[1], row[2]): row[3] for row in advisory_catalog()}
    images = {asset.asset_id: asset for asset in estate.assets if asset.resource_type == "container_image"}

    pairs: list[tuple[object, Finding]] = []
    for asset in estate.assets:
        if asset.resource_type != "package":
            continue
        ecosystem = asset.tags.get("ecosystem", "")
        name = asset.tags.get("package_name", "")
        version = asset.tags.get("package_version", "")
        advisory = by_key.get((ecosystem.lower(), name, version))
        if advisory is None:
            continue

        image = images.get(asset.tags.get("container_image", ""))
        package = Package(name=name, version=version, ecosystem=ecosystem)
        vulnerability = Vulnerability(
            id=advisory.vuln_id,
            summary=advisory.summary,
            severity=Severity(advisory.severity),
            cvss_score=advisory.cvss_score,
            cwe_ids=[advisory.cwe] if advisory.cwe else [],
            fixed_version=advisory.fixed,
            is_kev=advisory.is_kev,
            epss_score=_epss_for(advisory),
            # Network exploitability is a property of the advisory, not of the
            # host: a KEV entry with a network CVSS vector is exploitable
            # wherever it runs. Derived from the catalog, never from whether the
            # estate happened to mark the workload internet-facing, so the two
            # signals stay independent when the graph fuses them.
            network_exploitable=advisory.cvss_score >= 7.0,
        )
        blast_radius = BlastRadius(
            vulnerability=vulnerability,
            package=package,
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )
        # The same stamping a live package scan does before converting. Without
        # it the blast radius reaches the converter with every framework list
        # empty, and the estate's vulnerabilities evidence no control at all —
        # a demo showing a CVE lane that the compliance posture cannot see.
        apply_framework_tags(blast_radius)
        finding = blast_radius_to_finding(blast_radius)
        bind_to_inventory(finding, asset, estate, location=asset.native_id)
        # The converter keys a finding on (advisory, package) because a
        # repository scan sees each package once. An estate ships the same
        # package inside twenty-one images, so that key collapsed twenty-one
        # distinct exposures onto one id — the same "dedupe key omits the scope"
        # defect that has cost this repo a cross-tenant row before. The scope
        # here is the inventoried package row.
        finding.id = stable_id("estate-vuln", advisory.vuln_id, asset.asset_id)
        finding.evidence.update(
            {
                # Every lane states what was observed and what was expected.
                # For a vulnerability that is the version edge — not a
                # fabricated "configuration", the actual finding: this version
                # is installed, the advisory fixes it in that one.
                "configuration": {
                    "setting": f"{ecosystem} package version",
                    "observed": f"{name}@{version}",
                    "expected": f"{name}>={advisory.fixed}",
                },
                "package_purl": asset.native_id,
                "package_ecosystem": ecosystem,
                "advisory_source": advisory.source,
                # The score is synthetic. Say so here rather than let a consumer
                # read it as a published EPSS value.
                "epss_source": "synthetic-demo",
                "container_image": image.asset_id if image is not None else "",
                "container_image_name": image.display_name if image is not None else "",
                "image_signed": image.tags.get("signed", "") if image is not None else "",
            }
        )
        pairs.append((blast_radius, finding))
    return tuple(pairs)


def build_vulnerability_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """The estate's CVE findings, without their blast radii."""
    return tuple(finding for _blast_radius, finding in build_vulnerability_evidence(estate))


def build_vulnerability_blast_radii(estate: EnterpriseEstate) -> tuple[Any, ...]:
    """The blast radii behind those findings, for the report's legacy CVE array.

    Both halves have to reach the scan report, and this is the reason.
    ``output.finding_views.cve_findings`` reads ``report.blast_radii`` in
    preference to the unified findings list, and the unified JSON ``findings``
    array excludes ``CVE`` by design — CVEs travel in the vulnerability array.
    So an estate that contributed CVE *findings* and no blast radii had all 768
    of them silently dropped between the seeder and ``/v1/findings``: the demo
    reported 1,833 of 2,601 seeded rows, with the entire vulnerability lane
    missing and nothing anywhere saying so.
    """
    return tuple(blast_radius for blast_radius, _finding in build_vulnerability_evidence(estate))


# ── Hardcoded secrets ────────────────────────────────────────────────────────

_SECRET_KINDS: tuple[tuple[str, str, str, str], ...] = (
    ("aws_access_key_id", "cloud_credential", "critical", ".github/workflows/deploy.yml"),
    ("snowflake_password", "database_credential", "high", "src/warehouse/client.py"),
    ("openai_api_key", "model_provider_key", "high", "services/copilot/config.py"),
    ("github_pat", "vcs_token", "high", "scripts/release.sh"),
    ("private_key_pem", "signing_key", "critical", "deploy/certs/service.pem"),
    ("slack_webhook", "webhook_url", "medium", "ops/alerting/notify.py"),
)


def build_secret_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Committed credentials, bound to the repository that holds them.

    The scanner's own identity for a secret is ``file:line`` — correct for the
    repository scan, unusable as an estate join. The repository is the
    inventoried thing; the path stays in evidence, which is what a remediator
    actually needs.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        if asset.resource_type != "repository":
            continue
        seed = _seed("secret", asset.asset_id)
        # Roughly a third of repositories carry one. An estate where every
        # repository leaks is a lint rule, not a posture.
        if seed % 3 != 0:
            continue
        for offset in range(1 + (seed // 5) % 2):
            kind, category, severity, path = _SECRET_KINDS[(seed + offset) % len(_SECRET_KINDS)]
            line = 12 + ((seed >> (offset * 3)) % 180)
            finding = secret_dict_to_finding(
                {
                    "file": f"{asset.display_name}/{path}",
                    "line": line,
                    "type": kind,
                    "category": category,
                    "severity": severity,
                    # Never a value, not even a synthetic one: the converter
                    # redacts, and handing it something that looks like a secret
                    # teaches the demo to carry secret-shaped strings.
                    "preview": "***REDACTED***",
                }
            )
            bind_to_inventory(finding, asset, estate, location=f"{asset.display_name}/{path}")
            # ``secret_dict_to_finding`` sets no framework classification — it
            # predates the hub — so a secret would evidence no control and drop
            # out of the compliance posture entirely. Every other lane's
            # converter already does this internally.
            # The controls a committed credential genuinely evidences, from the
            # catalogs this repo ships. ``secret_dict_to_finding`` sets none.
            finding.owasp_tags = ["LLM06"]
            finding.owasp_mcp_tags = ["MCP01"]
            finding.nist_800_53_tags = ["IA-5"]
            _classify(finding)
            finding.evidence.update(
                {
                    "configuration": {
                        "setting": f"{kind} storage",
                        "observed": f"hardcoded at {path}:{line}",
                        "expected": "loaded from an environment variable or secret manager",
                    },
                    "repository": asset.asset_id,
                    "commit_sha": hashlib.sha256(f"{asset.asset_id}:{offset}".encode()).hexdigest()[:40],
                    "branch": "main",
                }
            )
            findings.append(finding)
    return tuple(findings)


# ── Infrastructure as code ───────────────────────────────────────────────────


class _IacRule:
    """One infrastructure-as-code rule, with the declaration it checks.

    ``setting``/``observed``/``expected`` are the block in the module and what it
    should have said. Every lane in this file carries that pair, because a
    finding that cannot say what it saw and what it wanted is not actionable —
    and because the demo's rendered chain asserts the edge on every row.
    """

    __slots__ = (
        "rule_id",
        "title",
        "message",
        "remediation",
        "severity",
        "category",
        "resource_types",
        "setting",
        "observed",
        "expected",
        "cis_checks",
        "nist_800_53",
    )

    def __init__(
        self,
        rule_id: str,
        title: str,
        message: str,
        remediation: str,
        severity: str,
        category: str,
        resource_types: tuple[str, ...],
        *,
        setting: str,
        observed: str,
        expected: str,
        cis_checks: dict[str, str] | None = None,
        nist_800_53: tuple[str, ...] = (),
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.message = message
        self.remediation = remediation
        self.severity = severity
        self.category = category
        self.resource_types = resource_types
        self.setting = setting
        self.observed = observed
        self.expected = expected
        # Keyed by provider: the same declaration is checked differently per
        # cloud, and only some rules have a runtime CIS twin at all. A rule with
        # no entry for the asset's provider claims no CIS coverage rather than
        # borrowing another cloud's control id.
        self.cis_checks = dict(cis_checks or {})
        self.nist_800_53 = nist_800_53


_IAC_RULES: tuple[_IacRule, ...] = (
    _IacRule(
        "TF-S3-001",
        "Bucket declared without server-side encryption",
        "The bucket resource omits a server_side_encryption_configuration block.",
        "Add a server_side_encryption_configuration block with a KMS key reference.",
        "high",
        "terraform",
        ("bucket", "storage_account"),
        setting="server_side_encryption_configuration",
        observed="block absent",
        expected="block present with a kms_master_key_id",
        cis_checks={"aws": "2.1.2"},
        nist_800_53=("SC-28",),
    ),
    _IacRule(
        "TF-IAM-002",
        "Policy document grants Action '*' on Resource '*'",
        "The policy document attached to this role grants unrestricted actions.",
        "Replace the wildcard statement with the actions the workload actually calls.",
        "critical",
        "terraform",
        ("iam_role", "service_principal", "service_account", "role"),
        setting="policy_document.statement.action",
        observed='Action "*" on Resource "*"',
        expected="the actions the workload calls, on named resources",
        cis_checks={"aws": "1.16"},
        nist_800_53=("AC-6",),
    ),
    _IacRule(
        "TF-NET-003",
        "Security group opens an admin port to 0.0.0.0/0",
        "An ingress rule allows tcp/22 from any address.",
        "Restrict the ingress CIDR to the approved bastion range.",
        "high",
        "terraform",
        ("instance", "virtual_machine", "cluster"),
        setting="ingress.cidr_blocks",
        observed="0.0.0.0/0 on tcp/22",
        expected="the approved bastion CIDR",
        cis_checks={"aws": "5.2", "gcp": "3.6"},
        nist_800_53=("SC-7",),
    ),
    _IacRule(
        "K8S-POD-004",
        "Container runs without a read-only root filesystem",
        "securityContext.readOnlyRootFilesystem is unset on the pod template.",
        "Set securityContext.readOnlyRootFilesystem: true and mount writable paths explicitly.",
        "medium",
        "kubernetes",
        ("deployment",),
        setting="securityContext.readOnlyRootFilesystem",
        observed="unset",
        expected="true",
        nist_800_53=("CM-7",),
    ),
    _IacRule(
        "K8S-RBAC-005",
        "ClusterRoleBinding grants cluster-admin to a workload identity",
        "The binding gives a service account full cluster administration.",
        "Bind the workload to a namespaced Role with the verbs it uses.",
        "critical",
        "kubernetes",
        ("cluster",),
        setting="roleRef.name",
        observed="cluster-admin",
        expected="a namespaced Role scoped to the verbs used",
        nist_800_53=("AC-6",),
    ),
    _IacRule(
        "TF-AI-006",
        "Model endpoint declared with public network access",
        "The endpoint sets public network access enabled and no private endpoint.",
        "Disable public network access and front the endpoint with a private endpoint.",
        "high",
        "terraform",
        ("sagemaker_endpoint", "vertex_endpoint", "azure_openai_deployment", "spcs_service", "gemini_api"),
        setting="public_network_access",
        observed="Enabled with no private endpoint",
        expected="Disabled, fronted by a private endpoint",
        nist_800_53=("SC-7",),
    ),
    _IacRule(
        "TF-TAG-008",
        "Resource declared without an ownership tag",
        "The module omits the owner tag the tagging policy requires.",
        "Add the owner tag to the module's default_tags so every resource it creates inherits it.",
        "low",
        "terraform",
        ("bucket", "instance", "database", "virtual_machine", "table", "function", "warehouse", "share"),
        setting="default_tags.owner",
        observed="absent",
        expected="the owning team's address",
        nist_800_53=("CM-8",),
    ),
    _IacRule(
        "DKR-IMG-007",
        "Image build does not pin a digest for its base image",
        "The Dockerfile FROM line references a mutable tag.",
        "Pin the base image by digest and rebuild on advisory, not on tag movement.",
        "medium",
        "dockerfile",
        ("container_image",),
        setting="FROM",
        observed="a mutable tag",
        expected="a pinned image digest",
        nist_800_53=("CM-2",),
    ),
)

_IAC_BY_TYPE: dict[str, tuple[_IacRule, ...]] = {}
for _rule in _IAC_RULES:
    for _resource_type in _rule.resource_types:
        _IAC_BY_TYPE[_resource_type] = (*_IAC_BY_TYPE.get(_resource_type, ()), _rule)


def build_iac_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Misconfigurations in the code that declares the resource.

    Bound to the resource, not to the ``.tf`` file. The file path is the
    remediation target and stays in evidence; the *asset* is what the graph, the
    exposure path and the account roll-up need to join on.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        rules = _IAC_BY_TYPE.get(asset.resource_type)
        if not rules:
            continue
        for rule in rules:
            seed = _seed("iac", asset.asset_id, rule.rule_id)
            # An IaC defect is a property of a module, so it repeats across the
            # resources that module produces — but not across all of them.
            if seed % 100 >= 24:
                continue
            module = f"infra/{asset.provider}/{asset.resource_type}s/main.tf"
            if rule.category == "kubernetes":
                module = f"deploy/k8s/{asset.display_name}.yaml"
            elif rule.category == "dockerfile":
                module = f"services/{asset.display_name.split(':')[0]}/Dockerfile"
            # Claim only the frameworks this rule actually evidences. Every IaC
            # rule used to declare ``["CIS", "NIST-800-53"]`` regardless — so
            # "resource declared without an ownership tag" asserted CIS
            # coverage it cannot support, and a consumer reading the compliance
            # posture was told a control had been evaluated when nothing had
            # evaluated it. Half these rules have no CIS twin at all, and
            # saying so is the accurate answer.
            cis_check = rule.cis_checks.get(asset.provider)
            frameworks = (["CIS"] if cis_check else []) + (["NIST-800-53"] if rule.nist_800_53 else [])
            finding = iac_finding_to_finding(
                {
                    "rule_id": rule.rule_id,
                    "file_path": module,
                    "line_number": 8 + (seed % 220),
                    "category": rule.category,
                    "severity": rule.severity,
                    "title": rule.title,
                    "message": f"{rule.message} Declared resource: {asset.display_name}.",
                    "remediation": rule.remediation,
                    "compliance": frameworks,
                }
            )
            bind_to_inventory(finding, asset, estate, location=module)
            finding.evidence["configuration"] = {
                "setting": rule.setting,
                "observed": rule.observed,
                "expected": rule.expected,
            }
            # ``check_id`` is the join key every posture consumer reads. The
            # rule id already IS the check identity, so emitting it only as
            # ``rule_id`` left this lane unjoinable to everything the cspm
            # domain is expected to support.
            finding.evidence["check_id"] = rule.rule_id
            if cis_check:
                finding.evidence["control_id"] = f"CIS-{cis_check}"
            if rule.nist_800_53:
                finding.nist_800_53_tags = list(rule.nist_800_53)
            # ``iac_finding_to_finding`` derives its id from the file path, and
            # one module declares many resources — so without re-deriving it,
            # every resource from one module collapsed onto a single finding id.
            finding.id = stable_id("estate-iac", rule.rule_id, asset.asset_id)
            _classify(finding)
            findings.append(finding)
    return tuple(findings)


# ── Runtime and policy ───────────────────────────────────────────────────────


class _RuntimeRule:
    """A runtime detection, with the controls it genuinely evidences.

    ``controls`` is spelled per framework because a finding with no control tag
    is invisible to the compliance posture — it lands in the findings list and
    nowhere else. Every code below is drawn from the catalogs this repo already
    ships (``owasp.OWASP_LLM_TOP10``, ``owasp_mcp.OWASP_MCP_TOP10``,
    ``owasp_agentic.OWASP_AGENTIC_TOP10``, ``nist_800_53.NIST_800_53``), never
    invented, and ``tests/test_estate_v2_scale.py`` asserts they still exist.
    """

    __slots__ = (
        "rule_id",
        "finding_type",
        "source",
        "title",
        "description",
        "remediation",
        "severity",
        "setting",
        "observed",
        "expected",
        "owasp",
        "owasp_mcp",
        "owasp_agentic",
        "nist_800_53",
    )

    def __init__(
        self,
        rule_id: str,
        finding_type: FindingType,
        source: FindingSource,
        title: str,
        description: str,
        remediation: str,
        severity: str,
        *,
        setting: str,
        observed: str,
        expected: str,
        owasp: tuple[str, ...] = (),
        owasp_mcp: tuple[str, ...] = (),
        owasp_agentic: tuple[str, ...] = (),
        nist_800_53: tuple[str, ...] = (),
    ) -> None:
        # The rule *is* the check identity. Without it the runtime lane reached
        # the findings list with nothing to join on, so every consumer keyed on
        # ``check_id`` — posture rollups, the graph projection, the compliance
        # hub — simply skipped it.
        self.rule_id = rule_id
        self.finding_type = finding_type
        self.source = source
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.setting = setting
        self.observed = observed
        self.expected = expected
        self.owasp = owasp
        self.owasp_mcp = owasp_mcp
        self.owasp_agentic = owasp_agentic
        self.nist_800_53 = nist_800_53


_TOOL_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "MCP-TOOL-001",
        FindingType.INJECTION,
        FindingSource.MCP_SCAN,
        "Tool argument reaches a SQL statement without parameter binding",
        "The tool interpolates a caller-supplied argument into the statement it executes.",
        "Bind every caller-supplied value as a parameter and reject statements built by concatenation.",
        "high",
        setting="tool.arguments binding",
        observed="interpolated into the statement",
        expected="bound as a parameter",
        owasp=("LLM01",),
        owasp_mcp=("MCP05",),
        owasp_agentic=("ASI02",),
        nist_800_53=("SI-10",),
    ),
    _RuntimeRule(
        "MCP-TOOL-002",
        FindingType.TOOL_DRIFT,
        FindingSource.MCP_SCAN,
        "Tool description changed after approval",
        "The advertised description differs from the version the gateway policy was written against.",
        "Re-review the tool and re-approve it, or pin the gateway policy to the approved descriptor hash.",
        "medium",
        setting="tool.descriptor hash",
        observed="differs from the approved descriptor",
        expected="matches the approved descriptor",
        owasp=("LLM05",),
        owasp_mcp=("MCP03",),
        owasp_agentic=("ASI04",),
        nist_800_53=("CM-6",),
    ),
    _RuntimeRule(
        "MCP-TOOL-003",
        FindingType.RATE_LIMIT,
        FindingSource.MCP_SCAN,
        "Tool has no per-caller rate limit",
        "The gateway policy applies no call ceiling, so one agent can exhaust the downstream quota.",
        "Set a per-caller ceiling on the gateway policy for this tool.",
        "low",
        setting="gateway.rate_limit.per_caller",
        observed="unset",
        expected="a per-caller call ceiling",
        owasp=("LLM10",),
        owasp_mcp=("MCP02",),
        owasp_agentic=("ASI01",),
        nist_800_53=("AU-6",),
    ),
    _RuntimeRule(
        "GW-DATA-004",
        FindingType.EXFILTRATION,
        FindingSource.PROXY,
        "Write-capable tool returned regulated data to a model context",
        "Gateway evidence shows a response carrying PHI-classified columns forwarded to a model call.",
        "Scope the tool to read-only projections and enable response classification on the gateway policy.",
        "critical",
        setting="gateway.response_classification",
        observed="off; PHI columns forwarded",
        expected="on, blocking regulated columns",
        owasp=("LLM06",),
        owasp_mcp=("MCP10",),
        owasp_agentic=("ASI02",),
        nist_800_53=("AC-3",),
    ),
)

_IDENTITY_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "IAM-CIEM-005",
        FindingType.CIEM_OVER_PRIVILEGE,
        FindingSource.CLOUD_SECURITY,
        "Principal holds permissions it has never exercised",
        "Ninety days of audit evidence show none of the write actions this principal is granted.",
        "Right-size the attached policy to the actions observed, and re-review on a schedule.",
        "high",
        setting="policy.granted_actions",
        observed="write actions granted, none exercised in 90 days",
        expected="only the actions observed in use",
        owasp_agentic=("ASI03",),
        nist_800_53=("AC-6",),
    ),
)

_AI_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "AI-PROMPT-006",
        FindingType.PROMPT_SECURITY,
        FindingSource.PROMPT_SCAN,
        "System prompt embeds a data-access instruction with no guardrail",
        "The template instructs the model to retrieve records without naming a classification boundary.",
        "Move the retrieval boundary into the tool contract and attach a guardrail to the deployment.",
        "medium",
        setting="prompt.retrieval_boundary",
        observed="no classification boundary named",
        expected="the boundary declared in the tool contract",
        owasp=("LLM01", "LLM07"),
        owasp_agentic=("ASI01",),
        nist_800_53=("CM-7",),
    ),
    _RuntimeRule(
        "AI-MODEL-007",
        FindingType.MODEL_INTEGRITY,
        FindingSource.MODEL_SCAN,
        "Model artifact has no verifiable provenance",
        "The served artifact carries no signature or attestation linking it to a build.",
        "Publish and verify an attestation for the artifact before it is promoted to production.",
        "high",
        setting="artifact.attestation",
        observed="absent",
        expected="a verified build attestation",
        owasp=("LLM05",),
        owasp_agentic=("ASI04",),
        nist_800_53=("SR-4", "SI-7"),
    ),
)


def _runtime_finding(rule: _RuntimeRule, asset: EstateAsset, estate: EnterpriseEstate, *, evidence: dict[str, object]) -> Finding:
    from agent_bom.compliance_hub import apply_hub_classification
    from agent_bom.finding_scope import normalize_account_ref

    account_ref = normalize_account_ref(asset.provider, asset.account_scope)
    finding = Finding(
        finding_type=rule.finding_type,
        source=rule.source,
        asset=Asset(
            name=asset.display_name,
            asset_type=estate_asset_type(asset),
            identifier=asset.asset_id,
            location=asset.native_id,
            provider=asset.provider,
            account_ref=account_ref,
            region=asset.region or None,
            environment=asset.environment or None,
        ),
        severity=rule.severity,
        provider=asset.provider,
        account_ref=account_ref,
        region=asset.region or None,
        environment=asset.environment or None,
        title=f"{rule.title}: {asset.display_name}",
        description=rule.description,
        remediation_guidance=rule.remediation,
        evidence={
            **evidence,
            "check_id": rule.rule_id,
            "configuration": {
                "setting": rule.setting,
                "observed": rule.observed,
                "expected": rule.expected,
            },
        },
        owasp_tags=list(rule.owasp),
        owasp_mcp_tags=list(rule.owasp_mcp),
        owasp_agentic_tags=list(rule.owasp_agentic),
        nist_800_53_tags=list(rule.nist_800_53),
        id=stable_id("estate-runtime", rule.finding_type.value, asset.asset_id),
    )
    bind_to_inventory(finding, asset, estate)
    # Declare the frameworks whose controls this rule actually names. The hub's
    # selection table has no row for every (source, finding_type) pair the
    # product emits — ``CLOUD_SECURITY`` + ``CIEM_OVER_PRIVILEGE`` resolves to
    # nothing — and a finding classified into no framework is invisible to the
    # compliance posture no matter how many control tags it carries. This adds
    # no crosswalk: it names exactly the frameworks whose codes are on the rule.
    declared = [
        slug
        for slug, tags in (
            ("owasp-llm", rule.owasp),
            ("owasp-mcp", rule.owasp_mcp),
            ("owasp-agentic", rule.owasp_agentic),
            ("nist-800-53", rule.nist_800_53),
        )
        if tags
    ]
    finding.applicable_frameworks = declared
    return apply_hub_classification(finding)


def build_runtime_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Runtime and policy violations on the AI surface and its identities.

    These are the findings that only exist because the estate is *running*: a
    tool whose arguments reach a statement, an identity whose grants exceed what
    the audit log shows it using, a model served with no attestation. They are
    the lane a posture scanner cannot produce, and without them the demo's AI
    surface carries configuration risk and nothing else.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        if asset.resource_type == "tool":
            for rule in _TOOL_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                writes = asset.tags.get("write_capable") == "true"
                if rule.finding_type is FindingType.EXFILTRATION and not writes:
                    continue
                if seed % 100 >= (32 if writes else 20):
                    continue
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "mcp_server": asset.tags.get("mcp_server", ""),
                            "write_capable": writes,
                            "gateway_policy": "mcp-prod-readonly-v3",
                            "observed_calls": 40 + (seed % 900),
                        },
                    )
                )
        elif asset.resource_type in {"iam_role", "service_principal", "service_account", "role"}:
            if asset.tags.get("over_permissive") != "true":
                continue
            for rule in _IDENTITY_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "granted_actions": 60 + (seed % 120),
                            "used_actions": seed % 12,
                            "evaluation_window_days": 90,
                        },
                    )
                )
        elif asset.tags.get(AI_LANE_TAG):
            for rule in _AI_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                if rule.finding_type is FindingType.PROMPT_SECURITY and asset.resource_type not in {
                    "prompt_template",
                    "bedrock_agent",
                    "vertex_agent",
                    "agent",
                }:
                    continue
                if rule.finding_type is FindingType.MODEL_INTEGRITY and asset.resource_type not in {
                    "hosted_model",
                    "model_artifact",
                    "foundation_model",
                    "vertex_model",
                    "sagemaker_model",
                }:
                    continue
                if seed % 100 >= 38:
                    continue
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "ai_lane": asset.tags.get(AI_LANE_TAG, ""),
                            "model_family": asset.tags.get("model_family", ""),
                            "guardrail_attached": asset.tags.get("guardrail", "none"),
                        },
                    )
                )
    return tuple(findings)


def build_risk_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Every non-posture lane, in one deterministic order."""
    lanes: Iterable[Sequence[Finding]] = (
        build_vulnerability_findings(estate),
        build_secret_findings(estate),
        build_iac_findings(estate),
        build_runtime_findings(estate),
    )
    return tuple(finding for lane in lanes for finding in lane)


__all__ = [
    "ESTATE_RISK_VERSION",
    "advisory_catalog",
    "build_vulnerability_blast_radii",
    "build_vulnerability_evidence",
    "bind_to_inventory",
    "build_iac_findings",
    "build_risk_findings",
    "build_runtime_findings",
    "build_secret_findings",
    "build_vulnerability_findings",
    "vulnerable_version_for",
]
