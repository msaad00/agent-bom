"""Cloud-native SBOM pull — ECR, GCP Container Analysis, Azure Defender.

Fetches vulnerability scan results and SBOM data directly from cloud
provider APIs. No local Docker required, no image pull, no Syft.

Supported providers:
- **AWS ECR**: Enhanced Scanning (Inspector) findings + CycloneDX SBOM
- **GCP Artifact Registry**: Container Analysis vulnerability occurrences
- **Azure ACR**: Defender for Containers scan results

Usage::

    from agent_bom.cloud.sbom_pull import pull_cloud_sbom

    result = pull_cloud_sbom("ecr", "123456.dkr.ecr.us-east-1.amazonaws.com/myapp:latest")
    # result = {"packages": [...], "vulnerabilities": [...], "source": "ecr-inspector"}
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


def _import_google_cloud_module(module: str) -> Any:
    """Import optional Google Cloud SDK modules without requiring mypy stubs."""
    return importlib.import_module(f"google.cloud.{module}")


@dataclass
class CloudSBOMResult:
    """Result from a cloud-native SBOM pull."""

    provider: str  # "ecr", "gcr", "acr"
    image_ref: str
    packages: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    sbom_format: str = ""  # "cyclonedx", "spdx", or ""
    raw_sbom: dict | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "image": self.image_ref,
            "packages": self.packages,
            "vulnerabilities": self.vulnerabilities,
            "sbom_format": self.sbom_format,
            "package_count": len(self.packages),
            "vuln_count": len(self.vulnerabilities),
            "warnings": self.warnings,
        }


# ── AWS ECR ──────────────────────────────────────────────────────────────────


def _pull_ecr(image_ref: str, region: str | None = None, profile: str | None = None) -> CloudSBOMResult:
    """Pull SBOM/scan findings from AWS ECR Enhanced Scanning (Inspector).

    Requires: boto3, aws credentials configured.
    """
    result = CloudSBOMResult(provider="ecr", image_ref=image_ref)

    try:
        import boto3
    except ImportError:
        result.warnings.append("boto3 not installed. Install with: pip install 'agent-bom[cloud]'")
        return result

    # Parse image reference: account.dkr.ecr.region.amazonaws.com/repo:tag
    parts = image_ref.split("/", 1)
    if len(parts) != 2 or "ecr" not in parts[0]:
        result.warnings.append(f"Invalid ECR image reference: {image_ref}")
        return result

    registry_host = parts[0]
    repo_tag = parts[1]
    repo_name = repo_tag.split(":")[0]
    image_tag = repo_tag.split(":")[1] if ":" in repo_tag else "latest"

    # Extract region from registry host
    if not region:
        # 123456.dkr.ecr.us-east-1.amazonaws.com
        host_parts = registry_host.split(".")
        if len(host_parts) >= 4:
            region = host_parts[3]

    try:
        session_kwargs: dict = {}
        if region:
            session_kwargs["region_name"] = region
        if profile:
            session_kwargs["profile_name"] = profile

        session = boto3.Session(**session_kwargs)
        ecr = session.client("ecr")

        # Get image digest
        resp = ecr.describe_images(
            repositoryName=repo_name,
            imageIds=[{"imageTag": image_tag}],
        )
        images = resp.get("imageDetails", [])
        if not images:
            result.warnings.append(f"Image not found: {repo_name}:{image_tag}")
            return result

        digest = images[0].get("imageDigest", "")

        # Get Enhanced Scanning findings
        findings_resp = ecr.describe_image_scan_findings(
            repositoryName=repo_name,
            imageId={"imageDigest": digest},
        )
        scan_findings = findings_resp.get("imageScanFindings", {})
        findings = scan_findings.get("findings", [])

        for f in findings:
            result.vulnerabilities.append(
                {
                    "id": f.get("name", ""),
                    "severity": f.get("severity", "UNKNOWN").lower(),
                    "description": f.get("description", ""),
                    "uri": f.get("uri", ""),
                    "package": f.get("attributes", [{}])[0].get("value", "") if f.get("attributes") else "",
                }
            )

        # Try to get SBOM from Inspector (if Enhanced Scanning is enabled)
        try:
            inspector = session.client("inspector2")
            sbom_resp = inspector.list_findings(
                filterCriteria={
                    "ecrImageRepositoryName": [{"comparison": "EQUALS", "value": repo_name}],
                    "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
                },
                maxResults=100,
            )
            for finding in sbom_resp.get("findings", []):
                pkg_info = finding.get("packageVulnerabilityDetails", {})
                for pkg in pkg_info.get("vulnerablePackages", []):
                    result.packages.append(
                        {
                            "name": pkg.get("name", ""),
                            "version": pkg.get("version", ""),
                            "ecosystem": pkg.get("packageManager", "").lower(),
                            "fixed_version": pkg.get("fixedInVersion", ""),
                        }
                    )
        except Exception as exc:
            result.warnings.append(f"Inspector SBOM not available: {exc}")

        result.sbom_format = "inspector"
        logger.info("ECR pull: %d vulns, %d packages from %s", len(result.vulnerabilities), len(result.packages), image_ref)

    except Exception as exc:
        result.warnings.append(f"ECR pull failed: {exc}")

    return result


# ── GCP Artifact Registry ────────────────────────────────────────────────────


def _pull_gcr(image_ref: str, project: str | None = None) -> CloudSBOMResult:
    """Pull vulnerability occurrences from GCP Container Analysis.

    Requires: google-cloud-containeranalysis, gcloud auth configured.
    """
    result = CloudSBOMResult(provider="gcr", image_ref=image_ref)

    try:
        containeranalysis_v1 = _import_google_cloud_module("containeranalysis_v1")
    except ImportError:
        result.warnings.append("google-cloud-containeranalysis not installed. Install with: pip install 'agent-bom[cloud]'")
        return result

    try:
        client = containeranalysis_v1.ContainerAnalysisClient()
        grafeas = client.get_grafeas_client()

        # Build resource URL from image ref
        resource_url = f"https://{image_ref}"
        filter_str = f'resourceUrl="{resource_url}" AND kind="VULNERABILITY"'

        if not project:
            # Try to extract project from image ref
            # region-docker.pkg.dev/project/repo/image:tag
            parts = image_ref.split("/")
            if len(parts) >= 3:
                project = parts[1]

        if not project:
            result.warnings.append("GCP project required. Use --gcp-project or include in image ref.")
            return result

        parent = f"projects/{project}"
        occurrences = grafeas.list_occurrences(parent=parent, filter=filter_str)

        for occ in occurrences:
            vuln = occ.vulnerability
            result.vulnerabilities.append(
                {
                    "id": vuln.short_description if vuln.short_description else occ.name,
                    "severity": vuln.severity.name.lower() if vuln.severity else "unknown",
                    "cvss_score": vuln.cvss_score if vuln.cvss_score else None,
                    "package": vuln.package_issue[0].affected_package if vuln.package_issue else "",
                    "fixed_version": vuln.package_issue[0].fixed_version.full_name
                    if vuln.package_issue and vuln.package_issue[0].fixed_version
                    else "",
                }
            )

        logger.info("GCR pull: %d vulns from %s", len(result.vulnerabilities), image_ref)

    except Exception as exc:
        result.warnings.append(f"GCR pull failed: {exc}")

    return result


# ── Azure ACR ────────────────────────────────────────────────────────────────


def _pull_acr(image_ref: str, subscription: str | None = None) -> CloudSBOMResult:
    """Pull scan results from Azure Defender for Containers.

    Requires: azure-mgmt-security, az login configured.
    """
    result = CloudSBOMResult(provider="acr", image_ref=image_ref)

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.security import SecurityCenter
    except ImportError:
        result.warnings.append("azure-mgmt-security not installed. Install with: pip install 'agent-bom[cloud]'")
        return result

    try:
        credential = DefaultAzureCredential()
        if not subscription:
            result.warnings.append("Azure subscription required. Use --azure-subscription.")
            return result

        client = SecurityCenter(credential, subscription)

        # Query container vulnerability assessments
        assessments = client.sub_assessments.list_all(
            scope=f"/subscriptions/{subscription}",
            assessment_name="dbd0cb49-b563-45e7-9724-889e799fa648",  # Container vuln assessment
        )

        for assessment in assessments:
            additional = assessment.additional_data or {}
            result.vulnerabilities.append(
                {
                    "id": assessment.id or "",
                    "severity": (assessment.status.severity or "unknown").lower() if assessment.status else "unknown",
                    "description": assessment.description or "",
                    "package": additional.get("patchable", ""),
                    "image": additional.get("imageDigest", ""),
                }
            )

        logger.info("ACR pull: %d vulns from %s", len(result.vulnerabilities), image_ref)

    except Exception as exc:
        result.warnings.append(f"ACR pull failed: {exc}")

    return result


# ── Public API ───────────────────────────────────────────────────────────────


def pull_cloud_sbom(
    provider: str,
    image_ref: str,
    *,
    region: str | None = None,
    profile: str | None = None,
    project: str | None = None,
    subscription: str | None = None,
) -> CloudSBOMResult:
    """Pull SBOM/vulnerability data from a cloud container registry.

    Args:
        provider: "ecr", "gcr", or "acr".
        image_ref: Full image reference (registry/repo:tag).
        region: AWS region (ECR only).
        profile: AWS credential profile (ECR only).
        project: GCP project ID (GCR only).
        subscription: Azure subscription ID (ACR only).

    Returns:
        CloudSBOMResult with packages, vulnerabilities, and metadata.
    """
    _providers = {
        "ecr": lambda: _pull_ecr(image_ref, region, profile),
        "gcr": lambda: _pull_gcr(image_ref, project),
        "acr": lambda: _pull_acr(image_ref, subscription),
    }

    if provider not in _providers:
        return CloudSBOMResult(
            provider=provider,
            image_ref=image_ref,
            warnings=[f"Unknown provider: {provider}. Use: ecr, gcr, acr"],
        )

    return _providers[provider]()


def detect_provider(image_ref: str) -> str | None:
    """Auto-detect cloud provider from image reference.

    Extracts the registry host (before first ``/``) and matches against
    known cloud registry patterns. Only checks the host component to
    prevent substring injection via repo names or tags.

    Returns "ecr", "gcr", "acr", or None.
    """
    ref = image_ref.lower().strip()
    if not ref:
        return None

    # Extract registry host: "registry.example.com/repo:tag" → "registry.example.com"
    registry, _, _ = ref.partition("/")

    # AWS ECR: 123456789012.dkr.ecr.us-east-1.amazonaws.com
    if ".dkr.ecr." in registry and registry.endswith(".amazonaws.com"):
        return "ecr"
    # GCP: gcr.io or REGION-docker.pkg.dev (Artifact Registry)
    if registry == "gcr.io" or registry.endswith("-docker.pkg.dev"):
        return "gcr"
    # Azure ACR: name.azurecr.io
    if registry.endswith(".azurecr.io"):
        return "acr"
    return None
