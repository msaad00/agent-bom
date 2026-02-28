"""Vulnerability scanning using OSV.dev API."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent_bom.atlas import tag_blast_radius as tag_atlas_techniques
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.malicious import check_typosquat, flag_malicious_from_vulns
from agent_bom.models import Agent, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.nist_ai_rmf import tag_blast_radius as tag_nist_ai_rmf
from agent_bom.owasp import tag_blast_radius
from agent_bom.owasp_mcp import tag_blast_radius as tag_owasp_mcp

# Known AI/ML framework packages — vulnerabilities in these carry elevated risk
# because they run inside AI agents that have credentials and tool access
_AI_FRAMEWORK_PACKAGES = frozenset(
    {
        # LLM orchestration
        "langchain",
        "langchain-core",
        "langchain-community",
        "langchain-openai",
        "langgraph",
        "llama-index",
        "llama_index",
        "llama-hub",
        "autogen",
        "pyautogen",
        "crewai",
        "agency-swarm",
        "haystack-ai",
        "semantic-kernel",
        # LLM clients
        "openai",
        "anthropic",
        "mistralai",
        "cohere",
        "together",
        "google-generativeai",
        "google-cloud-aiplatform",
        "boto3",
        # Model inference
        "transformers",
        "huggingface-hub",
        "diffusers",
        "accelerate",
        "sentence-transformers",
        "optimum",
        # Vector stores and RAG
        "chromadb",
        "pinecone-client",
        "weaviate-client",
        "qdrant-client",
        "faiss-cpu",
        "faiss-gpu",
        "pymilvus",
        "milvus",
        "pgvector",
        "lancedb",
        # MCP and agent infrastructure
        "mcp",
        "fastmcp",
        "modelcontextprotocol",
        # GPU / AI infrastructure — NVIDIA
        "cuda-python",
        "cupy",
        "cupy-cuda11x",
        "cupy-cuda12x",
        "nvidia-cublas-cu11",
        "nvidia-cublas-cu12",
        "nvidia-cudnn-cu11",
        "nvidia-cudnn-cu12",
        "nvidia-cufft-cu11",
        "nvidia-cufft-cu12",
        "nvidia-cusolver-cu11",
        "nvidia-cusolver-cu12",
        "nvidia-cusparse-cu11",
        "nvidia-cusparse-cu12",
        "nvidia-nccl-cu11",
        "nvidia-nccl-cu12",
        "nvidia-cuda-runtime-cu11",
        "nvidia-cuda-runtime-cu12",
        "nvidia-cuda-nvrtc-cu11",
        "nvidia-cuda-nvrtc-cu12",
        "tensorrt",
        "nvidia-tensorrt",
        "triton",
        "tritonclient",
        # GPU / AI infrastructure — AMD ROCm
        "hip-python",
        "rocm-smi",
        # ML frameworks with GPU backends
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "tensorflow-gpu",
        "tf-nightly",
        "jax",
        "jaxlib",
        # Inference servers
        "vllm",
        "text-generation-inference",
        "llama-cpp-python",
        "ctransformers",
        # MLOps / experiment tracking
        "mlflow",
        "wandb",
        "neptune",
        "clearml",
        "ray",
        "ray[serve]",
    }
)

console = Console(stderr=True)

OSV_API_URL = "https://api.osv.dev/v1"
OSV_BATCH_URL = f"{OSV_API_URL}/querybatch"
OSV_QUERY_URL = f"{OSV_API_URL}/query"

# Map ecosystem names to OSV ecosystem identifiers
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
}

# Rate limiting: max concurrent API requests + delay between batches
MAX_CONCURRENT_REQUESTS = 10
BATCH_DELAY_SECONDS = 0.5  # 500ms between OSV batch calls
_api_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)


# Map CVSS scores to severity
def cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


# CVSS 3.x metric weights
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def parse_cvss_vector(vector: str) -> Optional[float]:
    """Compute CVSS 3.x base score from a vector string.

    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' → 9.8
    """
    try:
        if not vector.startswith("CVSS:3"):
            return None
        # Strip prefix
        parts = vector.split("/")[1:]
        metrics = dict(p.split(":") for p in parts)

        av = _CVSS3_AV.get(metrics.get("AV", ""), None)
        ac = _CVSS3_AC.get(metrics.get("AC", ""), None)
        scope = metrics.get("S", "U")
        pr_map = _CVSS3_PR_C if scope == "C" else _CVSS3_PR_U
        pr = pr_map.get(metrics.get("PR", ""), None)
        ui = _CVSS3_UI.get(metrics.get("UI", ""), None)
        c = _CVSS3_CIA.get(metrics.get("C", ""), None)
        i = _CVSS3_CIA.get(metrics.get("I", ""), None)
        a = _CVSS3_CIA.get(metrics.get("A", ""), None)

        if any(v is None for v in (av, ac, pr, ui, c, i, a)):
            return None

        isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "C":
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        if isc <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if scope == "C":
            raw = min(1.08 * (isc + exploitability), 10.0)
        else:
            raw = min(isc + exploitability, 10.0)

        # Roundup to one decimal (CVSS spec: ceiling to 1 decimal)
        import math

        return math.ceil(raw * 10) / 10.0

    except Exception:
        return None


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float]]:
    """Extract severity and CVSS score from OSV vulnerability data."""
    cvss_score = None
    severity = Severity.MEDIUM  # Default

    # Check severity array — may be numeric score or CVSS vector string
    for sev in vuln_data.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            score_str = sev.get("score", "")
            try:
                cvss_score = float(score_str)
            except ValueError:
                # It's a CVSS vector string — compute the base score
                computed = parse_cvss_vector(score_str)
                if computed is not None:
                    cvss_score = computed

    # Check database_specific for severity label (reliable fallback)
    db_specific = vuln_data.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].upper()
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        severity = severity_map.get(sev_str, Severity.MEDIUM)

    # CVSS score overrides label-based severity
    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)

    return severity, cvss_score


def parse_fixed_version(vuln_data: dict, package_name: str) -> Optional[str]:
    """Extract fixed version from OSV affected data."""
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


async def query_osv_batch(packages: list[Package]) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in batch."""
    if not packages:
        return {}

    queries = []
    pkg_index = {}  # Map query index to package

    for i, pkg in enumerate(packages):
        osv_ecosystem = ECOSYSTEM_MAP.get(pkg.ecosystem)
        if not osv_ecosystem or pkg.version in ("unknown", "latest"):
            continue

        queries.append(
            {
                "version": pkg.version,
                "package": {
                    "name": pkg.name,
                    "ecosystem": osv_ecosystem,
                },
            }
        )
        pkg_index[len(queries) - 1] = pkg

    if not queries:
        return {}

    results = {}

    # OSV batch API accepts up to 1000 queries; rate-limited with retries
    batch_size = 1000
    async with create_client(timeout=30.0) as client:
        for batch_start in range(0, len(queries), batch_size):
            batch = queries[batch_start : batch_start + batch_size]

            async with _api_semaphore:
                response = await request_with_retry(
                    client,
                    "POST",
                    OSV_BATCH_URL,
                    json={"queries": batch},
                )

                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        for i, result in enumerate(data.get("results", [])):
                            vulns = result.get("vulns", [])
                            if vulns:
                                actual_idx = batch_start + i
                                pkg = pkg_index.get(actual_idx)
                                if pkg:
                                    key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                                    results[key] = vulns
                    except (ValueError, KeyError) as e:
                        console.print(f"  [red]✗[/red] OSV response parse error: {e}")
                elif response:
                    console.print(f"  [red]✗[/red] OSV API error: HTTP {response.status_code}")
                else:
                    console.print("  [red]✗[/red] OSV API unreachable after retries")

            # Rate limit: delay between batches
            if batch_start + batch_size < len(queries):
                await asyncio.sleep(BATCH_DELAY_SECONDS)

    return results


def build_vulnerabilities(vuln_data_list: list[dict], package: Package) -> list[Vulnerability]:
    """Convert OSV response data to Vulnerability objects."""
    vulns = []
    seen_ids = set()

    for vuln_data in vuln_data_list:
        vuln_id = vuln_data.get("id", "unknown")
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)

        severity, cvss_score = parse_osv_severity(vuln_data)
        fixed = parse_fixed_version(vuln_data, package.name)

        references = [ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")][:5]  # Limit to 5 references

        # Use aliases to surface CVE ID when primary ID is GHSA/OSV/RUSTSEC
        aliases = vuln_data.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        # Use CVE alias as the canonical ID so EPSS/NVD enrichment picks it up
        canonical_id = cve_alias if cve_alias and not vuln_id.startswith("CVE-") else vuln_id

        summary = vuln_data.get("summary", vuln_data.get("details", "No description available"))[:200]

        # Collect all aliases (original ID + OSV aliases, minus the canonical)
        all_aliases = [a for a in aliases if a != canonical_id]
        if vuln_id != canonical_id:
            all_aliases.append(vuln_id)

        vulns.append(
            Vulnerability(
                id=canonical_id,
                summary=summary,
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=fixed,
                references=references,
                aliases=all_aliases,
            )
        )

    return vulns


async def scan_packages(packages: list[Package]) -> int:
    """Scan a list of packages for vulnerabilities. Returns count of vulns found."""
    # Auto-resolve "latest"/"unknown" versions before OSV query
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "") and p.ecosystem in ("npm", "pypi")]
    if unresolved:
        try:
            from agent_bom.resolver import resolve_all_versions

            resolved_count = await resolve_all_versions(unresolved)
            if resolved_count:
                console.print(f"  [green]✓[/green] Auto-resolved {resolved_count} package version(s)")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] Version resolution skipped: {exc}")

    scannable = [p for p in packages if p.version not in ("unknown", "latest")]

    if not scannable:
        return 0

    results = await query_osv_batch(scannable)

    total_vulns = 0
    for pkg in scannable:
        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        vuln_data = results.get(key, [])
        if vuln_data:
            pkg.vulnerabilities = build_vulnerabilities(vuln_data, pkg)
            total_vulns += len(pkg.vulnerabilities)
            # Flag packages with MAL- prefixed vulnerability IDs as malicious
            flag_malicious_from_vulns(pkg)

    # Supplemental: check NVIDIA advisories for AI framework packages
    nvidia_packages = [
        p
        for p in scannable
        if p.name.lower().replace("-", "_") in _AI_FRAMEWORK_PACKAGES and p.name.lower().startswith(("nvidia", "cuda", "tensorrt", "nccl"))
    ]
    if nvidia_packages:
        try:
            from agent_bom.scanners.nvidia_advisory import check_nvidia_advisories

            nvidia_new = await check_nvidia_advisories(nvidia_packages)
            if nvidia_new:
                total_vulns += nvidia_new
                console.print(f"  [green]✓[/green] NVIDIA advisories: {nvidia_new} additional CVE(s)")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] NVIDIA advisory check skipped: {exc}")

    # Supplemental: check GitHub Security Advisories for all packages
    if scannable:
        try:
            from agent_bom.scanners.ghsa_advisory import check_github_advisories

            ghsa_new = await check_github_advisories(scannable)
            if ghsa_new:
                total_vulns += ghsa_new
                console.print(f"  [green]✓[/green] GHSA advisories: {ghsa_new} additional CVE(s)")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] GHSA advisory check skipped: {exc}")

    # Typosquat detection for all scanned packages
    for pkg in scannable:
        if not pkg.is_malicious:
            target = check_typosquat(pkg.name, pkg.ecosystem)
            if target:
                pkg.is_malicious = True
                pkg.malicious_reason = f"Possible typosquat of '{target}'"

    return total_vulns


async def scan_agents(agents: list[Agent]) -> list[BlastRadius]:
    """Scan all agents' MCP server packages for vulnerabilities."""
    console.print("\n[bold blue]🛡️  Scanning for vulnerabilities...[/bold blue]\n")

    # Collect all unique packages
    all_packages = []
    pkg_to_servers: dict[str, list[MCPServer]] = {}
    pkg_to_agents: dict[str, list[Agent]] = {}

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                all_packages.append(pkg)

                if key not in pkg_to_servers:
                    pkg_to_servers[key] = []
                pkg_to_servers[key].append(server)

                if key not in pkg_to_agents:
                    pkg_to_agents[key] = []
                if agent not in pkg_to_agents[key]:
                    pkg_to_agents[key].append(agent)

    # Deduplicate packages for scanning
    seen = set()
    unique_packages = []
    for pkg in all_packages:
        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    console.print(f"  Scanning {len(unique_packages)} unique packages across {len(agents)} agent(s)...")

    total_vulns = await scan_packages(unique_packages)

    # Propagate vulnerabilities back to all instances
    vuln_map = {}
    for pkg in unique_packages:
        if pkg.vulnerabilities:
            key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
            vuln_map[key] = pkg.vulnerabilities

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if key in vuln_map:
                    pkg.vulnerabilities = vuln_map[key]

    # Build blast radius analysis
    blast_radii = []
    for pkg in unique_packages:
        if not pkg.vulnerabilities:
            continue

        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        affected_servers = pkg_to_servers.get(key, [])
        affected_agents = pkg_to_agents.get(key, [])

        # Collect exposed credentials and tools — enrich from registry when server
        # config doesn't have explicit tool/credential data.
        # Cache registry lookups per server to avoid duplicate tool creation.
        from agent_bom.parsers import get_registry_entry

        exposed_creds: list[str] = []
        exposed_tools: list = []
        _registry_cache: dict[str, dict | None] = {}
        for server in affected_servers:
            server_creds = server.credential_names
            server_tools = server.tools

            # Registry enrichment: if no tools/creds known from config, use registry
            if not server_tools or not server_creds:
                if server.name not in _registry_cache:
                    _registry_cache[server.name] = get_registry_entry(server)
                reg = _registry_cache[server.name]
                if reg:
                    if not server_tools and reg.get("tools"):
                        from agent_bom.models import MCPTool

                        server_tools = [MCPTool(name=t, description="") for t in reg["tools"]]
                    if not server_creds and reg.get("credential_env_vars"):
                        server_creds = reg["credential_env_vars"]

            exposed_creds.extend(server_creds)
            exposed_tools.extend(server_tools)

        # Deduplicate credentials and tools to prevent inflation
        exposed_creds_deduped = list(set(exposed_creds))
        seen_tool_names: set[str] = set()
        deduped_tools = []
        for t in exposed_tools:
            if t.name not in seen_tool_names:
                seen_tool_names.add(t.name)
                deduped_tools.append(t)
        exposed_tools = deduped_tools

        # AI-native risk context: elevated when an AI framework has creds + tools
        is_ai_framework = (
            pkg.name.lower().replace("-", "_") in {n.replace("-", "_") for n in _AI_FRAMEWORK_PACKAGES}
            or pkg.name.lower() in _AI_FRAMEWORK_PACKAGES
        )
        has_creds = bool(exposed_creds_deduped)
        has_tools = bool(exposed_tools)
        if is_ai_framework and has_creds and has_tools:
            ai_risk_context = (
                f"AI framework '{pkg.name}' runs inside an agent with {len(exposed_creds_deduped)} "
                f"exposed credential(s) and {len(exposed_tools)} reachable tool(s). "
                f"A compromise here gives an attacker both identity and capability."
            )
        elif is_ai_framework and has_creds:
            ai_risk_context = (
                f"AI framework '{pkg.name}' has access to {len(exposed_creds_deduped)} "
                f"credential(s). Exploitation could exfiltrate secrets via LLM output."
            )
        elif is_ai_framework:
            ai_risk_context = "AI framework package — vulnerability affects LLM inference/orchestration pipeline."
        else:
            ai_risk_context = None

        for vuln in pkg.vulnerabilities:
            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=affected_servers,
                affected_agents=affected_agents,
                exposed_credentials=exposed_creds_deduped,
                exposed_tools=exposed_tools,
                ai_risk_context=ai_risk_context,
            )
            br.calculate_risk_score()
            br.owasp_tags = tag_blast_radius(br)
            br.atlas_tags = tag_atlas_techniques(br)
            br.nist_ai_rmf_tags = tag_nist_ai_rmf(br)
            br.owasp_mcp_tags = tag_owasp_mcp(br)
            blast_radii.append(br)

    # Sort by risk score descending
    blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    if total_vulns:
        console.print(f"  [red]⚠ Found {total_vulns} vulnerabilities across {len(blast_radii)} findings[/red]")
    else:
        console.print("  [green]✓ No known vulnerabilities found[/green]")

    return blast_radii


async def scan_agents_with_enrichment(
    agents: list[Agent],
    nvd_api_key: Optional[str] = None,
    enable_enrichment: bool = True,
) -> list[BlastRadius]:
    """Scan agents and enrich vulnerabilities with NVD/EPSS/KEV data."""
    # First, do normal OSV scan
    blast_radii = await scan_agents(agents)

    # Then enrich with external data
    if enable_enrichment and blast_radii:
        from agent_bom.enrichment import enrich_vulnerabilities

        # Collect all vulnerabilities
        all_vulns = []
        for agent in agents:
            for server in agent.mcp_servers:
                for pkg in server.packages:
                    all_vulns.extend(pkg.vulnerabilities)

        if all_vulns:
            await enrich_vulnerabilities(
                all_vulns,
                nvd_api_key=nvd_api_key,
                enable_nvd=True,
                enable_epss=True,
                enable_kev=True,
            )

            # Recalculate blast radius with enriched data
            for br in blast_radii:
                br.calculate_risk_score()

            # Re-sort by updated risk scores
            blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    return blast_radii


def scan_agents_sync(agents: list[Agent], enable_enrichment: bool = False, nvd_api_key: Optional[str] = None) -> list[BlastRadius]:
    """Synchronous wrapper for scan_agents."""
    if enable_enrichment:
        return asyncio.run(scan_agents_with_enrichment(agents, nvd_api_key, enable_enrichment))
    return asyncio.run(scan_agents(agents))
