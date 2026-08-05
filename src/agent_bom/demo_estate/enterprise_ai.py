"""Generate the AI, delivery and runtime estate *inside* the cloud accounts.

:mod:`agent_bom.demo_estate.enterprise_scale` builds the cloud population —
accounts, compute, identity, data. This module builds everything that runs *on*
it, and the single decision that shapes the whole module is where it puts them.

**First-party AI is an account resource, not a vendor lane.** A Bedrock agent, an
Azure OpenAI deployment, a Vertex endpoint and a Cortex function are services of
the account that owns them. They reuse that account's ``account_scope``,
``region`` and ``environment``, they assume identities the account already
inventoried, and they read data stores that already exist there. That shared
context *is* the correlation the product claims: the same role, the same
account, the same table. Modelling AI as a separate ``openai``/``anthropic``
provider — the shape the estate had — makes every AI asset an island with
nothing to correlate against, which is why nine of them read as an afterthought
next to two thousand cloud rows.

The third-party lane (external model providers, MCP servers and their tools,
agents) is kept, because it is real, and kept *smaller*, because it is the
minority of an enterprise's AI surface.

Everything is derived from the identity of the thing itself, never from a random
source, so the same profile always produces the same estate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from agent_bom.demo_estate.enterprise import EstateAsset

# Tag key that says which AI lane an asset belongs to. Read by the graph
# projection, the surfaces gate and the tests, so it lives in one place.
AI_LANE_TAG = "ai_lane"

_TENANT_DOMAIN = "northstar.example"

# Identity and data resource types the cloud population already generates. An AI
# service borrows from these rather than minting its own, which is the whole
# point: the principal that answers for the model is the principal that already
# answers for the bucket beside it.
_IDENTITY_TYPES = frozenset({"iam_role", "service_principal", "service_account", "role"})
_DATA_TYPES = frozenset({"bucket", "storage_account", "database", "sql_database", "table", "stage", "share"})
_COMPUTE_TYPES = frozenset({"instance", "virtual_machine", "function", "function_app", "warehouse", "cluster"})


def stable_index(*parts: str) -> int:
    """Deterministic pseudo-index derived from the identity of the thing itself.

    Same derivation as the cloud generator: structure in, structure out, so an
    estate is byte-identical on every machine and every run.
    """
    return int.from_bytes(hashlib.sha256("|".join(parts).encode("utf-8")).digest()[:4], "big")


@dataclass(frozen=True, slots=True)
class CloudAccount:
    """One generated cloud account, indexed by what an AI service needs from it.

    Built by reading the population back rather than by re-deriving it. A second
    derivation of "which identities does account X hold" would be a second source
    of truth, free to disagree with the assets actually inventoried.
    """

    provider: str
    scope: str
    regions: tuple[str, ...]
    environments: tuple[str, ...]
    identities: tuple[str, ...]
    data_stores: tuple[str, ...]
    compute: tuple[str, ...]
    # (region, environment) pairs that non-AI resources actually occupy. An AI
    # service must land on one of these, not on an arbitrary product of the two:
    # a scope no other resource occupies is a scope the drill-down shows empty.
    placements: tuple[tuple[str, str], ...]

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.scope}"


def index_cloud_accounts(assets: Sequence[EstateAsset]) -> tuple[CloudAccount, ...]:
    """Group the generated cloud population into the accounts an AI service can join."""
    identities: dict[tuple[str, str], list[str]] = {}
    data_stores: dict[tuple[str, str], list[str]] = {}
    compute: dict[tuple[str, str], list[str]] = {}
    placements: dict[tuple[str, str], list[tuple[str, str]]] = {}
    regions: dict[tuple[str, str], list[str]] = {}
    environments: dict[tuple[str, str], list[str]] = {}

    for asset in assets:
        if asset.resource_type == "organization" or asset.tags.get(AI_LANE_TAG):
            continue
        key = (asset.provider, asset.account_scope)
        placements.setdefault(key, [])
        placement = (asset.region, asset.environment)
        if placement not in placements[key]:
            placements[key].append(placement)
        for bucket, value in ((regions, asset.region), (environments, asset.environment)):
            bucket.setdefault(key, [])
            if value not in bucket[key]:
                bucket[key].append(value)
        if asset.resource_type in _IDENTITY_TYPES:
            identities.setdefault(key, []).append(asset.asset_id)
        elif asset.resource_type in _DATA_TYPES:
            data_stores.setdefault(key, []).append(asset.asset_id)
        elif asset.resource_type in _COMPUTE_TYPES:
            compute.setdefault(key, []).append(asset.asset_id)

    accounts: list[CloudAccount] = []
    for provider, scope in sorted(placements):
        key = (provider, scope)
        accounts.append(
            CloudAccount(
                provider=provider,
                scope=scope,
                regions=tuple(regions.get(key, ("global",))),
                environments=tuple(environments.get(key, ("production",))),
                identities=tuple(sorted(identities.get(key, ()))),
                data_stores=tuple(sorted(data_stores.get(key, ()))),
                compute=tuple(sorted(compute.get(key, ()))),
                placements=tuple(placements[key]),
            )
        )
    return tuple(accounts)


@dataclass(frozen=True, slots=True)
class AiServiceSpec:
    """One first-party AI service type offered by a cloud.

    ``resource_type`` is the vocabulary the graph maps onto an entity type, and
    ``service`` is the console name an operator would recognise. Both are the
    vendor's own naming — an estate that invents plausible-looking service names
    demonstrates a product that has never seen the real thing.
    """

    resource_type: str
    service: str
    label: str
    # Whether this service type is reachable from the internet when exposed, and
    # whether it reads a data store. Drives the exposure surface and the paths.
    exposable: bool
    reads_data: bool


# Verified against each vendor's current service naming (AWS Bedrock agents /
# knowledge bases / guardrails and SageMaker endpoints; Azure OpenAI deployments,
# AI Foundry projects and Cognitive Services accounts; Vertex AI endpoints,
# models and agents plus the Gemini API; Snowflake Cortex functions, Cortex
# Search services and Snowpark Container Services).
_FIRST_PARTY_AI: dict[str, tuple[AiServiceSpec, ...]] = {
    "aws": (
        AiServiceSpec("bedrock_agent", "bedrock", "Bedrock agent", exposable=False, reads_data=True),
        AiServiceSpec("bedrock_knowledge_base", "bedrock", "Bedrock knowledge base", exposable=False, reads_data=True),
        AiServiceSpec("bedrock_guardrail", "bedrock", "Bedrock guardrail", exposable=False, reads_data=False),
        AiServiceSpec("foundation_model", "bedrock", "Bedrock foundation model", exposable=False, reads_data=False),
        AiServiceSpec("sagemaker_endpoint", "sagemaker", "SageMaker endpoint", exposable=True, reads_data=True),
        AiServiceSpec("sagemaker_model", "sagemaker", "SageMaker model", exposable=False, reads_data=False),
        AiServiceSpec("training_dataset", "sagemaker", "SageMaker training dataset", exposable=False, reads_data=True),
    ),
    "azure": (
        AiServiceSpec("azure_openai_deployment", "openai", "Azure OpenAI deployment", exposable=True, reads_data=False),
        AiServiceSpec("ai_foundry_project", "aifoundry", "AI Foundry project", exposable=False, reads_data=True),
        AiServiceSpec("cognitive_services_account", "cognitiveservices", "Cognitive Services account", exposable=True, reads_data=False),
        AiServiceSpec("ai_search_index", "search", "AI Search index", exposable=False, reads_data=True),
        AiServiceSpec("prompt_template", "aifoundry", "AI Foundry prompt flow", exposable=False, reads_data=False),
    ),
    "gcp": (
        AiServiceSpec("vertex_endpoint", "aiplatform", "Vertex AI endpoint", exposable=True, reads_data=True),
        AiServiceSpec("vertex_model", "aiplatform", "Vertex AI model", exposable=False, reads_data=False),
        AiServiceSpec("vertex_agent", "aiplatform", "Vertex AI agent", exposable=False, reads_data=True),
        AiServiceSpec("gemini_api", "generativelanguage", "Gemini API surface", exposable=True, reads_data=False),
        AiServiceSpec("training_dataset", "aiplatform", "Vertex AI managed dataset", exposable=False, reads_data=True),
    ),
    "snowflake": (
        AiServiceSpec("cortex_function", "cortex", "Cortex LLM function", exposable=False, reads_data=True),
        AiServiceSpec("cortex_search_service", "cortex", "Cortex Search service", exposable=False, reads_data=True),
        AiServiceSpec("spcs_service", "spcs", "Snowpark Container Services service", exposable=True, reads_data=True),
        AiServiceSpec("prompt_template", "cortex", "Cortex prompt template", exposable=False, reads_data=False),
    ),
}

_MODEL_FAMILIES: dict[str, tuple[str, ...]] = {
    "aws": ("anthropic.claude-sonnet-4-5", "amazon.nova-pro-v1", "meta.llama-4-70b"),
    "azure": ("gpt-4.1", "gpt-4o-mini", "o4-mini"),
    "gcp": ("gemini-2.5-pro", "gemini-2.5-flash", "medlm-large"),
    "snowflake": ("snowflake-arctic", "mistral-large2", "llama3.1-70b"),
}


def _owner_for(provider: str, service: str) -> str:
    return f"{service}-ai-owners@{_TENANT_DOMAIN}"


def build_first_party_ai_assets(accounts: Sequence[CloudAccount], *, tenant_id: str, per_account: int) -> tuple[EstateAsset, ...]:
    """Emit first-party AI services into the accounts that already exist.

    Each service reuses one of the account's real ``(region, environment)``
    placements and, where the service type warrants it, names the identity it
    assumes and the data store it reads. Those two tags are what the graph turns
    into ``ASSUMES`` and ``CAN_ACCESS`` edges — the AI service, the principal and
    the table become one reachable path rather than three unrelated rows.
    """
    assets: list[EstateAsset] = []
    for account in accounts:
        catalog = _FIRST_PARTY_AI.get(account.provider)
        if not catalog or not account.placements:
            continue
        families = _MODEL_FAMILIES[account.provider]
        for slot in range(per_account):
            spec = catalog[slot % len(catalog)]
            name = f"{account.provider}-{spec.service}-{account.scope[-4:]}-{slot:02d}"
            seed = stable_index(account.provider, account.scope, name)
            region, environment = account.placements[seed % len(account.placements)]
            identity = account.identities[seed % len(account.identities)] if account.identities else ""
            data_store = account.data_stores[(seed // 7) % len(account.data_stores)] if spec.reads_data and account.data_stores else ""
            # A minority of the exposable services are actually exposed. An
            # estate where every endpoint is public is not an estate, it is a
            # test fixture for one control.
            internet_facing = spec.exposable and seed % 5 == 0
            tags = {
                "synthetic": "true",
                "environment": environment,
                AI_LANE_TAG: "first_party",
                "ai_service": spec.service,
                "model_family": families[seed % len(families)],
                "internet_facing": "true" if internet_facing else "false",
            }
            if identity:
                tags["uses_identity"] = identity
            if data_store:
                tags["reads_data"] = data_store
            if internet_facing and spec.reads_data and data_store:
                # Public endpoint in front of regulated data: the shape an
                # exposure path is supposed to find.
                tags["public_access"] = "true"
            assets.append(
                EstateAsset(
                    asset_id=f"{account.provider}:{spec.resource_type}:{account.scope}:{name}",
                    tenant_id=tenant_id,
                    provider=account.provider,
                    resource_type=spec.resource_type,
                    native_id=f"{account.provider}://{account.scope}/{spec.service}/{name}",
                    display_name=f"{spec.label} {name}",
                    environment=environment,
                    account_scope=account.scope,
                    region=region,
                    owner=_owner_for(account.provider, spec.service),
                    cost_center=f"AI-{410 + (seed % 6)}",
                    data_classifications=("phi", "restricted") if data_store else ("confidential",),
                    tags=tags,
                )
            )
    return tuple(assets)


# ── Third-party lane: external providers, MCP servers, agents ────────────────

_MCP_SERVER_CATALOG: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("claims-intake", ("lookup_member", "submit_claim", "read_policy", "list_attachments")),
    ("clinical-notes", ("search_notes", "summarize_encounter", "redact_phi", "export_note")),
    ("provider-directory", ("find_provider", "check_network", "update_roster", "read_contract")),
    ("pharmacy-benefits", ("check_formulary", "price_drug", "prior_auth", "read_claim")),
    ("care-gap-analytics", ("execute_sql", "run_cohort", "export_csv", "read_measure")),
    ("member-messaging", ("send_message", "read_thread", "list_templates", "attach_document")),
)

_EXTERNAL_MODELS: tuple[tuple[str, str, str], ...] = (
    ("openai", "gpt-4.1-mini", "hosted_model"),
    ("openai", "text-embedding-3-large", "hosted_model"),
    ("anthropic", "claude-haiku-4-5", "hosted_model"),
    ("anthropic", "claude-opus-4-1", "hosted_model"),
    ("huggingface", "bge-base-en-v1.5", "model_artifact"),
    ("huggingface", "clinical-bert-ner", "model_artifact"),
)

_AGENT_ROLES: tuple[str, ...] = (
    "member-copilot",
    "claims-triage",
    "prior-auth-reviewer",
    "care-gap-outreach",
    "provider-onboarding",
    "appeals-drafter",
)


def build_third_party_ai_assets(
    accounts: Sequence[CloudAccount],
    *,
    tenant_id: str,
    mcp_servers: int,
    agents: int,
    external_models: int,
) -> tuple[EstateAsset, ...]:
    """Emit the external AI lane — deliberately the smaller share.

    MCP servers, their tools and the agents that call them still live inside a
    cloud account, because that is where they run; what makes them third party is
    the vendor, not the address. External model endpoints are the one genuinely
    off-estate surface, and they are the terminus of the egress path.
    """
    hosts = [account for account in accounts if account.placements]
    if not hosts:
        return ()
    assets: list[EstateAsset] = []

    for index in range(mcp_servers):
        catalog_name, tool_names = _MCP_SERVER_CATALOG[index % len(_MCP_SERVER_CATALOG)]
        server_name = f"{catalog_name}-{index:02d}"
        account = hosts[stable_index("mcp-server", server_name) % len(hosts)]
        seed = stable_index(account.scope, server_name)
        region, environment = account.placements[seed % len(account.placements)]
        server_id = f"mcp:server:{server_name}"
        # A gateway-fronted server is not internet facing; a directly published
        # one is. Both exist in a real estate and the difference is the finding.
        published = seed % 4 == 0
        assets.append(
            EstateAsset(
                asset_id=server_id,
                tenant_id=tenant_id,
                provider="mcp",
                resource_type="server",
                native_id=f"mcp://{server_name}",
                display_name=f"{catalog_name.replace('-', ' ').title()} MCP",
                environment=environment,
                account_scope=account.scope,
                region=region,
                owner=f"ai-platform@{_TENANT_DOMAIN}",
                cost_center="AI-410",
                data_classifications=("phi", "pii") if seed % 3 == 0 else ("confidential",),
                tags={
                    "synthetic": "true",
                    "environment": environment,
                    AI_LANE_TAG: "third_party",
                    "internet_facing": "true" if published else "false",
                    "transport": "streamable-http" if published else "stdio",
                    "host_provider": account.provider,
                },
            )
        )
        for tool_index, tool_name in enumerate(tool_names):
            tool_seed = stable_index(server_id, tool_name)
            writes = tool_name.startswith(("submit", "update", "send", "export", "attach"))
            assets.append(
                EstateAsset(
                    asset_id=f"mcp:tool:{server_name}/{tool_name}",
                    tenant_id=tenant_id,
                    provider="mcp",
                    resource_type="tool",
                    native_id=f"mcp://{server_name}/tools/{tool_name}",
                    display_name=tool_name,
                    environment=environment,
                    account_scope=account.scope,
                    region=region,
                    owner=f"ai-platform@{_TENANT_DOMAIN}",
                    cost_center="AI-410",
                    data_classifications=("phi", "pii") if tool_seed % 3 == 0 else (),
                    tags={
                        "synthetic": "true",
                        "environment": environment,
                        AI_LANE_TAG: "third_party",
                        "mcp_server": server_id,
                        "tool_index": str(tool_index),
                        "write_capable": "true" if writes else "false",
                        "over_permissive": "true" if writes and tool_seed % 3 == 0 else "false",
                    },
                )
            )

    agent_ids: list[str] = []
    for index in range(agents):
        role = _AGENT_ROLES[index % len(_AGENT_ROLES)]
        agent_name = f"{role}-{index:02d}"
        account = hosts[stable_index("agent", agent_name) % len(hosts)]
        seed = stable_index(account.scope, agent_name)
        region, environment = account.placements[seed % len(account.placements)]
        agent_id = f"agent:{agent_name}"
        agent_ids.append(agent_id)
        tags = {
            "synthetic": "true",
            "environment": environment,
            AI_LANE_TAG: "third_party",
            "agent_role": role,
            "host_provider": account.provider,
            "autonomy": "supervised" if seed % 3 else "autonomous",
        }
        if account.identities:
            tags["uses_identity"] = account.identities[seed % len(account.identities)]
        assets.append(
            EstateAsset(
                asset_id=agent_id,
                tenant_id=tenant_id,
                provider="agent",
                resource_type="agent",
                native_id=f"agent://{agent_name}",
                display_name=agent_name,
                environment=environment,
                account_scope=account.scope,
                region=region,
                owner=f"ai-platform@{_TENANT_DOMAIN}",
                cost_center="AI-410",
                data_classifications=("confidential",),
                tags=tags,
            )
        )

    # Agent-to-agent topology, applied after the pool exists so a delegation
    # always names an agent the estate holds. A supervisor delegates to the
    # specialist in the next role, which is a ring rather than a star: a star
    # would make one node the only interesting one.
    delegated: list[EstateAsset] = []
    for asset in assets:
        if asset.resource_type != "agent":
            delegated.append(asset)
            continue
        position = agent_ids.index(asset.asset_id)
        if position % 3 == 0 and len(agent_ids) > 1:
            target = agent_ids[(position + 1) % len(agent_ids)]
            delegated.append(asset.model_copy(update={"tags": {**asset.tags, "delegates_to": target}}))
        else:
            delegated.append(asset)
    assets = delegated

    for index in range(external_models):
        provider, model_name, resource_type = _EXTERNAL_MODELS[index % len(_EXTERNAL_MODELS)]
        suffix = index // len(_EXTERNAL_MODELS)
        display = model_name if suffix == 0 else f"{model_name}-{suffix}"
        seed = stable_index(provider, display)
        account = hosts[seed % len(hosts)]
        _, environment = account.placements[seed % len(account.placements)]
        assets.append(
            EstateAsset(
                asset_id=f"model:{provider}:{display}",
                tenant_id=tenant_id,
                provider=provider,
                resource_type=resource_type,
                native_id=f"{provider}://models/{display}",
                display_name=display,
                environment=environment,
                account_scope="northstar-health-ai",
                region="global",
                owner=f"ai-platform@{_TENANT_DOMAIN}",
                cost_center="AI-410",
                data_classifications=("confidential",),
                tags={
                    "synthetic": "true",
                    "environment": environment,
                    AI_LANE_TAG: "third_party",
                    "external_endpoint": "true",
                    "internet_facing": "true",
                },
            )
        )
    return tuple(assets)


# ── Delivery and runtime: repositories, workflows, clusters, images ──────────

_REPO_NAMES: tuple[str, ...] = (
    "member-portal",
    "claims-engine",
    "eligibility-api",
    "care-gap-jobs",
    "provider-sync",
    "pharmacy-gateway",
    "appeals-service",
    "member-copilot-ui",
)


def _vulnerable_packages() -> tuple[tuple[str, str, str], ...]:
    """``(name, version, ecosystem)`` drawn from the curated advisory catalog.

    Derived rather than hand-listed on purpose. A hand-written package list is
    free to drift from the advisories, and the moment it does the estate
    inventories packages no CVE covers — a vulnerability lane that silently
    produces nothing. Generating the inventory from the catalog makes the join
    total by construction, and ``tests/test_estate_v2_scale.py`` asserts it.
    """
    from agent_bom.demo_estate.enterprise_risk import advisory_catalog

    return tuple(
        (advisory.package, version, ecosystem)
        for ecosystem, _package, version, advisory in ((row[0], row[1], row[2], row[3]) for row in advisory_catalog())
    )


def build_delivery_assets(
    accounts: Sequence[CloudAccount],
    *,
    tenant_id: str,
    repositories: int,
    clusters: int,
    workloads_per_cluster: int,
    packages_per_image: int,
) -> tuple[EstateAsset, ...]:
    """Emit the code -> image -> workload spine the cross-vendor trace walks.

    Without it a trace has nowhere to start: the estate inventoried exactly one
    repository, one workflow and one deployment, so every generated journey would
    have converged on the same three nodes and the "cross-vendor" claim would
    have rested on a single hand-authored chain.
    """
    hosts = [a for a in accounts if a.provider in {"aws", "azure", "gcp"} and a.placements]
    if not hosts:
        return ()
    assets: list[EstateAsset] = []

    for index in range(repositories):
        base = _REPO_NAMES[index % len(_REPO_NAMES)]
        repo_name = f"{base}-{index:02d}"
        seed = stable_index("repo", repo_name)
        environment = ("production", "staging", "development")[seed % 3]
        repo_id = f"github:repository:northstar-health/{repo_name}"
        assets.append(
            EstateAsset(
                asset_id=repo_id,
                tenant_id=tenant_id,
                provider="github",
                resource_type="repository",
                native_id=f"github://northstar-health/{repo_name}",
                display_name=repo_name,
                environment=environment,
                account_scope="northstar-health",
                region="global",
                owner=f"ai-platform@{_TENANT_DOMAIN}",
                cost_center=f"ENG-{500 + (seed % 8)}",
                data_classifications=("confidential",),
                tags={
                    "synthetic": "true",
                    "environment": environment,
                    "visibility": "public" if seed % 11 == 0 else "private",
                    "internet_facing": "true" if seed % 11 == 0 else "false",
                },
            )
        )
        assets.append(
            EstateAsset(
                asset_id=f"github:workflow:{repo_name}/deploy",
                tenant_id=tenant_id,
                provider="github",
                resource_type="workflow",
                native_id=f"github://northstar-health/{repo_name}/actions/deploy",
                display_name=f"Deploy {repo_name}",
                environment=environment,
                account_scope="northstar-health",
                region="global",
                owner=f"ai-platform@{_TENANT_DOMAIN}",
                cost_center=f"ENG-{500 + (seed % 8)}",
                data_classifications=("confidential",),
                tags={
                    "synthetic": "true",
                    "environment": environment,
                    "repository": repo_id,
                    # A workflow federating into a cloud role with no branch
                    # condition is how CI becomes an entry point.
                    "oidc_unconstrained": "true" if seed % 6 == 0 else "false",
                },
            )
        )

    for index in range(clusters):
        account = hosts[stable_index("cluster", str(index)) % len(hosts)]
        seed = stable_index(account.scope, "cluster", str(index))
        region, environment = account.placements[seed % len(account.placements)]
        distro = {"aws": "eks", "azure": "aks", "gcp": "gke"}[account.provider]
        cluster_name = f"{distro}-{account.scope[-4:]}-{index:02d}"
        cluster_id = f"kubernetes:cluster:{distro}/{cluster_name}"
        assets.append(
            EstateAsset(
                asset_id=cluster_id,
                tenant_id=tenant_id,
                provider="kubernetes",
                resource_type="cluster",
                native_id=f"k8s://{distro}/{cluster_name}",
                display_name=cluster_name,
                environment=environment,
                account_scope=account.scope,
                region=region,
                owner=f"cloud-platform@{_TENANT_DOMAIN}",
                cost_center="PLAT-210",
                data_classifications=("confidential",),
                tags={
                    "synthetic": "true",
                    "environment": environment,
                    "distribution": distro,
                    "host_provider": account.provider,
                    "api_server_public": "true" if seed % 5 == 0 else "false",
                    "internet_facing": "true" if seed % 5 == 0 else "false",
                },
            )
        )
        for slot in range(workloads_per_cluster):
            base = _REPO_NAMES[(seed + slot) % len(_REPO_NAMES)]
            workload_name = f"{base}-{slot:02d}"
            workload_seed = stable_index(cluster_id, workload_name)
            image_tag = f"2026.08.{(workload_seed % 28) + 1:02d}"
            digest = hashlib.sha256(f"{cluster_id}:{workload_name}".encode()).hexdigest()
            image_id = f"cloud_resource:{account.provider}:registry:image:{workload_name}@sha256:{digest}"
            workload_id = f"kubernetes:workload:{cluster_name}/{base}/{workload_name}"
            exposed = workload_seed % 7 == 0
            assets.append(
                EstateAsset(
                    asset_id=image_id,
                    tenant_id=tenant_id,
                    provider=account.provider,
                    resource_type="container_image",
                    native_id=f"registry.{account.provider}.example/{workload_name}@sha256:{digest}",
                    display_name=f"{workload_name}:{image_tag}",
                    environment=environment,
                    account_scope=account.scope,
                    region=region,
                    owner=f"ai-platform@{_TENANT_DOMAIN}",
                    cost_center="AI-410",
                    data_classifications=("confidential",),
                    tags={
                        "synthetic": "true",
                        "environment": environment,
                        "image_tag": image_tag,
                        "signed": "false" if workload_seed % 4 == 0 else "true",
                    },
                )
            )
            workload_tags = {
                "synthetic": "true",
                "environment": environment,
                "cluster": cluster_id,
                "container_image": image_id,
                "host_provider": account.provider,
                "internet_facing": "true" if exposed else "false",
                "privileged": "true" if workload_seed % 9 == 0 else "false",
            }
            if account.identities:
                workload_tags["uses_identity"] = account.identities[workload_seed % len(account.identities)]
            if account.data_stores:
                # The store this workload's identity actually reads. Declared on
                # the workload rather than inferred later, so an internet-facing
                # workload in front of regulated data is an EXPOSED_TO edge with
                # two real ends instead of a property of one node.
                workload_tags["reads_data"] = account.data_stores[(workload_seed // 11) % len(account.data_stores)]
            assets.append(
                EstateAsset(
                    asset_id=workload_id,
                    tenant_id=tenant_id,
                    provider="kubernetes",
                    resource_type="deployment",
                    native_id=f"k8s://{cluster_name}/{base}/deployment/{workload_name}",
                    display_name=workload_name,
                    environment=environment,
                    account_scope=account.scope,
                    region=region,
                    owner=f"ai-platform@{_TENANT_DOMAIN}",
                    cost_center="AI-410",
                    data_classifications=("phi", "pii") if workload_seed % 3 == 0 else ("confidential",),
                    tags=workload_tags,
                )
            )
            catalog = _vulnerable_packages()
            for package_slot in range(packages_per_image):
                name, version, ecosystem = catalog[(workload_seed + package_slot) % len(catalog)]
                assets.append(
                    EstateAsset(
                        # Keyed by the image digest, not the workload name: the
                        # same service name recurs across clusters, and keying on
                        # it collapsed four images' package lists into one.
                        asset_id=f"package:{ecosystem.lower()}:{name}@{version}:{digest[:12]}",
                        tenant_id=tenant_id,
                        provider=account.provider,
                        resource_type="package",
                        native_id=f"pkg:{ecosystem.lower()}/{name}@{version}",
                        display_name=f"{name}@{version}",
                        environment=environment,
                        account_scope=account.scope,
                        region=region,
                        owner=f"ai-platform@{_TENANT_DOMAIN}",
                        cost_center="AI-410",
                        tags={
                            "synthetic": "true",
                            "environment": environment,
                            "container_image": image_id,
                            "ecosystem": ecosystem,
                            "package_name": name,
                            "package_version": version,
                            # The identity the workload running this package
                            # holds. A vulnerability's blast radius is whatever
                            # the process can reach, so the principal belongs on
                            # the package row, not only on the workload — that is
                            # what lets a CVE finding carry an identity edge.
                            **({"uses_identity": workload_tags["uses_identity"]} if "uses_identity" in workload_tags else {}),
                            "workload": workload_id,
                        },
                    )
                )
    return tuple(assets)


def mark_cloud_exposure(assets: Sequence[EstateAsset]) -> tuple[EstateAsset, ...]:
    """Tag a deterministic minority of cloud resources as exposed or over-permissive.

    Exposure has to be a property of the inventory, not of a finding, or the
    graph cannot draw an ``EXPOSED_TO`` edge for a resource that happens to have
    no finding raised against it — and "internet-facing with no finding" is
    exactly the state a reviewer needs to see.
    """
    marked: list[EstateAsset] = []
    for asset in assets:
        if asset.tags.get("internet_facing") is not None or asset.tags.get(AI_LANE_TAG):
            marked.append(asset)
            continue
        seed = stable_index("exposure", asset.asset_id)
        tags = dict(asset.tags)
        if asset.resource_type in _IDENTITY_TYPES:
            tags["over_permissive"] = "true" if seed % 9 == 0 else "false"
            tags["internet_facing"] = "false"
        elif asset.resource_type in _DATA_TYPES:
            public = seed % 13 == 0
            tags["public_access"] = "true" if public else "false"
            tags["internet_facing"] = "true" if public else "false"
        elif asset.resource_type in _COMPUTE_TYPES:
            tags["internet_facing"] = "true" if seed % 11 == 0 else "false"
        else:
            tags["internet_facing"] = "false"
        marked.append(asset.model_copy(update={"tags": tags}))
    return tuple(marked)


__all__ = [
    "AI_LANE_TAG",
    "AiServiceSpec",
    "CloudAccount",
    "build_delivery_assets",
    "build_first_party_ai_assets",
    "build_third_party_ai_assets",
    "index_cloud_accounts",
    "mark_cloud_exposure",
    "stable_index",
]
