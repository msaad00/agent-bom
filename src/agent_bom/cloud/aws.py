"""AWS cloud discovery — Bedrock agents, Lambda action groups, ECS tasks, SageMaker endpoints.

Requires ``boto3``.  Install with::

    pip install 'agent-bom[aws]'

Authentication uses the standard boto3 credential chain (env vars, ~/.aws/credentials,
IAM role, SSO).  Only *read* permissions are needed — no write APIs are ever called.
"""

from __future__ import annotations

import io
import json
import logging
import os
import zipfile
from email.parser import Parser as EmailParser
from pathlib import Path
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover(
    region: str | None = None,
    profile: str | None = None,
    include_ecs: bool = True,
    include_sagemaker: bool = False,
    include_lambda: bool = False,
    include_eks: bool = False,
    include_step_functions: bool = False,
    include_ec2: bool = False,
    ec2_tag_filter: dict[str, str] | None = None,
    tag_filter: dict[str, str] | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from AWS Bedrock, Lambda, ECS, EKS, Step Functions, and more.

    Returns:
        (agents, warnings) — agents found and non-fatal warning strings.

    Raises:
        CloudDiscoveryError: if ``boto3`` is not installed.
    """
    try:
        import boto3  # noqa: F811
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for AWS discovery. Install with: pip install 'agent-bom[aws]'")

    agents: list[Agent] = []
    warnings: list[str] = []
    ecs_image_refs: list[str] = []

    session_kwargs: dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    if profile:
        session_kwargs["profile_name"] = profile

    session = boto3.Session(**session_kwargs)
    resolved_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    # ── Bedrock Agents ────────────────────────────────────────────────────
    try:
        bedrock_agents, bedrock_warnings = _discover_bedrock(session, resolved_region)
        agents.extend(bedrock_agents)
        warnings.extend(bedrock_warnings)
    except NoCredentialsError:
        warnings.append("AWS credentials not found. Configure via env vars, ~/.aws/credentials, IAM role, or SSO.")
        return agents, warnings
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDeniedException", "UnauthorizedAccess"):
            warnings.append("Access denied for bedrock-agent:ListAgents. Attach the BedrockAgentReadOnly or AmazonBedrockReadOnly policy.")
        else:
            warnings.append(f"AWS Bedrock API error: {exc}")

    # ── ECS Tasks ─────────────────────────────────────────────────────────
    if include_ecs:
        try:
            ecs_refs, ecs_warns = _discover_ecs_images(session, resolved_region)
            ecs_image_refs.extend(ecs_refs)
            warnings.extend(ecs_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for ECS APIs. Attach AmazonECSReadOnlyAccess policy.")
            else:
                warnings.append(f"AWS ECS API error: {exc}")

    # ── SageMaker Endpoints ───────────────────────────────────────────────
    if include_sagemaker:
        try:
            sm_agents, sm_warns = _discover_sagemaker(session, resolved_region)
            agents.extend(sm_agents)
            warnings.extend(sm_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for SageMaker APIs. Attach AmazonSageMakerReadOnly policy.")
            else:
                warnings.append(f"AWS SageMaker API error: {exc}")

    # ── Lambda Functions (direct discovery) ────────────────────────────────
    if include_lambda:
        try:
            lambda_agents, lambda_warns = _discover_lambda_functions(session, resolved_region, warnings)
            agents.extend(lambda_agents)
            warnings.extend(lambda_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for Lambda APIs. Attach AWSLambda_ReadOnlyAccess policy.")
            else:
                warnings.append(f"AWS Lambda API error: {exc}")

    # ── EKS Clusters ───────────────────────────────────────────────────────
    if include_eks:
        try:
            eks_agents, eks_warns = _discover_eks_images(session, resolved_region)
            agents.extend(eks_agents)
            warnings.extend(eks_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for EKS APIs. Attach AmazonEKSReadOnlyAccess policy.")
            else:
                warnings.append(f"AWS EKS API error: {exc}")

    # ── Step Functions ─────────────────────────────────────────────────────
    if include_step_functions:
        try:
            sfn_agents, sfn_warns = _discover_step_functions(session, resolved_region, warnings)
            agents.extend(sfn_agents)
            warnings.extend(sfn_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for Step Functions APIs. Attach AWSStepFunctionsReadOnlyAccess policy.")
            else:
                warnings.append(f"AWS Step Functions API error: {exc}")

    # ── EC2 Instances (tag-filtered) ───────────────────────────────────────
    if include_ec2:
        try:
            ec2_agents, ec2_warns = _discover_ec2_instances(session, resolved_region, ec2_tag_filter or {})
            agents.extend(ec2_agents)
            warnings.extend(ec2_warns)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UnauthorizedAccess"):
                warnings.append("Access denied for EC2 APIs. Attach AmazonEC2ReadOnlyAccess policy.")
            else:
                warnings.append(f"AWS EC2 API error: {exc}")

    # ── ECS images as agents ──────────────────────────────────────────────
    for img_ref in ecs_image_refs:
        ecs_agent = Agent(
            name=f"ecs-image:{img_ref}",
            agent_type=AgentType.CUSTOM,
            config_path=f"ecs://{img_ref}",
            source="aws-ecs",
            mcp_servers=[
                MCPServer(
                    name=img_ref,
                    command="docker",
                    args=["run", img_ref],
                    transport=TransportType.STDIO,
                )
            ],
        )
        agents.append(ecs_agent)

    return agents, warnings


# ---------------------------------------------------------------------------
# Bedrock discovery
# ---------------------------------------------------------------------------


def _discover_bedrock(session: Any, region: str) -> tuple[list[Agent], list[str]]:
    """Discover Bedrock agents and their action groups."""
    client = session.client("bedrock-agent", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    # Paginate through all agents
    paginator = client.get_paginator("list_agents")
    for page in paginator.paginate():
        for summary in page.get("agentSummaries", []):
            agent_id = summary["agentId"]
            agent_name = summary.get("agentName", agent_id)
            agent_status = summary.get("agentStatus", "UNKNOWN")

            if agent_status not in ("PREPARED", "NOT_PREPARED"):
                continue

            try:
                detail = client.get_agent(agentId=agent_id)["agent"]
            except Exception as exc:
                warnings.append(f"Could not get details for Bedrock agent {agent_id}: {exc}")
                continue

            agent_arn = detail.get("agentArn", f"arn:aws:bedrock:{region}:agent/{agent_id}")
            foundation_model = detail.get("foundationModel", "unknown")

            # Discover action groups → Lambda functions
            mcp_servers = _get_action_group_servers(client, session, agent_id, region, warnings)

            agent = Agent(
                name=f"bedrock:{agent_name}",
                agent_type=AgentType.CUSTOM,
                config_path=agent_arn,
                source="aws-bedrock",
                version=foundation_model,
                mcp_servers=mcp_servers,
            )
            agents.append(agent)

    return agents, warnings


def _get_action_group_servers(
    bedrock_client: Any,
    session: Any,
    agent_id: str,
    region: str,
    warnings: list[str],
) -> list[MCPServer]:
    """Convert Bedrock agent action groups into MCPServer objects."""
    servers: list[MCPServer] = []

    try:
        paginator = bedrock_client.get_paginator("list_agent_action_groups")
        for page in paginator.paginate(agentId=agent_id, agentVersion="DRAFT"):
            for ag in page.get("actionGroupSummaries", []):
                ag_name = ag.get("actionGroupName", "unknown")
                ag_id = ag.get("actionGroupId", "")

                try:
                    detail = bedrock_client.get_agent_action_group(
                        agentId=agent_id,
                        agentVersion="DRAFT",
                        actionGroupId=ag_id,
                    )["agentActionGroup"]
                except Exception:
                    continue

                executor = detail.get("actionGroupExecutor", {})
                lambda_arn = executor.get("lambda")

                # Extract tools from the action group API schema
                tools = _extract_tools_from_schema(detail)

                # Extract packages from Lambda layers if we have a Lambda ARN
                packages: list[Package] = []
                if lambda_arn:
                    packages = _extract_lambda_packages(session, lambda_arn, region, warnings)

                server = MCPServer(
                    name=f"action-group:{ag_name}",
                    command="lambda" if lambda_arn else "",
                    args=[lambda_arn] if lambda_arn else [],
                    transport=TransportType.STREAMABLE_HTTP,
                    env={"AWS_REGION": region},
                    tools=tools,
                    packages=packages,
                )
                servers.append(server)

    except Exception as exc:
        warnings.append(f"Could not list action groups for agent {agent_id}: {exc}")

    return servers


def _extract_tools_from_schema(action_group_detail: dict) -> list[MCPTool]:
    """Extract tool definitions from an action group's API schema."""
    tools: list[MCPTool] = []

    api_schema = action_group_detail.get("apiSchema", {})
    # The schema can be inline JSON or an S3 reference
    payload = api_schema.get("payload", "")
    if not payload:
        # Function schema — simpler format
        func_schema = action_group_detail.get("functionSchema", {})
        for func in func_schema.get("functions", []):
            tools.append(
                MCPTool(
                    name=func.get("name", "unknown"),
                    description=func.get("description", ""),
                )
            )
        return tools

    # Parse OpenAPI spec
    try:
        spec = json.loads(payload) if isinstance(payload, str) else payload
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    op_id = op.get("operationId", f"{method.upper()} {path}")
                    tools.append(
                        MCPTool(
                            name=op_id,
                            description=op.get("summary", op.get("description", "")),
                        )
                    )
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse OpenAPI spec for Lambda tool extraction: %s", exc)

    return tools


# ---------------------------------------------------------------------------
# Lambda package extraction
# ---------------------------------------------------------------------------


def _extract_lambda_packages(
    session: Any,
    lambda_arn: str,
    region: str,
    warnings: list[str],
) -> list[Package]:
    """Extract packages from a Lambda function's layers and deployment package."""
    lambda_client = session.client("lambda", region_name=region)
    packages: list[Package] = []

    try:
        func_config = lambda_client.get_function(FunctionName=lambda_arn)
        config = func_config.get("Configuration", {})
        runtime = config.get("Runtime", "")

        # Determine ecosystem from runtime
        ecosystem = "pypi" if "python" in runtime else "npm" if "node" in runtime else "unknown"

        # Extract from layers
        for layer in config.get("Layers", []):
            layer_arn = layer.get("Arn", "")
            try:
                layer_packages = _packages_from_layer(lambda_client, layer_arn, ecosystem)
                packages.extend(layer_packages)
            except Exception as exc:
                warnings.append(f"Could not extract packages from Lambda layer {layer_arn}: {exc}")

    except Exception as exc:
        warnings.append(f"Could not get Lambda function {lambda_arn}: {exc}")

    return packages


def _packages_from_layer(
    lambda_client: Any,
    layer_arn: str,
    ecosystem: str,
) -> list[Package]:
    """Download and parse a Lambda layer to extract package metadata."""
    packages: list[Package] = []

    # Get the layer version (ARN includes version)
    response = lambda_client.get_layer_version_by_arn(Arn=layer_arn)
    download_url = response.get("Content", {}).get("Location", "")
    if not download_url:
        return packages

    # Download the layer zip
    from agent_bom.http_client import fetch_bytes

    layer_bytes = fetch_bytes(download_url, timeout=60)

    # Parse the zip for package metadata
    with zipfile.ZipFile(io.BytesIO(layer_bytes)) as zf:
        if ecosystem == "pypi":
            packages = _parse_python_packages_from_zip(zf)
        elif ecosystem == "npm":
            packages = _parse_node_packages_from_zip(zf)

    return packages


def _parse_python_packages_from_zip(zf: zipfile.ZipFile) -> list[Package]:
    """Extract Python package info from .dist-info/METADATA files in a zip."""
    packages: list[Package] = []
    seen: set[str] = set()

    for name in zf.namelist():
        if name.endswith(".dist-info/METADATA"):
            try:
                metadata_text = zf.read(name).decode("utf-8", errors="replace")
                parser = EmailParser()
                msg = parser.parsestr(metadata_text)
                pkg_name = msg.get("Name", "")
                pkg_version = msg.get("Version", "")
                if pkg_name and pkg_version and pkg_name.lower() not in seen:
                    seen.add(pkg_name.lower())
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="pypi",
                        )
                    )
            except Exception:
                continue

    return packages


def _parse_node_packages_from_zip(zf: zipfile.ZipFile) -> list[Package]:
    """Extract Node.js package info from node_modules/*/package.json in a zip."""
    packages: list[Package] = []
    seen: set[str] = set()

    for name in zf.namelist():
        parts = Path(name).parts
        if len(parts) >= 3 and parts[-1] == "package.json" and "node_modules" in parts:
            try:
                data = json.loads(zf.read(name))
                pkg_name = data.get("name", "")
                pkg_version = data.get("version", "")
                if pkg_name and pkg_version and pkg_name not in seen:
                    seen.add(pkg_name)
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="npm",
                        )
                    )
            except Exception:
                continue

    return packages


# ---------------------------------------------------------------------------
# ECS discovery
# ---------------------------------------------------------------------------


def _discover_ecs_images(session: Any, region: str) -> tuple[list[str], list[str]]:
    """Discover container image refs from running ECS tasks."""
    ecs = session.client("ecs", region_name=region)
    image_refs: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    try:
        cluster_arns = ecs.list_clusters().get("clusterArns", [])
    except Exception as exc:
        return [], [f"Could not list ECS clusters: {exc}"]

    for cluster_arn in cluster_arns:
        try:
            task_arns = ecs.list_tasks(cluster=cluster_arn, desiredStatus="RUNNING").get("taskArns", [])
            if not task_arns:
                continue

            # DescribeTasks accepts max 100 tasks per call
            for i in range(0, len(task_arns), 100):
                batch = task_arns[i : i + 100]
                tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=batch).get("tasks", [])
                for task in tasks:
                    for container in task.get("containers", []):
                        image = container.get("image", "")
                        if image and image not in seen:
                            seen.add(image)
                            image_refs.append(image)
        except Exception as exc:
            warnings.append(f"Could not list tasks in ECS cluster {cluster_arn}: {exc}")

    return image_refs, warnings


# ---------------------------------------------------------------------------
# SageMaker discovery
# ---------------------------------------------------------------------------


def _discover_sagemaker(session: Any, region: str) -> tuple[list[Agent], list[str]]:
    """Discover SageMaker endpoints and their container images."""
    sm = session.client("sagemaker", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        endpoints = sm.list_endpoints(StatusEquals="InService").get("Endpoints", [])
    except Exception as exc:
        return [], [f"Could not list SageMaker endpoints: {exc}"]

    for ep in endpoints:
        ep_name = ep["EndpointName"]
        try:
            ep_desc = sm.describe_endpoint(EndpointName=ep_name)
            config_name = ep_desc.get("EndpointConfigName", "")
            if not config_name:
                continue

            config_desc = sm.describe_endpoint_config(EndpointConfigName=config_name)
            for variant in config_desc.get("ProductionVariants", []):
                model_name = variant.get("ModelName", "")
                if not model_name:
                    continue

                model_desc = sm.describe_model(ModelName=model_name)
                container = model_desc.get("PrimaryContainer", {})
                image = container.get("Image", "")

                if image:
                    server = MCPServer(
                        name=f"sagemaker-model:{model_name}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                        env={"AWS_REGION": region},
                    )
                    agent = Agent(
                        name=f"sagemaker:{ep_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=ep_desc.get("EndpointArn", f"sagemaker://{ep_name}"),
                        source="aws-sagemaker",
                        mcp_servers=[server],
                    )
                    agents.append(agent)

        except Exception as exc:
            warnings.append(f"Could not describe SageMaker endpoint {ep_name}: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Lambda direct discovery
# ---------------------------------------------------------------------------

_AI_RUNTIMES = {
    "python3.9",
    "python3.10",
    "python3.11",
    "python3.12",
    "python3.13",
    "nodejs18.x",
    "nodejs20.x",
    "nodejs22.x",
}


def _discover_lambda_functions(
    session: Any,
    region: str,
    parent_warnings: list[str],
) -> tuple[list[Agent], list[str]]:
    """Discover standalone Lambda functions (not just Bedrock action group Lambdas).

    Filters by runtime to focus on AI-relevant functions (Python, Node.js).
    Reuses ``_extract_lambda_packages()`` for layer scanning.
    """
    lambda_client = session.client("lambda", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page.get("Functions", []):
            func_name = func.get("FunctionName", "unknown")
            func_arn = func.get("FunctionArn", "")
            runtime = func.get("Runtime", "")

            if runtime not in _AI_RUNTIMES:
                continue

            packages = _extract_lambda_packages(session, func_arn, region, parent_warnings)

            server = MCPServer(
                name=f"lambda:{func_name}",
                command="lambda",
                args=[func_arn],
                transport=TransportType.STREAMABLE_HTTP,
                env={"AWS_REGION": region},
                packages=packages,
            )

            agent = Agent(
                name=f"lambda:{func_name}",
                agent_type=AgentType.CUSTOM,
                config_path=func_arn,
                source="aws-lambda",
                version=runtime,
                mcp_servers=[server],
            )
            agents.append(agent)

    return agents, warnings


# ---------------------------------------------------------------------------
# EKS discovery
# ---------------------------------------------------------------------------


def _discover_eks_images(
    session: Any,
    region: str,
) -> tuple[list[Agent], list[str]]:
    """Discover EKS clusters and reuse k8s.discover_images() for pod scanning.

    Requires kubectl configured with access to the discovered clusters.
    """
    eks_client = session.client("eks", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from agent_bom.k8s import K8sDiscoveryError, discover_images
    except ImportError:
        warnings.append("k8s module not available for EKS discovery.")
        return agents, warnings

    try:
        cluster_names = eks_client.list_clusters().get("clusters", [])
    except Exception as exc:
        return [], [f"Could not list EKS clusters: {exc}"]

    for cluster_name in cluster_names:
        try:
            image_records = discover_images(all_namespaces=True, context=cluster_name)
            for image_ref, pod_name, container_name in image_records:
                server = MCPServer(
                    name=image_ref,
                    command="docker",
                    args=["run", image_ref],
                    transport=TransportType.STDIO,
                )
                agent = Agent(
                    name=f"eks:{cluster_name}/{pod_name}/{container_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"eks://{cluster_name}/{pod_name}",
                    source="aws-eks",
                    mcp_servers=[server],
                )
                agents.append(agent)

        except K8sDiscoveryError as exc:
            warnings.append(
                f"Could not discover images in EKS cluster '{cluster_name}': {exc}. "
                f"Ensure kubectl context is configured (aws eks update-kubeconfig --name {cluster_name})"
            )

    return agents, warnings


# ---------------------------------------------------------------------------
# Step Functions discovery
# ---------------------------------------------------------------------------


def _discover_step_functions(
    session: Any,
    region: str,
    parent_warnings: list[str],
) -> tuple[list[Agent], list[str]]:
    """Discover Step Functions state machines and extract referenced service ARNs.

    Parses the state machine definition JSON to find Task states with Lambda,
    SageMaker, and Bedrock resource ARNs.
    """
    sfn_client = session.client("stepfunctions", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    paginator = sfn_client.get_paginator("list_state_machines")
    for page in paginator.paginate():
        for sm in page.get("stateMachines", []):
            sm_arn = sm.get("stateMachineArn", "")
            sm_name = sm.get("name", "unknown")

            try:
                detail = sfn_client.describe_state_machine(stateMachineArn=sm_arn)
                definition_str = detail.get("definition", "{}")
                definition = json.loads(definition_str)
            except Exception as exc:
                warnings.append(f"Could not describe Step Function {sm_name}: {exc}")
                continue

            resource_arns = _extract_sfn_task_resources(definition)
            if not resource_arns:
                continue

            servers: list[MCPServer] = []
            tools: list[MCPTool] = []

            for arn in resource_arns:
                if ":lambda:" in arn:
                    packages = _extract_lambda_packages(session, arn, region, parent_warnings)
                    func_name = arn.split(":")[-1] if ":" in arn else arn
                    servers.append(
                        MCPServer(
                            name=f"sfn-lambda:{func_name}",
                            command="lambda",
                            args=[arn],
                            transport=TransportType.STREAMABLE_HTTP,
                            packages=packages,
                        )
                    )
                else:
                    service = arn.split(":")[2] if len(arn.split(":")) > 2 else "aws"
                    tools.append(
                        MCPTool(
                            name=f"{service}:{arn.split(':')[-1]}",
                            description=f"Step Functions task resource: {arn}",
                        )
                    )

            if not servers:
                servers = [
                    MCPServer(
                        name=f"sfn-orchestration:{sm_name}",
                        transport=TransportType.UNKNOWN,
                        tools=tools,
                    )
                ]

            agent = Agent(
                name=f"step-functions:{sm_name}",
                agent_type=AgentType.CUSTOM,
                config_path=sm_arn,
                source="aws-step-functions",
                mcp_servers=servers,
            )
            agents.append(agent)

    return agents, warnings


def _extract_sfn_task_resources(definition: dict) -> list[str]:
    """Recursively extract Task.Resource ARNs from a Step Functions definition."""
    resources: list[str] = []

    def _walk_states(states: dict) -> None:
        for _state_name, state_def in states.items():
            state_type = state_def.get("Type", "")

            if state_type == "Task":
                resource = state_def.get("Resource", "")
                if resource and resource.startswith("arn:"):
                    resources.append(resource)
                params = state_def.get("Parameters", {})
                fn_name = params.get("FunctionName", params.get("FunctionName.$", ""))
                if isinstance(fn_name, str) and fn_name.startswith("arn:"):
                    resources.append(fn_name)

            elif state_type == "Parallel":
                for branch in state_def.get("Branches", []):
                    _walk_states(branch.get("States", {}))

            elif state_type == "Map":
                iterator = state_def.get("Iterator", state_def.get("ItemProcessor", {}))
                _walk_states(iterator.get("States", {}))

    _walk_states(definition.get("States", {}))
    return list(set(resources))


# ---------------------------------------------------------------------------
# EC2 discovery
# ---------------------------------------------------------------------------


def _discover_ec2_instances(
    session: Any,
    region: str,
    tag_filter: dict[str, str],
) -> tuple[list[Agent], list[str]]:
    """Discover EC2 instances matching tag filters.

    Inventory-only: without SSH access we cannot extract packages,
    but we record the instance metadata for audit/compliance purposes.
    """
    ec2_client = session.client("ec2", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    if not tag_filter:
        warnings.append(
            "EC2 discovery requires --aws-ec2-tag KEY=VALUE to filter instances. Scanning all instances is not supported for safety."
        )
        return agents, warnings

    filters: list[dict[str, Any]] = []
    for key, value in tag_filter.items():
        filters.append({"Name": f"tag:{key}", "Values": [value]})
    filters.append({"Name": "instance-state-name", "Values": ["running"]})

    try:
        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=filters):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "unknown")
                    instance_type = instance.get("InstanceType", "")
                    ami_id = instance.get("ImageId", "")

                    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                    name = tags.get("Name", instance_id)

                    server = MCPServer(
                        name=f"ec2:{instance_id}",
                        transport=TransportType.UNKNOWN,
                        env={"INSTANCE_TYPE": instance_type, "AMI_ID": ami_id},
                    )

                    agent = Agent(
                        name=f"ec2:{name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"arn:aws:ec2:{region}::instance/{instance_id}",
                        source="aws-ec2",
                        version=f"{instance_type} ({ami_id})",
                        mcp_servers=[server],
                    )
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not describe EC2 instances: {exc}")

    return agents, warnings
