# Product Inspiration Notes

This file captures durable product inspiration for `agent-bom`. It is not a
spec and should not be treated as copied source material. Use it to keep the
product direction consistent as the graph, data model, docs, and demos evolve.

## AI System Component Stack

The product should model an AI system as a layered security stack, not as a
flat list of packages or tools.

Core layers:

- User and application layer: web UI, desktop app, mobile app, CLI, API client,
  IDE extension, automation job, and service account.
- API and gateway layer: API gateway, MCP gateway, proxy, reverse proxy,
  authorization boundary, API key, rate limit, headers, auth metadata, and
  tenant boundary.
- Orchestration layer: LangChain, LangGraph, CrewAI, AutoGen, custom agent
  runtime, workflow engine, planner, router, memory manager, and execution
  policy.
- RAG and data layer: embeddings, vector database, chunking strategy, retriever,
  document source, index, similarity threshold, prompt template, and data
  classification.
- Agent tool layer: MCP server, tool schema, function call, JSON-RPC method,
  command permission, filesystem scope, network scope, browser capability, and
  approval policy.
- Tool and MCP package layer: runtime package, transitive dependency, lockfile
  source, vulnerable package, malicious package signal, maintainer signal,
  install script, native extension, container layer, and package provenance.
- External integration layer: SaaS API, database connector, file system, cloud
  account, CI system, ticketing system, source repository, A2A endpoint, and
  business asset.
- Inference serving layer: local inference server, hosted model endpoint,
  Ollama, vLLM, TGI, model gateway, model router, adapter loader, and model
  cache.
- Model and weight layer: base model, fine tune, adapter, embedding model,
  model card, manifest, checksum, signature, risky weight format, lineage, and
  provenance.
- Infrastructure layer: host, VM, container, Kubernetes workload, GPU node,
  accelerator, chip family, bare-metal server, cloud region, subnet, IAM role,
  storage volume, secrets manager, and telemetry pipeline.
- Enumeration and evidence targets: HTTP header, API endpoint, MCP tool schema,
  model behavior, error message, package manifest, lockfile, runtime trace,
  gateway decision, proxy alert, and audit log entry.

## Layer Notes

At the top of the stack, users and applications interact through web
interfaces, desktop clients, mobile apps, CLIs, APIs, IDEs, service accounts,
and automation jobs. Those requests pass through API gateways, MCP gateways,
reverse proxies, and policy boundaries that handle authentication, rate
limiting, routing, tenancy, and enforcement. HTTP headers and gateway behavior
can reveal useful backend details such as proxy software, caching strategy,
upstream server identity, auth scheme, and routing topology.

The orchestration layer coordinates how requests move through the AI system.
Frameworks such as LangChain, LangGraph, CrewAI, AutoGen, and custom runtimes
build prompts, manage context windows, invoke tools, route tasks, and chain
multi-step reasoning. These frameworks have fingerprintable behaviors: error
messages, trace shapes, retry patterns, memory conventions, prompt templates,
tool-call envelopes, and framework-specific metadata.

In practice, orchestration code often embeds the components that diagrams draw
as separate boxes. RAG logic, tool definitions, inference client calls,
approval policies, memory, and routing are frequently implemented inside the
same agent runtime. The graph model should support both views: a clean product
layer for readability and a code-true dependency view for audit accuracy.

The middle tier contains the highest-value reachability surfaces. RAG pipelines
fetch context from vector databases, document stores, and indexes before model
generation. Even when RAG is implemented inside orchestration code, it has
distinct enumerable parameters: embedding model, vector database, index name,
chunking strategy, retriever settings, similarity threshold, prompt template,
source documents, and data classification. Agent tools expose capabilities
through MCP, JSON-RPC, function calling, shell execution, browser actions, file
access, network reachability, and permission boundaries. External integrations
connect agents to databases, SaaS APIs, cloud services, source repositories,
CI systems, file systems, and other agents.

The inference serving layer hosts or routes model execution. Examples include
local servers, hosted endpoints, Ollama, vLLM, TGI, model gateways, router
services, adapter loaders, and model caches. These surfaces expose API shapes,
streaming behavior, tokenization quirks, response formatting, model routing
metadata, and deployment fingerprints.

The underlying model layer represents the model, adapter, embedding model, or
fine tune that produces outputs. Model weights may be inaccessible at runtime,
but model identity and lineage can often be inferred from model cards,
manifests, checksums, signatures, deployment metadata, behavior, capability
boundaries, training-data artifacts, and response patterns.

The infrastructure layer sits underneath the runtime and is part of the real
blast radius. AI systems run on hosts, VMs, containers, Kubernetes workloads,
GPU nodes, accelerator hardware, bare-metal servers, cloud accounts, IAM
roles, subnets, storage volumes, secrets managers, artifact registries, and
telemetry pipelines. A graph that stops at the model or MCP server misses the
systems operators actually need to protect.

## Self-Describing Protocol Risk

MCP and A2A deserve special treatment because they are designed for capability
discovery. Unlike many opaque application layers, they advertise what they can
do. That makes them useful to operators and attackers.

MCP standardizes how AI agents discover and invoke tools. It commonly exposes
JSON-RPC methods and tool schemas that describe available functions, inputs,
return types, and sometimes permission assumptions. During reconnaissance,
these schemas reveal what actions an agent can perform, what data it can
access, and which package/runtime boundary backs the exposed tool.

A2A-style agent collaboration exposes a related risk shape: capability
discovery, task delegation, result aggregation, trust relationships, and
cross-boundary invocation. From a graph perspective, A2A endpoints should be
modeled as externally reachable agent relationships with explicit trust,
tenant, identity, evidence, and data-flow edges.

Product implication: self-describing protocols should not be treated as simple
integration labels. Their schemas, methods, auth boundaries, and runtime calls
are evidence sources. The graph should connect them to packages, tools,
credentials, agents, users, assets, traces, and policy decisions.

## Product Implications

The graph should make every layer above inspectable and connected. A finding is
only useful when the operator can see what it can reach.

Graph principles:

- Treat layers as first-class graph dimensions so users can filter by
  application, gateway, orchestration, RAG, tool, package, integration,
  inference, model, and infrastructure.
- Show packages inside tools and MCP servers, not only the server name. The
  useful path is often vulnerable package -> MCP server -> exposed tool ->
  agent/client -> credential -> asset.
- Model infrastructure underneath inference and runtime. GPU nodes, chips,
  bare-metal hosts, Kubernetes workloads, secrets stores, and cloud IAM are part
  of the blast radius when agents can invoke tools against real systems.
- Preserve runtime context separately from static inventory. Static scan data
  explains what could happen; gateway, proxy, and trace evidence explain what
  did happen.
- Keep evidence retention explicit. Durable evidence should stay safe to store;
  raw prompts, tool inputs and outputs, full paths, full URLs, command args, and
  response bodies belong in replay-only or short-TTL storage.
- Make effective reach loud. A vulnerable package behind read-only search is
  different from the same package behind `run_shell`, visible credential env
  names, broad network egress, and a production agent.
- Use layer-aware legends and relationship labels so dense graphs stay readable:
  "runs on", "loads package", "exposes tool", "called by", "can reach", "uses
  credential", "queries index", "serves model", "backs asset", "logged by",
  "blocked by", and "observed in trace".
- Support attack-path views that collapse noise by default and expand only the
  relevant neighborhood around the selected finding, asset, agent, MCP server,
  or credential.

## Product Positioning

Useful framing:

`agent-bom` maps the AI system component stack and turns it into an auditable
security graph: packages, MCP servers, agents, tools, credentials, runtime
evidence, models, and infrastructure connected by reachability.

The durable promise is not "another scanner." The product should answer:

- What do we have?
- What package, tool, model, credential, or infrastructure layer is risky?
- Which agent or user can trigger it?
- Which asset can it reach?
- Was it observed at runtime?
- What evidence can we safely retain?
- What should be blocked, fixed, isolated, or monitored first?
