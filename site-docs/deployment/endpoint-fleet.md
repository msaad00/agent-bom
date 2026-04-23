# Endpoint Fleet

Use this path when `fleet` means employee laptops and workstations running
local agent clients and MCP configs:

- Cursor
- Claude Desktop / Claude Code
- VS Code / Copilot / Continue.dev
- Windsurf
- Cline / Roo / Zed
- Cortex Code
- other local MCP-capable developer tooling

This is different from:

- `runtime fleet`: EKS workloads and server-side MCP deployments
- `cloud / platform inventory`: AWS, Snowflake, IaC, registries, containers

If you are deciding whether this is the right entrypoint versus `proxy` or
`gateway`, start with [When To Use Proxy vs Gateway vs
Fleet](proxy-vs-gateway-vs-fleet.md).

## What ships today

The endpoint-fleet path is real, but it is an opt-in scan + push model:

1. the laptop runs `agent-bom agents`
2. discovery and live MCP introspection happen locally
3. the result is sanitized and pushed to the control plane with `--push-url`
4. the control plane surfaces it in `/fleet`, `/agents`, `/mesh`, `/security-graph`,
   `/gateway`, and `/findings`

The endpoint command is:

```bash
agent-bom agents \
  --preset enterprise \
  --introspect \
  --push-url https://agent-bom.internal.example.com/v1/fleet/sync \
  --push-api-key "$AGENT_BOM_PUSH_API_KEY"
```

That gives you:

- endpoint MCP config discovery
- live MCP read-only introspection
- sanitized fleet sync to the self-hosted control plane
- the same fleet/mesh/gateway review path as cluster-discovered MCPs

Inventory confidence on this path:

- MCP client presence, config paths, transports, command or URL targets, declared tools, auth mode, and credential-backed environment references are the strongest endpoint-fleet signals today
- source-code-derived agent and tool extraction can still miss indirect or runtime-only registrations in some frameworks, so treat those as strong heuristic inventory rather than a claim of perfect dynamic coverage
- if a rollout decision depends on one framework family, validate that family with a focused fixture or pilot before claiming full discovery coverage

Important boundary:

- this is not a managed endpoint agent
- there is no MDM or quarantine control channel today
- the pilot model is explicit local execution on a schedule you control

## Managed rollout-ready bundle contract

`agent-bom proxy-bootstrap` now emits more than install scripts. The bundle also
ships:

- `endpoint-enrollment.json` — machine-readable rollout metadata for IT
- `endpoint-onboarding-summary.json` — operator-facing bundle summary
- optional stable `source_id` wiring via `AGENT_BOM_PUSH_SOURCE_ID`
- optional enrolled endpoint metadata wiring via:
  - `AGENT_BOM_PUSH_ENROLLMENT_NAME`
  - `AGENT_BOM_PUSH_OWNER`
  - `AGENT_BOM_PUSH_ENVIRONMENT`
  - `AGENT_BOM_PUSH_TAGS`
  - `AGENT_BOM_PUSH_MDM_PROVIDER`

That means Jamf, Intune, or Kandji rollout can keep one explicit endpoint
identity contract without pretending `agent-bom` is already a bidirectional
managed agent.

Example:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./bundle \
  --control-plane-url https://agent-bom.internal.example.com \
  --push-url https://agent-bom.internal.example.com/v1/fleet/sync \
  --push-api-key "$AGENT_BOM_PUSH_API_KEY" \
  --source-id device-acme-001 \
  --enrollment-name corp-laptop-rollout \
  --owner platform-security \
  --environment production \
  --tag developer-endpoint \
  --tag mdm \
  --mdm-provider jamf
```

## Endpoint service templates

Shipped templates:

- [agent-bom-fleet-sync.sh](https://github.com/msaad00/agent-bom/blob/main/deploy/endpoints/agent-bom-fleet-sync.sh)
- [agent-bom-fleet-sync.service](https://github.com/msaad00/agent-bom/blob/main/deploy/endpoints/agent-bom-fleet-sync.service)
- [agent-bom-fleet-sync.timer](https://github.com/msaad00/agent-bom/blob/main/deploy/endpoints/agent-bom-fleet-sync.timer)
- [com.agentbom.fleet-sync.plist](https://github.com/msaad00/agent-bom/blob/main/deploy/endpoints/com.agentbom.fleet-sync.plist)

The wrapper script expects:

- `AGENT_BOM_PUSH_URL`
- optionally `AGENT_BOM_PUSH_API_KEY`
- optionally the rollout metadata env vars listed above

## Linux systemd example

1. put the wrapper script at `~/.local/share/agent-bom/agent-bom-fleet-sync.sh`
2. make it executable
3. create `~/.config/agent-bom/fleet-sync.env`

Example env file:

```bash
AGENT_BOM_PUSH_URL=https://agent-bom.internal.example.com/v1/fleet/sync
AGENT_BOM_PUSH_API_KEY=replace-me
AGENT_BOM_PUSH_SOURCE_ID=device-acme-001
AGENT_BOM_PUSH_ENROLLMENT_NAME=corp-laptop-rollout
AGENT_BOM_PUSH_OWNER=platform-security
AGENT_BOM_PUSH_ENVIRONMENT=production
AGENT_BOM_PUSH_TAGS=developer-endpoint,mdm
AGENT_BOM_PUSH_MDM_PROVIDER=jamf
```

4. install the unit files:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/endpoints/agent-bom-fleet-sync.service ~/.config/systemd/user/
cp deploy/endpoints/agent-bom-fleet-sync.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now agent-bom-fleet-sync.timer
```

## macOS launchd example

1. put the wrapper script at `~/.local/share/agent-bom/agent-bom-fleet-sync.sh`
2. update the environment values in the plist
3. load it:

```bash
mkdir -p ~/Library/LaunchAgents
cp deploy/endpoints/com.agentbom.fleet-sync.plist ~/Library/LaunchAgents/
launchctl unload ~/Library/LaunchAgents/com.agentbom.fleet-sync.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.agentbom.fleet-sync.plist
```

## Proxy enforcement on endpoints

Endpoint enforcement is separate from endpoint sync.

For laptops, the proxy runs locally as a stdio wrapper around the editor's MCP
command:

```bash
agent-bom proxy \
  --control-plane-url https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_API_TOKEN" \
  --detect-credentials \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem ~/workspace
```

That path now supports:

- control-plane policy pull
- control-plane audit push
- local inline MCP enforcement

For OCR rollout on screenshot-heavy tools, see [Visual Leak
Detection](visual-leak-detection.md).

## How this fits with the EKS pilot

Use both when you want one pilot across laptops and infra:

- `endpoint fleet`: employee laptops push local discovery into the control plane
- `runtime fleet`: the EKS pilot discovers cluster-side MCP workloads and uses
  selected proxy sidecars for server-side enforcement

The control plane stays the same. Only the discovery and enforcement path differs.
