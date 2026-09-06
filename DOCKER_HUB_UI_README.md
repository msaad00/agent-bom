# agent-bom-ui

Explore scan coverage, investigate exposures, and track remediation in the
self-hosted agent-bom control plane. The dashboard connects to the companion
`agentbom/agent-bom` API image; scan and evidence state stay in your deployment.
This companion image is not a separate product.

## Start on one workstation

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
docker compose -f docker-compose.pilot.yml ps
```

Open **http://localhost:3000** once both services are healthy. The pilot binds
to loopback, uses the local analyst role without login, and persists evidence
in the `agent-bom-pilot-data` Docker volume. It is for single-workstation
evaluation; use configured authentication for a shared deployment.

**First result:** open **New Scan** and select a public repository, or open
**Connections**, verify a read-only source grant, and run its first scan. A
scan creates the inventory and findings; starting the dashboard alone does not
collect an estate. Inspect coverage, open a finding, then follow its evidence
and remediation action.

Stop with `docker compose -f docker-compose.pilot.yml down`. The named data
volume remains available for the next run.

## Configure the runtime API

Set `AGENT_BOM_API_URL` on the UI server to the API's HTTP(S) origin, for
example `http://api:8422` inside a Compose network. Browser requests remain
same-origin through the UI proxy. `NEXT_PUBLIC_API_URL` is accepted as a legacy
fallback. See the [deployment guide](https://github.com/msaad00/agent-bom/blob/main/docs/DEPLOYMENT.md)
for authentication, proxy, and production settings.

For Kubernetes, check out the repository and configure the
[Helm chart](https://github.com/msaad00/agent-bom/tree/main/deploy/helm/agent-bom)
and the identity, database, and ingress settings for your environment.

[Product scenarios](https://github.com/msaad00/agent-bom/blob/main/docs/GALLERY.md) ·
[Documentation](https://msaad00.github.io/agent-bom/) ·
[API and scanner image](https://hub.docker.com/r/agentbom/agent-bom)

<details>
<summary>Control-Plane Contract</summary>

The API owns authentication (`/v1/auth/policy`), tenant quotas
(`/v1/auth/quota`), paginated graph agents (`/v1/graph/agents`), and fleet state
(`/v1/fleet`). The UI reflects those facts and role capabilities; it does not
create a separate role, tenant, gateway, or secret lifecycle.

</details>
