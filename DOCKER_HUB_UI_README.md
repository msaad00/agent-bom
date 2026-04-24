# agent-bom-ui

Dashboard image for `agent-bom`.

`agent-bom` is one product with two deployable images:

- `agentbom/agent-bom` runs the scanner, API, jobs, gateway, proxy, and other non-browser runtimes
- `agentbom/agent-bom-ui` runs the browser dashboard

This image is not a separate product and it is not meant to be the first thing a
pilot user reasons about. Use the packaged pilot or Helm chart so both images are
pulled for you.

## Run This First

Pilot on one workstation:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production in your own cluster from a checked-out repo:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

## Image Role

- `agentbom/agent-bom` = runtime image for scanner, API, jobs, gateway, proxy
- `agentbom/agent-bom-ui` = dashboard image for the same self-hosted control plane

## Control-Plane Contract

The UI consumes the API control-plane contract. Auth posture comes from
`/v1/auth/policy`, tenant quota state from `/v1/auth/quota`, scalable graph
agent selection from `/v1/graph/agents`, and fleet inventory from `/v1/fleet`.
The dashboard should display those API facts and role capabilities; it should
not create a separate role, tenant, gateway, or secret lifecycle model.

## Links

- GitHub: https://github.com/msaad00/agent-bom
- Docs: https://msaad00.github.io/agent-bom/
- Helm chart: `deploy/helm/agent-bom`
