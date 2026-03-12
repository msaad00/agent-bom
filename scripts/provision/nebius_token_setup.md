# agent-bom Nebius AI Cloud Token Setup

Nebius AI Cloud uses IAM service accounts with API keys.
Authentication: Bearer token in `Authorization` header.
Docs: https://docs.nebius.com/iam/service-accounts/manage

## Permission Model

Nebius uses a role-based system with resource-level bindings:
- **Roles** are bound to service accounts at the folder or project level
- Minimum role for agent-bom: `viewer` on the target folder/project

## Create a Read-Only Service Account

### Via Nebius Console

1. Go to https://console.nebius.ai → IAM → Service Accounts
2. Click **Create service account**
3. Name: `agent-bom-scanner`
4. Role: **viewer** (read-only — list instances, endpoints, container services)
5. Scope: your project/folder (not account-wide unless needed)
6. Click **Create**

### Generate an API Key for the Service Account

1. Select the service account → **API Keys** → **Create API key**
2. Description: `agent-bom CI scanner`
3. Expiry: set the shortest viable expiry for your workflow
4. Copy the key — it is shown only once

Docs: https://docs.nebius.com/iam/service-accounts/access-keys

## Key Rotation

1. Create a new API key for the service account
2. Update `NEBIUS_API_KEY` env var / CI secret
3. Delete the old key from the console

## Usage

```bash
export NEBIUS_API_KEY=<api-key>
export NEBIUS_PROJECT_ID=<project-id>
agent-bom scan --nebius

# With explicit project
agent-bom scan --nebius --nebius-project-id <project-id>
```

## What Gets Scanned

- AI Studio model deployments → base images + framework packages → CVEs
- GPU instances (H100/A100) → instance type, image → CVEs
- Kubernetes GPU pods → resource requests, container images → CVEs
- Container services → images → CVEs
