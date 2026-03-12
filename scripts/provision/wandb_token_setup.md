# agent-bom Weights & Biases (W&B) Token Setup

W&B uses API keys for authentication. Permissions are governed by:
- **Role** at the entity/team level (Viewer, Member, Admin)
- **Project-level visibility** (public, private, restricted)
- **Team-level access controls**

Docs: https://docs.wandb.ai/guides/app/settings-page/api-keys

## Minimum Role: Viewer

Create a dedicated **service account** or use a **Viewer-role user** — never use
an Admin API key for scanning.

### Option A: Team Service Account (recommended for CI/CD)

1. Go to your W&B team settings: https://wandb.ai/<TEAM>/settings
2. Under **Service Accounts**, click **New service account**
3. Name: `agent-bom-scanner`
4. Role: **Viewer** (read-only — cannot create/delete runs or artifacts)
5. Copy the generated API key

Docs: https://docs.wandb.ai/guides/technical-faq/general#service-accounts

### Option B: Personal API Key (Viewer role user)

1. Go to https://wandb.ai/settings
2. Under **Danger Zone → API keys**, copy your key
3. Ensure your account has **Viewer** role in the target team/entity

## Token Rotation

W&B API keys do not expire. Rotate manually:
1. Generate a new key at https://wandb.ai/settings
2. Update the env var / CI secret
3. Revoke the old key

## Usage

```bash
export WANDB_API_KEY=<viewer-api-key>
export WANDB_ENTITY=<team-or-username>
agent-bom scan --wandb

# Scan a specific project only
agent-bom scan --wandb --wandb-entity my-team --wandb-project my-model
```

## What Gets Scanned

- Training run metadata → logged packages (requirements.txt, conda.yaml) → CVEs
- Model artifacts → framework + version → CVEs
- W&B Model Registry entries → dependency metadata
