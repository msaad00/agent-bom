# agent-bom Hugging Face Token Setup

Hugging Face uses access tokens for authentication.
Token types, scopes, and org-level restrictions are all managed at:
https://huggingface.co/settings/tokens

## Token Types (HF uses a fine-grained token model)

| Type | agent-bom needs? | Why |
|---|---|---|
| `read` scope | Yes — minimum required | List models, spaces, inference endpoints |
| `write` scope | Never | agent-bom is read-only |
| `inference` scope | No | Only needed to call model APIs |
| `manage` scope | Never | Admin operations |

## Create a Read-Only Token

1. Go to https://huggingface.co/settings/tokens
2. Click **New token**
3. Name: `agent-bom-scanner`
4. Type: **Fine-grained**
5. Repositories: **Read access to contents of all public gated repos**
6. Inference: **None**
7. Organizations: Select your org (if scanning org models/spaces)
8. Click **Create token**

Docs: https://huggingface.co/docs/hub/en/security-tokens

## Token Expiry and Rotation

- HF tokens do not expire by default — set a reminder to rotate every 90 days
- Revoke at: https://huggingface.co/settings/tokens → Delete
- For CI/CD: store as a GitHub/GitLab/CI secret, never in code

## Zero-Credential Path (public repos only)

If your models and spaces are public, no token is needed:

```bash
# Public org discovery — no token required
agent-bom scan --huggingface --hf-organization <ORG_NAME>
```

Token is only required for:
- Private models/spaces
- Gated models (Llama, Mistral, etc.)
- Inference endpoints (private)

## Usage

```bash
# With token (private/gated content)
export HF_TOKEN=hf_...
agent-bom scan --huggingface

# With org filter (limits scan to your org's assets)
export HF_TOKEN=hf_...
agent-bom scan --huggingface --hf-organization my-org

# Public models only (no token)
agent-bom scan --huggingface --hf-organization my-public-org
```

## What Gets Scanned

- Model cards → framework packages (transformers, torch, diffusers) → CVEs
- Spaces (Gradio/Streamlit) → dependency packages → CVEs
- Inference endpoints → runtime packages → CVEs
- Dataset cards → dependency metadata
