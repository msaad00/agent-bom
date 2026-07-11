# Self-Hosted BYOC Quickstart

Stand up agent-bom on **one machine you control**, turn on authentication, and
connect it **read-only** to **your own** cloud account (bring-your-own-cloud).
No Kubernetes, no hosted service, no cloud data leaving your account: the
control plane runs on your box and reaches *out* to AWS, Azure, GCP, or
Snowflake with a read-only grant.

```
   your box (control plane)                 your cloud account
   API + UI + Postgres  ───── read-only ────▶  AWS / Azure / GCP / Snowflake
   (you run this)                              (List*/Describe*/Get* only)
```

This is the smoothest single-box path. For a cluster install use
[Vanilla EKS Quickstart](eks-vanilla-quickstart.md); for an invite-only hosted
demo see [`docs/HOSTED_POC.md`](https://github.com/msaad00/agent-bom/blob/main/docs/HOSTED_POC.md).

> **Read the honest limitation first.** The published image today ships the
> Snowflake SDK but **not** the AWS/Azure/GCP SDKs. Snowflake works out of the
> box; AWS/Azure/GCP need one extra build step until
> [#3832](https://github.com/msaad00/agent-bom/issues/3832) lands. See
> [Which clouds work from the published image today](#which-clouds-work-from-the-published-image-today).

## 1. Prerequisites

- **Docker** with the Compose plugin (`docker compose version`).
- **A clone of the repo** (the compose files and secret tooling live in it):
  `git clone https://github.com/msaad00/agent-bom && cd agent-bom`.
- **Python 3** on the box — only to generate secret files and (optionally) the
  Fernet connection key. No project install required for the preflight script.
- **A cloud account** where you can create a **read-only** role (AWS
  `SecurityAudit`, Azure `Reader`, GCP `roles/viewer`) or a read-only Snowflake
  governance role. You never grant write access.
- ~2 vCPU / 4 GB free. agent-bom is CPU-only; it does no GPU inference.

## 2. Run the control plane (auth on)

Use `deploy/docker-compose.platform.yml` — the production-shaped single-host
profile. It mounts all secrets as **files** (never `.env`), binds API/UI to
`127.0.0.1` by default, keeps Postgres internal, and runs the API with an API
key required.

### 2a. Generate the secret files

Every secret is a file under `deploy/secrets/`. Generate them all with the
shipped preflight helper (stdlib-only, safe to run on a fresh box):

```bash
python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
```

This writes `postgres_password`, `postgres_app_password`, `api_key`,
`audit_hmac_key`, `browser_session_signing_key`, and a Fernet
`connections_key` into `deploy/secrets/` with tight permissions. (To write them
by hand instead, follow [`deploy/secrets/README.md`](https://github.com/msaad00/agent-bom/blob/main/deploy/secrets/README.md).)

The `*.example` files next to them are non-secret placeholders — compose points
at the real filenames so a missing secret fails closed rather than booting
insecure.

### 2b. Bring it up

```bash
docker compose -f deploy/docker-compose.platform.yml up -d
docker compose -f deploy/docker-compose.platform.yml ps
```

The API service reads `AGENT_BOM_API_KEY_FILE`, so **authentication is on**:
unauthenticated API calls are rejected. `AGENT_BOM_ALLOW_UNAUTHENTICATED_API`
stays unset.

> The platform profile's API service uses `image: agent-bom:latest` (a locally
> built image), while the UI uses the published `agentbom/agent-bom-ui` image.
> Build the API image once with `docker build -t agent-bom:latest .` before
> `up` — and see the [cloud-SDK note](#which-clouds-work-from-the-published-image-today)
> for the extras to add if you are scanning AWS/Azure/GCP.

### 2c. Verify `/health`

`/health` is the unauthenticated readiness probe:

```bash
curl -fsS http://127.0.0.1:8422/health        # -> healthy
```

Then open the dashboard at <http://127.0.0.1:3000>. Your admin API key is the
value in `deploy/secrets/api_key`; pass it as a Bearer token or `X-API-Key`
header for API/CLI calls:

```bash
curl -fsS http://127.0.0.1:8422/v1/findings \
  -H "X-API-Key: $(cat deploy/secrets/api_key)"
```

## 3. Connect your cloud read-only, then scan

The `agent-bom connect <provider>` command is a **guide**: it prints the exact
read-only grant options (CLI, CloudShell/console, or Terraform), the opt-in
inventory env var, and the scan command — and reports whether credentials are
already detectable. It creates nothing and does no network I/O until you opt
in. There are no `--role-arn` / `--external-id` flags; credentials are supplied
the standard way for each provider, and inventory is gated by an env var.

Below is the smoothest AWS path. Swap in another provider from the
[matrix](#4-per-provider-read-only-matrix).

### 3a. Mint a read-only role in your account (Terraform)

The [`connect-aws`](https://github.com/msaad00/agent-bom/tree/main/deploy/terraform/connect-aws)
module creates an IAM role with the AWS-managed `SecurityAudit` (+
`ViewOnlyAccess`) policy and an always-enforced `ExternalId` — no write
permission anywhere.

```bash
cd deploy/terraform/connect-aws
terraform init
# Trust the principal your box uses to call STS (your IAM user/role ARN):
terraform apply -var 'trusted_principal_arns=["arn:aws:iam::<your-account>:user/<you>"]'

terraform output role_arn            # role the scanner assumes
terraform output -raw external_id    # confused-deputy guard (sensitive)
```

Prefer clicks? Run `agent-bom connect aws` and follow the printed CloudShell /
console recipe (`scripts/provision/aws_readonly_policy.json`) instead.

### 3b. Point the box at that role and scan

Give the control plane credentials that can assume the role (an
`AWS_PROFILE`/role ARN or short-lived keys), opt in to inventory, then scan:

```bash
export AGENT_BOM_AWS_INVENTORY=1     # opt-in, default-off
export AWS_PROFILE=abom-readonly     # a profile that assumes the role_arn above
agent-bom scan --aws
```

To run the scan inside the running stack (so results land in the same store the
UI reads), exec into the API container and pass the cloud credentials through:

```bash
docker compose -f deploy/docker-compose.platform.yml exec \
  -e AGENT_BOM_AWS_INVENTORY=1 \
  -e AWS_PROFILE=abom-readonly \
  api agent-bom scan --aws
```

Findings, graph, and posture then appear in the dashboard.
**This requires the AWS SDK to be present in the image** — see the note below.

## 4. Per-provider read-only matrix

| Provider | Read-only grant | Opt-in env | Scan command |
|---|---|---|---|
| **AWS** | `SecurityAudit` (+ `ViewOnlyAccess`) role — `terraform -chdir=deploy/terraform/connect-aws apply`, or `scripts/provision/aws_readonly_policy.json` | `AGENT_BOM_AWS_INVENTORY=1` + `AWS_PROFILE`/`AWS_ROLE_ARN` | `agent-bom scan --aws` |
| **Azure** | `Reader`-role service principal — `deploy/terraform/connect-azure`, or `scripts/provision/azure_readonly_role.json` | `AGENT_BOM_AZURE_INVENTORY=1` + Azure CLI / SP creds | `agent-bom scan --azure` |
| **GCP** | `roles/viewer` service account — `deploy/terraform/connect-gcp`, or `scripts/provision/gcp_readonly_role.yaml` | `AGENT_BOM_GCP_INVENTORY=1` + `gcloud` / SA creds | `agent-bom scan --gcp` |
| **Snowflake** | Read-only governance role (warehouse `USAGE` + governance views, no DML/DDL) — `deploy/terraform/connect-snowflake`, or `scripts/provision/snowflake_readonly.sql` | `SNOWFLAKE_ACCOUNT` (+ `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY_PATH`) | `agent-bom cloud snowflake` |

Run `agent-bom connect aws|azure|gcp|snowflake` for the exact, copy-pasteable
grant for your access level.

## Which clouds work from the published image today

The published control-plane image is built with `.[api,snowflake,postgres]`
(see the repo `Dockerfile`). That means:

- ✅ **Snowflake works out of the box** — the `snowflake-connector-python` SDK
  ships in the image. Connect and scan Snowflake with no extra build step.
- ⚠️ **AWS / Azure / GCP need the cloud SDKs**, which are **not** in the
  published image yet. Until
  [#3832](https://github.com/msaad00/agent-bom/issues/3832) (cloud SDKs in the
  image) merges, a containerized `agent-bom scan --aws|--azure|--gcp` returns an
  **empty inventory** because `boto3` / the Azure / Google SDKs are absent.

**Workarounds until #3832 lands (pick one):**

1. **Build your own image with the extras** (the platform profile already
   expects a locally built `agent-bom:latest`, so this fits the normal flow).
   Add the cloud extras to the build, e.g. change the `Dockerfile` install to
   `.[api,aws,azure,gcp,snowflake,postgres]`, or bake a thin layer:

   ```dockerfile
   FROM agent-bom:latest
   RUN pip install --no-cache-dir 'agent-bom[aws,azure,gcp]'
   ```

   Rebuild, `docker compose ... up -d`, then scan inside the container as in
   [3b](#3b-point-the-box-at-that-role-and-scan).

2. **Run the collector on the host** with a local install:
   `pip install 'agent-bom[aws,azure,gcp]'`, then run `agent-bom scan --aws`
   from the host (with the read-only creds and `AGENT_BOM_AWS_INVENTORY=1`).

3. **Use the Snowflake path**, which needs no extra step today.

This limitation is about the *image contents only* — the read-only grant, the
`connect` flow, and the scan commands are identical once the SDK is present.

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| API returns `401`/`403` on `/v1/*` | Auth is on (as intended) and no key was sent | Send `X-API-Key: <deploy/secrets/api_key>` (or a Bearer token). `/health` needs no auth. |
| Stack won't start; compose complains about a secret file | A `deploy/secrets/*` file is missing — the stack fails closed | Re-run `python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose`; confirm files exist and are non-empty. |
| Scan runs but inventory is **empty** for AWS/Azure/GCP | Cloud SDK missing from the image (#3832), or read-only permissions/credentials not reachable | Use a build with the cloud extras (see [above](#which-clouds-work-from-the-published-image-today)); confirm the read-only role/grant is applied and creds are set. |
| Scan runs but inventory is empty even with the SDK | Inventory opt-in env var not set | `export AGENT_BOM_AWS_INVENTORY=1` (or `AGENT_BOM_AZURE_INVENTORY` / `AGENT_BOM_GCP_INVENTORY`, or `SNOWFLAKE_ACCOUNT`). It is default-off. |
| `AccessDenied` / `sts:ExternalId` mismatch on AWS | Scanner not configured with the generated External ID, or trust policy doesn't trust your principal | Read `terraform output -raw external_id` and configure the assuming profile; confirm `trusted_principal_arns` matches your box's IAM principal. |
| Secrets "not mounted" / API can't read a key | Ran the wrong compose file, or secret paths overridden | Use `deploy/docker-compose.platform.yml`; keep secrets at `deploy/secrets/*` (compose defaults there). Do not put secrets in `.env`. |
| `/health` never turns healthy | API image not built, or Postgres not ready | `docker build -t agent-bom:latest .`; check `docker compose ... logs api postgres`. |

## Related

- [Deploy anywhere](https://github.com/msaad00/agent-bom/blob/main/docs/DEPLOY_PLATFORM.md) — all three deployment tiers
- [Vanilla EKS Quickstart](eks-vanilla-quickstart.md) — cluster install
- [`connect-*` Terraform modules](https://github.com/msaad00/agent-bom/tree/main/deploy/terraform) — read-only cloud grants
- [Compose secrets directory](https://github.com/msaad00/agent-bom/blob/main/deploy/secrets/README.md) — file-based secret model
