# demo-deploy-oidc

Mints the **keyless OIDC role** the `demo-redeploy` GitHub Actions workflow
(`.github/workflows/demo-redeploy.yml`) assumes to redeploy the public hosted
demo VM over AWS SSM Run Command. No long-lived AWS access keys, no stored SSH
keys.

Because the repo is **public**, this module is written so that neither a fork
nor a pull-request contributor can assume the role:

- The trust policy pins the GitHub OIDC `sub` to **exactly**

  ```
  repo:<github_repo>:environment:demo
  ```

  (`StringEquals`, no `:*` wildcard) and `aud` = `sts.amazonaws.com`. Only a
  workflow run executing in this repo's protected `demo` environment presents
  that subject. Fork/PR runs get a different `sub` and STS rejects them.
- The role's permissions are least-privilege: it may `ssm:SendCommand` the
  `AWS-RunShellScript` document to **one specific instance ARN** and read
  command status with `ssm:GetCommandInvocation`. No `ec2:*`, no broad `ssm:*`.

## What it creates

- `aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com`
  (guarded by `create_oidc_provider`; set it to `false` and the module looks up
  the existing provider instead — AWS allows only one per URL per account).
- `aws_iam_role` `demo_deploy` with the scoped web-identity trust policy above.
- An inline policy with just the two SSM actions, `SendCommand` scoped to the
  shell document + the demo instance ARN.

## One-time apply

```bash
cd deploy/terraform/demo-deploy-oidc

terraform init

terraform apply \
  -var 'github_repo=msaad00/agent-bom' \
  -var 'demo_instance_id=i-0123456789abcdef0' \
  -var 'aws_region=us-east-1'
# If the account already has the GitHub OIDC provider:
#   -var 'create_oidc_provider=false'

terraform output -raw role_arn
```

## Wire it up

1. **Repo secret** — paste `role_arn` into the repo Actions secret
   `DEMO_DEPLOY_ROLE_ARN`.
2. **Repo vars** — set `DEMO_INSTANCE_ID`, `AWS_REGION`, and (optionally)
   `DEMO_DEPLOY_DIR`. See `docs/HOSTED_POC.md` → "Demo redeploy".
3. **Protected environment** — in the repo, create an Actions **Environment**
   named `demo` and add **yourself as a required reviewer**. Optionally restrict
   its deployment branches/tags to the default branch and `v*.*.*` tags. This
   makes every `release` / `workflow_dispatch` run **pause for your approval**
   before any AWS call, and the environment name is what the trust policy above
   is scoped to — the two defenses reinforce each other.

Once configured, a published release (or a manual dispatch) queues a redeploy
that waits for your approval, then runs `git pull` → `docker compose up -d
--build` → fail-closed preflight → smoke on the VM, failing the job if the demo
is unhealthy.

## Scope note

The trust policy is scoped to this repo's `demo` environment, so **no fork or
pull request can assume the role**. Rotate nothing here to revoke access —
delete the `demo` environment or `terraform destroy` this module and the role is
gone.
