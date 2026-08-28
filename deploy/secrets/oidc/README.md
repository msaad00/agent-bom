# OIDC client secret mount

For a confidential OIDC client, create `client_secret` in this directory. The
Compose control-plane profiles mount this directory read-only at
`/run/agent-bom/oidc`; `deploy/secrets/oidc.env` contains only that runtime path.

Do not commit the secret. This directory's `.gitignore` excludes it.
