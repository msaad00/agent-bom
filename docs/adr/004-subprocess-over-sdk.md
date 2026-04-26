# ADR-004: Subprocess CLI over vendor SDKs for infrastructure discovery

## Status

Accepted

## Context

agent-bom discovers GPU containers (Docker), Kubernetes GPU nodes, cloud resources,
and other infrastructure. Two approaches for interacting with these systems:

1. **Vendor SDKs** — `docker` Python SDK, `kubernetes` client library, `boto3`, etc.
   Type-safe, well-documented, but each adds a dependency (often heavy)
2. **Subprocess CLI** — shell out to `docker`, `kubectl`, `aws`, `gcloud` CLI tools
   that are already installed in target environments

## Decision

Use **subprocess + JSON output** (`docker inspect --format json`, `kubectl get -o json`)
for all infrastructure discovery. No vendor SDK dependencies.

This follows the same pattern used by external container scanners (subprocess to container runtimes)
and is consistent across all discovery modules:

- `gpu_infra.py` — `docker ps`, `docker inspect`, `kubectl get nodes`
- `discovery/__init__.py` — reads config files directly (no SDK)
- `cloud/coreweave.py`, `cloud/aws.py`, etc. — CLI tools or REST APIs

## Consequences

### Positive

- Zero additional dependencies — keeps `pip install agent-bom` lightweight
- Works in any environment where the CLI tools are already installed
- JSON output is stable across CLI versions (more stable than SDK APIs)
- No authentication/credential management in our code — CLIs handle their own auth
- Consistent pattern across all discovery modules

### Negative

- Subprocess calls are harder to mock in tests (requires MagicMock on `subprocess.run`)
- No type safety on CLI output — we parse raw JSON
- Error messages from CLI tools are less structured than SDK exceptions
- Container ID hex validation needed as defense-in-depth against injection
