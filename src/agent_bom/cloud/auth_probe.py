"""Credential-presence probes for cloud providers — detect by *credentials*, not CLI.

The unified ``cloud`` command needs to know which providers it can actually scan.
Probing for a CLI binary on ``PATH`` (``shutil.which``) mis-detects both ways:

- **False positive** — AWS CloudShell and most CI images ship the ``aws`` CLI but
  carry no usable credentials, so a CLI-presence check says "AWS configured" and
  the scan then fails at the first API call.
- **False negative** — a hosted collector on EKS with IRSA / workload-identity
  (``AWS_WEB_IDENTITY_TOKEN_FILE``) has perfectly good credentials but no ``aws``
  CLI installed, so the cloud is skipped even though it is fully scannable.

This module checks the actual *credential sources* each SDK resolves — env vars,
shared config/credential files, well-known ADC paths, and (where cheap and
local) the SDK's own credential resolver — without making any network call.
Returning the *source* lets the UI explain exactly what was detected and why
(``creds via AWS_WEB_IDENTITY_TOKEN_FILE``), which is the difference between a
collector operator trusting the run and filing a bug.

Design contract:

- **No forced network.** Every probe here is local: env vars, file existence, and
  SDK *credential resolution* (which for env/profile/IRSA-token-file is local and
  never calls STS). A real auth confirmation (STS / whoami) is opt-in via
  :func:`verify_credentials`.
- **Never raises.** Detection runs inside collectors and CLI fan-out; a missing
  optional SDK, an unreadable file, or any SDK quirk degrades to "not detected"
  for that source, never an exception.
- **Guarded imports.** ``boto3`` / ``google.auth`` may be absent; their absence
  falls back to env + file checks so detection still works.
- **Deterministic.** Sources are checked in a fixed precedence order so the same
  environment always reports the same source string.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

# Last-resort CLI hint: when no credential source is found but the provider's CLI
# is installed, the caller may treat the provider as "maybe — attempt with
# guidance" rather than skip it outright. This is a hint only; it never counts as
# a positive credential detection.
PROVIDER_CLI: dict[str, str] = {
    "aws": "aws",
    "azure": "az",
    "gcp": "gcloud",
    "snowflake": "snow",
}

PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "snowflake")


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path))


def _first_env(*names: str) -> Optional[str]:
    """Return the first environment variable *name* that is set and non-empty."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return name
    return None


# ── AWS ──────────────────────────────────────────────────────────────────────


def _probe_aws() -> Optional[str]:
    """Detect AWS credentials locally. Returns a source string or ``None``.

    Precedence mirrors how an operator reads their own setup: explicit env keys
    and IRSA/container-role tokens first (most specific), then a named profile,
    then a resolved boto3 session, then the shared config/credential files.
    boto3 credential *resolution* for these sources is local — it reads env vars
    and token files and never calls STS — so it stays within the no-network
    contract.
    """
    # Static keys / container + IRSA role tokens — unambiguous, env-only.
    env = _first_env(
        "AWS_ACCESS_KEY_ID",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_ROLE_ARN",
    )
    if env:
        return f"env {env}"

    # boto3's own resolver picks up profiles, SSO cache, IMDS config, etc. This is
    # local resolution (no STS) — wrapped because boto3 may be absent and some
    # provider chains can raise on malformed config.
    try:
        import boto3  # type: ignore

        creds = boto3.Session().get_credentials()
        if creds is not None:
            method = getattr(creds, "method", None) or "boto3"
            return f"boto3 ({method})"
    except Exception:
        pass

    # Named profile selects a section in the shared credentials/config files.
    if os.environ.get("AWS_PROFILE"):
        return "env AWS_PROFILE"

    # Shared credential/config files (with honor for the override env vars).
    cred_file = _expand(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"))
    config_file = _expand(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config"))
    if cred_file.is_file():
        return f"shared credentials file ({cred_file})"
    if config_file.is_file():
        return f"shared config file ({config_file})"
    return None


# ── Azure ────────────────────────────────────────────────────────────────────


def _probe_azure() -> Optional[str]:
    """Detect Azure credentials locally. Returns a source string or ``None``.

    Service-principal env vars and workload-identity / managed-identity markers
    are checked first, then the azure CLI token cache directory. No network call
    is made: ``DefaultAzureCredential`` is *not* invoked here (its ``get_token``
    would hit the network); only its local source markers are inspected.
    """
    # Workload identity (federated token file) — the EKS/AKS collector case.
    if os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        return "env AZURE_FEDERATED_TOKEN_FILE (workload identity)"

    # Service principal — client id + (secret or cert) + tenant.
    if os.environ.get("AZURE_CLIENT_ID") and (os.environ.get("AZURE_CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH")):
        return "env AZURE_CLIENT_ID (service principal)"

    # Managed identity endpoints (App Service / Functions / IMDS override).
    msi = _first_env("MSI_ENDPOINT", "IDENTITY_ENDPOINT", "AZURE_POD_IDENTITY_AUTHORITY_HOST")
    if msi:
        return f"env {msi} (managed identity)"

    # A lone client/tenant id still signals an intended SP source for the UI.
    partial = _first_env("AZURE_CLIENT_ID", "AZURE_TENANT_ID")
    if partial:
        return f"env {partial}"

    # az CLI token cache directory.
    az_dir = _expand(os.environ.get("AZURE_CONFIG_DIR", "~/.azure"))
    if (az_dir / "msal_token_cache.json").is_file() or (az_dir / "azureProfile.json").is_file():
        return f"az CLI config ({az_dir})"
    return None


# ── GCP ──────────────────────────────────────────────────────────────────────


def _probe_gcp() -> Optional[str]:
    """Detect GCP credentials locally. Returns a source string or ``None``.

    ``GOOGLE_APPLICATION_CREDENTIALS`` and the well-known ADC file are checked
    directly; impersonation/metadata markers are honored; finally
    ``google.auth.default()`` is used as a resolver. ``google.auth.default`` only
    *resolves* a credential object (env/file/metadata-config) and does not fetch a
    token, so it stays local for the env/file cases.
    """
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if gac and _expand(gac).is_file():
        return "env GOOGLE_APPLICATION_CREDENTIALS"
    if gac:
        # Set but missing file — still an intended source; surface it honestly.
        return "env GOOGLE_APPLICATION_CREDENTIALS (file missing)"

    impersonate = _first_env("AGENT_BOM_GCP_IMPERSONATE_SA", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT")
    if impersonate:
        return f"env {impersonate} (impersonation)"

    # Well-known Application Default Credentials file.
    cloudsdk = os.environ.get("CLOUDSDK_CONFIG")
    adc = (
        _expand(cloudsdk) / "application_default_credentials.json"
        if cloudsdk
        else _expand("~/.config/gcloud/application_default_credentials.json")
    )
    if adc.is_file():
        return f"ADC file ({adc})"

    # Metadata server marker (GCE / GKE workload identity).
    meta = _first_env("GCE_METADATA_HOST", "GCE_METADATA_ROOT", "GCE_METADATA_IP")
    if meta:
        return f"env {meta} (metadata server)"

    # google.auth resolver as a last local resolution step.
    try:
        import google.auth  # type: ignore

        creds, _project = google.auth.default()
        if creds is not None:
            return "google.auth.default()"
    except Exception:
        pass
    return None


# ── Snowflake ────────────────────────────────────────────────────────────────


def _probe_snowflake() -> Optional[str]:
    """Detect Snowflake credentials locally. Returns a source string or ``None``.

    Requires an account plus a key-pair path or a user. Pure env inspection.
    """
    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        return None
    if os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH"):
        return "env SNOWFLAKE_ACCOUNT + SNOWFLAKE_PRIVATE_KEY_PATH (key-pair)"
    if os.environ.get("SNOWFLAKE_USER"):
        return "env SNOWFLAKE_ACCOUNT + SNOWFLAKE_USER"
    return None


_PROBES: dict[str, Callable[[], Optional[str]]] = {
    "aws": _probe_aws,
    "azure": _probe_azure,
    "gcp": _probe_gcp,
    "snowflake": _probe_snowflake,
}


def provider_has_credentials(provider: str) -> tuple[bool, str]:
    """Return ``(has_credentials, source)`` for *provider* — local checks only.

    Detection inspects credential *sources* (env vars, files, local SDK
    resolution) and never makes a network call. The returned ``source`` is a
    short human string the UI can surface (``env AWS_WEB_IDENTITY_TOKEN_FILE``).

    When no credential source is found, the provider's CLI presence is returned
    as a *last-resort hint* — ``(False, "cli present (no credentials resolved)")``
    — so the caller can decide whether to attempt-with-guidance instead of
    silently skipping. CLI presence never counts as a positive detection.

    Never raises: an unknown provider, a missing optional SDK, or any probe quirk
    degrades to ``(False, ...)``.
    """
    probe = _PROBES.get(provider)
    if probe is None:
        return False, "unknown provider"

    try:
        source = probe()
    except Exception:
        source = None

    if source:
        return True, source

    cli = PROVIDER_CLI.get(provider)
    if cli:
        import shutil

        if shutil.which(cli):
            return False, "cli present (no credentials resolved)"
    return False, "no credentials"


def verify_credentials(provider: str) -> tuple[bool, str]:
    """Opt-in network confirmation that *provider* credentials actually work.

    Unlike :func:`provider_has_credentials`, this performs a cheap authenticated
    identity call (STS ``GetCallerIdentity`` for AWS, token acquisition for
    Azure/GCP). Network-bound — call only when ``--verify`` is requested. Never
    raises; returns ``(False, reason)`` on any failure.
    """
    try:
        if provider == "aws":
            import boto3  # type: ignore

            ident = boto3.client("sts").get_caller_identity()
            return True, f"sts: {ident.get('Arn', ident.get('Account', 'ok'))}"
        if provider == "gcp":
            import google.auth  # type: ignore
            import google.auth.transport.requests  # type: ignore

            creds, project = google.auth.default()
            creds.refresh(google.auth.transport.requests.Request())
            return True, f"adc token ok (project={project})"
        if provider == "azure":
            from azure.identity import DefaultAzureCredential  # type: ignore

            token = DefaultAzureCredential().get_token("https://management.azure.com/.default")
            return (True, "aad token ok") if token else (False, "no token")
        if provider == "snowflake":
            # A real connection is the only confirmation; treat presence as best
            # effort here to avoid opening a session during detection.
            has, source = provider_has_credentials("snowflake")
            return has, source
    except Exception as exc:  # noqa: BLE001 — verification must never crash
        return False, f"verify failed: {type(exc).__name__}"
    return False, "unknown provider"
