"""Shared test helpers for attested trusted-proxy auth."""

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


def proxy_headers(role: str = "viewer", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def enable_trusted_proxy_env() -> None:
    import os

    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    from agent_bom.api.server import configure_api

    configure_api(api_key=None)


def disable_trusted_proxy_env() -> None:
    import os

    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)
    from agent_bom.api.server import configure_api

    configure_api(api_key=None)
