#!/usr/bin/env python3
"""Obtain a short-lived read token and run the deployment probe without printing it."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import urllib.request
from urllib.parse import quote, urlencode, urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("OAuth token endpoint redirects are not allowed")


def probe_environment(environ: dict[str, str]) -> dict[str, str]:
    env = dict(environ)
    names = ("ISSUER", "TOKEN_URL", "CLIENT_ID", "CLIENT_SECRET", "AUDIENCE")
    settings = {name: env.get("MCP_PROBE_OAUTH_" + name, "").strip() for name in names}
    if not any(settings.values()):
        env["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] = env.get("RAILWAY_MCP_BEARER_TOKEN", "")
        return env
    if not all(settings.values()):
        raise ValueError("Incomplete OAuth probe configuration")
    issuer, endpoint = (urlsplit(settings[k]) for k in ("ISSUER", "TOKEN_URL"))
    for value in (issuer, endpoint):
        if value.scheme != "https" or not value.hostname or value.username or value.password or value.query or value.fragment:
            raise ValueError("OAuth probe endpoints require HTTPS without embedded credentials")
    if issuer.netloc != endpoint.netloc:
        raise ValueError("OAuth token endpoint must use the configured issuer origin")
    credentials = ":".join(quote(settings[k], safe="") for k in ("CLIENT_ID", "CLIENT_SECRET"))
    request = urllib.request.Request(
        settings["TOKEN_URL"],
        data=urlencode({"grant_type": "client_credentials", "scope": "read", "resource": settings["AUDIENCE"]}).encode(),
        headers={
            "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:  # noqa: S310 — operator-pinned HTTPS origin, redirects disabled
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("OAuth token response exceeds size limit")
    result = json.loads(body)
    ttl = result.get("expires_in")
    token = result.get("access_token")
    if result.get("token_type", "").lower() != "bearer" or type(ttl) is not int or not 0 < ttl <= 3600:
        raise ValueError("OAuth probe requires a bearer token with a lifetime of at most one hour")
    if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise ValueError("Invalid OAuth access token")
    env["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] = token
    # The probe process needs the access token, never the client secret.
    for name in names:
        env.pop("MCP_PROBE_OAUTH_" + name, None)
    return env


def main() -> int:
    try:
        env = probe_environment(dict(os.environ))
    except Exception:  # noqa: BLE001 — fail closed without exposing credentials or issuer response
        print("Unable to obtain the configured deployment probe credential", file=sys.stderr)
        return 1
    arguments = sys.argv[1:]
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    return subprocess.run([sys.executable, "-m", "agent_bom.deployment_probe", *arguments], env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
