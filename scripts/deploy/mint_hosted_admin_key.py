#!/usr/bin/env python3
"""Mint the first hosted POC admin API key.

The raw key is written once to a local 0600 file, never logged. The stored
record is written through the same API key store used by the API process, so
hosted deployments should run this inside the API container with
``AGENT_BOM_POSTGRES_URL`` configured.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bom.api.auth import Role, create_api_key, get_key_store

DEFAULT_RAW_KEY_FILE = Path("/tmp/agent-bom-customer0-admin.key")


@dataclass(frozen=True)
class MintedAdminKey:
    """One-time key material plus non-secret metadata for operator output."""

    raw_key: str
    metadata: dict[str, Any]


def mint_admin_key(
    *,
    tenant_id: str,
    name: str,
    expires_at: str | None = None,
    scopes: list[str] | None = None,
    allow_inmemory: bool = False,
) -> MintedAdminKey:
    """Create and persist one admin key for an invite-only hosted POC."""

    if not os.environ.get("AGENT_BOM_POSTGRES_URL") and not allow_inmemory:
        raise RuntimeError("AGENT_BOM_POSTGRES_URL must be set for hosted admin bootstrap; use --allow-inmemory only for local tests.")
    raw_key, record = create_api_key(
        name=name,
        role=Role.ADMIN,
        expires_at=expires_at,
        scopes=scopes or ["*"],
        tenant_id=tenant_id,
    )
    get_key_store().add(record)
    return MintedAdminKey(
        raw_key=raw_key,
        metadata={
            "key_id": record.key_id,
            "key_prefix": record.key_prefix,
            "name": record.name,
            "role": record.role.value,
            "tenant_id": record.tenant_id,
            "expires_at": record.expires_at,
            "scopes": record.scopes,
        },
    )


def write_raw_key_file(path: Path, raw_key: str, *, force: bool = False) -> Path:
    """Write the one-time raw API key to a private file without logging it."""

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"raw key file already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(raw_key)
        handle.write("\n")
    path.chmod(0o600)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint an initial hosted POC admin API key")
    parser.add_argument("--tenant-id", default="customer-0", help="tenant id for the invited POC account")
    parser.add_argument("--name", default="customer-0-admin", help="display name stored for the key")
    parser.add_argument("--expires-at", default=None, help="optional ISO-8601 expiration")
    parser.add_argument("--scope", action="append", dest="scopes", help="scope to add; defaults to '*'")
    parser.add_argument("--allow-inmemory", action="store_true", help="allow local in-memory bootstrap for tests only")
    parser.add_argument(
        "--raw-key-file",
        type=Path,
        default=DEFAULT_RAW_KEY_FILE,
        help="private 0600 file that receives the one-time raw API key",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite --raw-key-file if it already exists",
    )
    args = parser.parse_args(argv)

    try:
        minted = mint_admin_key(
            tenant_id=args.tenant_id,
            name=args.name,
            expires_at=args.expires_at,
            scopes=args.scopes,
            allow_inmemory=args.allow_inmemory,
        )
        raw_key_file = write_raw_key_file(args.raw_key_file, minted.raw_key, force=args.force)
        public_payload = {**minted.metadata, "raw_key_file": str(raw_key_file)}
    except Exception as exc:  # noqa: BLE001 - CLI entrypoint returns a clean failure
        if isinstance(exc, RuntimeError) and str(exc).startswith("raw key file already exists:"):
            print(f"failed to mint hosted admin key: {exc}", file=sys.stderr)
        else:
            print("failed to mint hosted admin key; check server logs and bootstrap configuration", file=sys.stderr)
        return 1
    print(json.dumps(public_payload, indent=2, sort_keys=True))
    print(f"raw API key written once to {raw_key_file} with mode 0600", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
