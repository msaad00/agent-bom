"""Shared endpoint connector contracts for API, CLI and storage."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from agent_bom.device_posture import DeviceSignal

FALCON_REGIONS = {
    "us1": "https://api.crowdstrike.com",
    "us2": "https://api.us-2.crowdstrike.com",
    "eu1": "https://api.eu-1.crowdstrike.com",
    "usgov1": "https://api.laggar.gcw.crowdstrike.com",
    "usgov2": "https://api.us-gov-2.crowdstrike.mil",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    provider: Literal["jamf", "crowdstrike"]
    account_id: str = Field(min_length=1, max_length=200)
    jamf_url: str = ""
    region: Literal["us1", "us2", "eu1", "usgov1", "usgov2"] = "us1"
    client_id: str = Field(min_length=1, max_length=200)
    page_size: int = Field(default=100, ge=1, le=100)
    freshness_hours: int = Field(default=24, ge=1, le=168)

    @model_validator(mode="after")
    def validate_scope(self) -> ConnectionSpec:
        if self.provider == "jamf":
            url = urlsplit(self.jamf_url)
            # Provider-controlled domains only: no caller-selected credential destinations.
            if (
                url.scheme != "https"
                or not url.hostname
                or not re.fullmatch(r"[a-z0-9-]+\.jamfcloud\.com", url.hostname)
                or url.netloc != url.hostname
                or url.path not in ("", "/")
                or url.query
                or url.fragment
            ):
                raise ValueError("Jamf requires an HTTPS instance origin under jamfcloud.com")
            self.jamf_url = f"https://{url.hostname}"
            if self.account_id != url.hostname:
                raise ValueError("Jamf account_id must equal the instance hostname")
        else:
            if self.jamf_url or not re.fullmatch(r"[a-fA-F0-9]{32}", self.account_id):
                raise ValueError("Falcon requires a 32-character customer CID, without its checksum suffix")
            self.account_id = self.account_id.lower()
        return self

    @property
    def origin(self) -> str:
        return self.jamf_url if self.provider == "jamf" else FALCON_REGIONS[self.region]


class ConnectionCreate(ConnectionSpec):
    client_secret: SecretStr = Field(min_length=1, max_length=4096)


class Connection(ConnectionSpec):
    id: str
    tenant_id: str
    created_at: str
    enabled: bool = True


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    restart: bool = False
    max_pages: int = Field(default=5, ge=1, le=20)


class SyncState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    connection_id: str
    tenant_id: str
    started_at: str
    updated_at: str
    status: Literal["collecting", "partial", "complete", "failed"] = "collecting"
    cursor: str = ""
    cursor_at: str = ""
    pages: int = 0
    device_count: int = 0
    expected_count: int | None = None
    gap: str = ""


def scoped_device_id(tenant: str, provider: str, account: str, vendor_id: str) -> str:
    digest = hashlib.sha256(json.dumps([tenant, provider, account, vendor_id], separators=(",", ":")).encode()).hexdigest()
    return f"endpoint-{digest}"


class ConnectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    client_secret: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class ConnectionStatus(BaseModel):
    connection: Connection
    sync: SyncState | None


class ConnectionList(BaseModel):
    connections: list[ConnectionStatus]


class DevicePage(BaseModel):
    schema_version: Literal["endpoint.inventory.v1"] = "endpoint.inventory.v1"
    sync: SyncState | None
    devices: list[DeviceSignal]
    recent_receipts: list[SyncState] = Field(default_factory=list)
    offset: int
    limit: int


class AgentBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=512)
    active: bool = True
