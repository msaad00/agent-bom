"""Secret-free, bounded tenant markers for durable gateway audit recovery."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from agent_bom.runtime.audit_delivery import AuditSpilloverStore, canonical_runtime_state_path

_GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES = 4096


_GATEWAY_AUDIT_TENANT_ID_MAX_BYTES = 512


class _GatewayAuditTenantRegistry:
    """Secret-free durable discovery markers for tenant audit backlogs."""

    def __init__(self, state_dir: Path, *, source_id: str, audit_url: str) -> None:
        router_identity = f"{source_id}\0{audit_url}"
        router_digest = hashlib.sha256(router_identity.encode("utf-8")).hexdigest()[:20]
        self._root = canonical_runtime_state_path(state_dir) / "runtime-audit"
        self._prefix = f"gateway-router-{router_digest}-"

    @staticmethod
    def _normalize_tenant_id(tenant_id: str) -> str:
        normalized = tenant_id.strip()
        encoded = normalized.encode("utf-8")
        if not normalized or len(encoded) > _GATEWAY_AUDIT_TENANT_ID_MAX_BYTES or any(ord(character) < 32 for character in normalized):
            raise ValueError("gateway audit tenant id is invalid")
        return normalized

    def _marker_name(self, tenant_id: str) -> str:
        normalized = self._normalize_tenant_id(tenant_id)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]
        return f"{self._prefix}{digest}.tenant.json"

    def _parent_fd(self) -> int:
        return AuditSpilloverStore._safe_parent_fd(self._root / ".tenant-registry")

    def register(self, tenant_id: str) -> None:
        """Atomically persist one tenant identity without its credential."""

        normalized = self._normalize_tenant_id(tenant_id)
        marker_name = self._marker_name(normalized)
        content = json.dumps(
            {"schema_version": 1, "tenant_id": normalized},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(content) > _GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES:
            raise ValueError("gateway audit tenant marker is too large")
        parent_fd = self._parent_fd()
        temp_name = f".{marker_name}.tmp-{os.urandom(8).hex()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = -1
        try:
            try:
                existing = os.stat(marker_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                AuditSpilloverStore._validate_single_link_regular(existing)
            fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, marker_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def discover(self) -> list[str]:
        """Load and validate every marker for this control-plane route."""

        parent_fd = self._parent_fd()
        tenants: set[str] = set()
        read_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            read_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            read_flags |= os.O_CLOEXEC
        try:
            names = sorted(name for name in os.listdir(parent_fd) if name.startswith(self._prefix) and name.endswith(".tenant.json"))
            for name in names:
                fd = os.open(name, read_flags, dir_fd=parent_fd)
                try:
                    file_stat = os.fstat(fd)
                    AuditSpilloverStore._validate_single_link_regular(file_stat)
                    if file_stat.st_mode & 0o077:
                        raise ValueError("gateway audit tenant marker permissions must be owner-only")
                    if file_stat.st_size > _GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES:
                        raise ValueError("gateway audit tenant marker is too large")
                    with os.fdopen(fd, "rb") as handle:
                        fd = -1
                        raw = handle.read(_GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES + 1)
                finally:
                    if fd >= 0:
                        os.close(fd)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict) or payload.get("schema_version") != 1:
                    raise ValueError("gateway audit tenant marker schema is invalid")
                tenant_id = self._normalize_tenant_id(str(payload.get("tenant_id") or ""))
                if name != self._marker_name(tenant_id):
                    raise ValueError("gateway audit tenant marker identity is invalid")
                tenants.add(tenant_id)
        finally:
            os.close(parent_fd)
        return sorted(tenants)

    def unregister(self, tenant_id: str) -> None:
        """Remove a marker only after its durable backlog is empty."""

        marker_name = self._marker_name(tenant_id)
        parent_fd = self._parent_fd()
        try:
            try:
                existing = os.stat(marker_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            AuditSpilloverStore._validate_single_link_regular(existing)
            os.unlink(marker_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
