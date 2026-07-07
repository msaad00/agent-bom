"""Agentless AWS EBS disk side-scan (CWPP) with guaranteed cleanup.

This is the **one deliberate, opt-in, non-read-only** capability in agent-bom.
Everything else in the product calls only ``List*/Describe*/Get*``. The side-scan
needs a separately-scoped *snapshot role* (distinct from the read-only scanner
role) so it can take an EBS snapshot, attach a temp volume to an in-account
collector, read the filesystem, and tear everything back down.

Trust model (non-negotiable):

- **Opt-in only.** OFF unless ``AGENT_BOM_SIDESCAN`` is truthy (see
  :func:`is_sidescan_enabled`). No snapshot is ever created implicitly.
- **In-account collector.** The temp volume is attached to a collector instance
  *inside the target account*. No disk image or block data leaves the account.
- **Metadata-only output.** Only the package SBOM, matched CVEs, and secret
  *type/location* (never secret values, never file contents) are returned.
- **Mandatory cleanup.** Snapshot → volume → mount are always torn down in a
  ``try/finally``, even if parsing raises or the process is interrupted. A
  best-effort orphan sweep deletes any ``agent-bom-sidescan``-tagged snapshots
  left behind by an earlier crash.

The actual OS-level mount runs on the collector and is abstracted behind a
:class:`MountController` so the lifecycle is fully mockable in tests with no real
AWS and no real ``mount`` syscall.

This module deliberately does **not** import boto3 at module load — boto3 is an
optional extra (``pip install 'agent-bom[aws]'``) and the import is deferred so a
plain install can import this module (and surface the graceful opt-in message)
without the dependency present.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol

from agent_bom.filesystem import scan_disk_path_native
from agent_bom.models import Package
from agent_bom.secret_scanner import SecretScanResult, scan_secrets
from agent_bom.security import sanitize_text

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)

# Tag applied to every snapshot/volume we create, so the orphan sweep can find
# and reap resources left behind by a crashed run.
SIDESCAN_TAG_KEY = "agent-bom-sidescan"
SIDESCAN_TAG_VALUE = "true"

# Environment flag that gates the entire capability. Default OFF.
SIDESCAN_ENV_VAR = "AGENT_BOM_SIDESCAN"


def is_sidescan_enabled() -> bool:
    """Return True only when the operator has explicitly opted in.

    The side-scan is the single non-read-only capability in agent-bom, so it is
    gated behind ``AGENT_BOM_SIDESCAN`` and is OFF by default.
    """
    raw = os.environ.get(SIDESCAN_ENV_VAR)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class SideScanDisabledError(CloudDiscoveryError):
    """Raised when a side-scan is attempted without the opt-in flag set."""


class SideScanConfigError(CloudDiscoveryError):
    """Raised when required side-scan configuration (collector, role) is missing."""


# ---------------------------------------------------------------------------
# Result model — metadata only. No file contents, no secret values.
# ---------------------------------------------------------------------------


@dataclass
class SideScanSecret:
    """A redacted secret finding from the side-scan.

    Records only the *type* and *location* of a secret — never the matched bytes.
    """

    secret_type: str
    file_path: str
    line_number: int
    severity: str
    category: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.secret_type,
            "file": self.file_path,
            "line": self.line_number,
            "severity": self.severity,
            "category": self.category,
        }


@dataclass
class SideScanDiskFinding:
    """Metadata-only workload disk finding from mounted side-scan content."""

    finding_type: str
    file_path: str
    severity: str
    category: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type,
            "file": self.file_path,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
        }


@dataclass
class SideScanResult:
    """Metadata-only result of an EBS side-scan for a single target volume.

    Carries the package SBOM (with CVEs attached to each :class:`Package`) and
    redacted secret findings. By construction it never holds raw file contents
    or secret values.
    """

    instance_id: Optional[str] = None
    volume_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    packages: list[Package] = field(default_factory=list)
    secrets: list[SideScanSecret] = field(default_factory=list)
    config_findings: list[SideScanDiskFinding] = field(default_factory=list)
    ioc_findings: list[SideScanDiskFinding] = field(default_factory=list)
    vulnerability_count: int = 0
    warnings: list[str] = field(default_factory=list)
    cleaned_up: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "volume_id": self.volume_id,
            "snapshot_id": self.snapshot_id,
            "package_count": len(self.packages),
            "vulnerability_count": self.vulnerability_count,
            "secret_count": len(self.secrets),
            "config_finding_count": len(self.config_findings),
            "ioc_finding_count": len(self.ioc_findings),
            "secrets": [s.to_dict() for s in self.secrets],
            "config_findings": [finding.to_dict() for finding in self.config_findings],
            "ioc_findings": [finding.to_dict() for finding in self.ioc_findings],
            "warnings": list(self.warnings),
            "cleaned_up": self.cleaned_up,
        }


# ---------------------------------------------------------------------------
# Mount boundary — abstracted so the real syscall runs only on the collector,
# and tests can substitute a fixture directory with no privileges.
# ---------------------------------------------------------------------------


class MountController(Protocol):
    """Boundary for the OS-level attach + mount that runs on the collector.

    Implementations attach the temp volume (created from the snapshot) to the
    in-account collector instance and mount it READ-ONLY, returning the mount
    point. ``unmount`` reverses it. Abstracting this keeps :class:`AwsEbsSideScanner`
    fully testable without root or a real block device.
    """

    def attach_and_mount(self, volume_id: str, device: str) -> Path:
        """Attach *volume_id* to the collector at *device*, mount read-only, return mount point."""
        ...

    def unmount(self, mount_point: Path) -> None:
        """Unmount the read-only mount at *mount_point* (best-effort)."""
        ...


class CollectorMountController:
    """Real mount controller for the in-account collector instance.

    Runs ``mount -o ro,nosuid,nodev,noexec`` against the device the temp volume
    was attached to. The actual ``ec2:AttachVolume`` call is performed by the
    scanner; this controller waits for the kernel to surface the device and then
    mounts it read-only. Used only on the collector host — never in tests.
    """

    def __init__(self, mount_base: Path | None = None) -> None:
        self._mount_base = mount_base or Path(tempfile.gettempdir())

    def attach_and_mount(self, volume_id: str, device: str) -> Path:
        mount_point = self._mount_base / f"agent-bom-sidescan-{uuid.uuid4().hex[:8]}"
        mount_point.mkdir(parents=True, exist_ok=True)
        # Read-only, and refuse setuid/device/exec semantics from untrusted disks.
        subprocess.run(
            ["mount", "-o", "ro,nosuid,nodev,noexec", device, str(mount_point)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        return mount_point

    def unmount(self, mount_point: Path) -> None:
        try:
            subprocess.run(["umount", str(mount_point)], check=True, capture_output=True, timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning("side-scan: umount %s failed (best-effort): %s", mount_point, sanitize_text(exc))
        try:
            mount_point.rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Scanner — orchestrates the snapshot lifecycle with guaranteed cleanup.
# ---------------------------------------------------------------------------


@dataclass
class _LifecycleState:
    """Tracks every AWS resource created so cleanup can reap exactly what we made."""

    snapshot_id: Optional[str] = None
    volume_id: Optional[str] = None
    attached_device: Optional[str] = None
    mount_point: Optional[Path] = None


class AwsEbsSideScanner:
    """Orchestrate the AWS EBS side-scan lifecycle for a single account/region.

    Lifecycle per target volume:

    1. **Snapshot** the target volume (``ec2:CreateSnapshot``), tagged
       ``agent-bom-sidescan``.
    2. **Create + attach** a temp volume from the snapshot to the in-account
       collector, then **mount** it read-only (via :class:`MountController`).
    3. **Parse** the mounted filesystem with the existing native parsers
       (:func:`scan_disk_path_native`) → SBOM, then run the existing secret
       scanner (values redacted).
    4. **Cleanup** in a ``finally``: unmount, detach + delete the temp volume,
       delete the snapshot. Always runs.

    All AWS calls go through a boto3 EC2 client; ``ec2_client`` may be injected
    for testing. The collector instance id and an availability zone are required
    so the temp volume can be created in the right AZ and attached to the right
    host.
    """

    def __init__(
        self,
        *,
        ec2_client: Any | None = None,
        collector_instance_id: str | None = None,
        availability_zone: str | None = None,
        mount_controller: MountController | None = None,
        region: str | None = None,
        device: str = "/dev/xvdf",
    ) -> None:
        if not is_sidescan_enabled():
            raise SideScanDisabledError(
                "Disk side-scan is opt-in and currently OFF. It is the only non-read-only "
                f"capability in agent-bom. To enable it, set {SIDESCAN_ENV_VAR}=1, apply the "
                "scoped snapshot role (deploy/terraform/connect-aws-sidescan), and provide an "
                "in-account collector instance."
            )

        self._region = region
        self._collector_instance_id = collector_instance_id
        self._availability_zone = availability_zone
        self._device = device
        self._mount_controller: MountController = mount_controller or CollectorMountController()
        self._ec2 = ec2_client if ec2_client is not None else self._build_ec2_client(region)

    @staticmethod
    def _build_ec2_client(region: str | None) -> Any:
        try:
            import boto3
        except ImportError as exc:
            raise CloudDiscoveryError("boto3 is required for the EBS side-scan. Install with: pip install 'agent-bom[aws]'") from exc
        return boto3.client("ec2", region_name=region) if region else boto3.client("ec2")

    # ── Enumeration (read-only describe) ──────────────────────────────────

    def enumerate_target_volumes(
        self,
        *,
        instance_id: str | None = None,
        volume_id: str | None = None,
    ) -> list[dict[str, str]]:
        """Resolve the set of EBS volumes to scan (read-only ``Describe*``).

        - A specific ``volume_id`` → that one volume.
        - An ``instance_id`` → all EBS volumes attached to that instance.
        - Neither → every in-account EBS volume.

        Returns a list of ``{"volume_id", "instance_id"}`` dicts.
        """
        if volume_id:
            paginate_kwargs: dict[str, object] = {"VolumeIds": [volume_id]}
        elif instance_id:
            paginate_kwargs = {"Filters": [{"Name": "attachment.instance-id", "Values": [instance_id]}]}
        else:
            paginate_kwargs = {}

        targets: list[dict[str, str]] = []
        paginator = self._ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(**paginate_kwargs):
            for vol in page.get("Volumes", []):
                vid = vol.get("VolumeId", "")
                if not vid:
                    continue
                attached_instance = ""
                for att in vol.get("Attachments", []):
                    attached_instance = att.get("InstanceId", "") or attached_instance
                targets.append({"volume_id": vid, "instance_id": attached_instance or (instance_id or "")})
        return targets

    # ── Full scan with guaranteed cleanup ─────────────────────────────────

    async def scan_volume(
        self,
        volume_id: str,
        *,
        instance_id: str | None = None,
        scan_secrets_enabled: bool = True,
    ) -> SideScanResult:
        """Run the full snapshot → mount → parse → cleanup lifecycle for one volume.

        Cleanup is guaranteed via ``try/finally`` — a parse failure or
        interruption still tears down the snapshot and temp volume. Returns a
        metadata-only :class:`SideScanResult`.
        """
        result = SideScanResult(instance_id=instance_id, volume_id=volume_id)
        state = _LifecycleState()
        try:
            state.snapshot_id = self._create_snapshot(volume_id)
            result.snapshot_id = state.snapshot_id
            self._wait_for_snapshot(state.snapshot_id)

            mount_point = self._provision_and_mount(state)

            packages = self._parse_packages(mount_point)
            result.packages = packages
            result.vulnerability_count = await self._scan_cves(packages)
            result.config_findings, result.ioc_findings = scan_workload_disk_findings(mount_point)

            if scan_secrets_enabled:
                result.secrets = self._scan_secrets_redacted(mount_point)
        finally:
            # MANDATORY: always reap what we created, even on failure / interrupt.
            cleanup_warnings = self._cleanup(state)
            result.warnings.extend(cleanup_warnings)
            result.cleaned_up = not cleanup_warnings
        return result

    # ── Lifecycle steps ───────────────────────────────────────────────────

    def _create_snapshot(self, volume_id: str) -> str:
        resp = self._ec2.create_snapshot(
            VolumeId=volume_id,
            Description="agent-bom agentless side-scan (metadata-only, auto-deleted)",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": SIDESCAN_TAG_KEY, "Value": SIDESCAN_TAG_VALUE}],
                }
            ],
        )
        snapshot_id = resp.get("SnapshotId", "")
        if not snapshot_id:
            raise CloudDiscoveryError(f"CreateSnapshot returned no SnapshotId for volume {volume_id}")
        logger.info("side-scan: created snapshot %s from volume %s", snapshot_id, volume_id)
        return snapshot_id

    def _wait_for_snapshot(self, snapshot_id: str) -> None:
        waiter = getattr(self._ec2, "get_waiter", None)
        if callable(waiter):
            try:
                self._ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot_id])
            except Exception as exc:  # noqa: BLE001 — waiter failure shouldn't abort; describe will catch it
                logger.debug("side-scan: snapshot waiter failed for %s: %s", snapshot_id, sanitize_text(exc))

    def _provision_and_mount(self, state: _LifecycleState) -> Path:
        if not self._collector_instance_id or not self._availability_zone:
            raise SideScanConfigError(
                "Side-scan requires an in-account collector instance id and availability zone "
                "(the temp volume is attached to the collector — no block data leaves the account)."
            )
        assert state.snapshot_id is not None
        vol_resp = self._ec2.create_volume(
            SnapshotId=state.snapshot_id,
            AvailabilityZone=self._availability_zone,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": SIDESCAN_TAG_KEY, "Value": SIDESCAN_TAG_VALUE}],
                }
            ],
        )
        state.volume_id = vol_resp.get("VolumeId", "")
        if not state.volume_id:
            raise CloudDiscoveryError("CreateVolume returned no VolumeId")
        self._wait_for_volume_available(state.volume_id)

        self._ec2.attach_volume(
            VolumeId=state.volume_id,
            InstanceId=self._collector_instance_id,
            Device=self._device,
        )
        state.attached_device = self._device
        logger.info(
            "side-scan: attached temp volume %s to collector %s at %s",
            state.volume_id,
            self._collector_instance_id,
            self._device,
        )

        mount_point = self._mount_controller.attach_and_mount(state.volume_id, self._device)
        state.mount_point = mount_point
        return mount_point

    def _wait_for_volume_available(self, volume_id: str) -> None:
        waiter = getattr(self._ec2, "get_waiter", None)
        if callable(waiter):
            try:
                self._ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id])
            except Exception as exc:  # noqa: BLE001
                logger.debug("side-scan: volume waiter failed for %s: %s", volume_id, sanitize_text(exc))

    # ── Parse (reuse existing native parsers + secret scanner) ────────────

    def _parse_packages(self, mount_point: Path) -> list[Package]:
        # Reuse the existing native disk parsers (dpkg/rpm/apk/python/node/lock).
        # Metadata only — these read package databases, never copy file contents out.
        return scan_disk_path_native(mount_point)

    async def _scan_cves(self, packages: list[Package]) -> int:
        if not packages:
            return 0
        from agent_bom.scanners import scan_packages

        return await scan_packages(packages)

    def _scan_secrets_redacted(self, mount_point: Path) -> list[SideScanSecret]:
        """Run the existing secret scanner and project to type/location only.

        The upstream :class:`SecretScanResult` already redacts matched bytes
        (``matched_preview`` is a fixed ``[*_REDACTED]`` label). We additionally
        drop even that preview field here so the side-scan output carries *only*
        the secret type and location — never any matched content.
        """
        try:
            scan_result: SecretScanResult = scan_secrets(mount_point)
        except Exception as exc:  # noqa: BLE001 — secret scan is best-effort enrichment
            logger.warning("side-scan: secret scan failed (continuing): %s", sanitize_text(exc))
            return []
        return [
            SideScanSecret(
                secret_type=f.secret_type,
                file_path=f.file_path,
                line_number=f.line_number,
                severity=f.severity,
                category=f.category,
            )
            for f in scan_result.findings
        ]

    # ── Cleanup (MANDATORY) ───────────────────────────────────────────────

    def _cleanup(self, state: _LifecycleState) -> list[str]:
        """Tear down mount → volume → snapshot. Best-effort; never raises.

        Returns a list of warning strings for any step that could not complete,
        so the caller can surface a non-clean teardown without aborting.
        """
        warnings: list[str] = []

        if state.mount_point is not None:
            try:
                self._mount_controller.unmount(state.mount_point)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"unmount failed: {exc}")

        if state.volume_id:
            if state.attached_device:
                try:
                    self._ec2.detach_volume(VolumeId=state.volume_id, Force=True)
                    waiter = getattr(self._ec2, "get_waiter", None)
                    if callable(waiter):
                        try:
                            self._ec2.get_waiter("volume_available").wait(VolumeIds=[state.volume_id])
                        except Exception:  # noqa: BLE001
                            pass
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"detach volume {state.volume_id} failed: {exc}")
            try:
                self._ec2.delete_volume(VolumeId=state.volume_id)
                logger.info("side-scan: deleted temp volume %s", state.volume_id)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"delete volume {state.volume_id} failed: {exc}")

        if state.snapshot_id:
            try:
                self._ec2.delete_snapshot(SnapshotId=state.snapshot_id)
                logger.info("side-scan: deleted snapshot %s", state.snapshot_id)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"delete snapshot {state.snapshot_id} failed: {exc}")

        return warnings

    # ── Orphan sweep (recover from an earlier crash) ──────────────────────

    def sweep_orphan_snapshots(self) -> list[str]:
        """Delete any ``agent-bom-sidescan``-tagged snapshots left by a crash.

        Best-effort recovery: even though every run cleans up in a ``finally``,
        a hard kill (OOM, SIGKILL) could strand a snapshot. This sweep is safe to
        call at the start of every run — it only touches resources we tagged.
        Returns the list of snapshot ids deleted.
        """
        deleted: list[str] = []
        try:
            resp = self._ec2.describe_snapshots(
                Filters=[{"Name": f"tag:{SIDESCAN_TAG_KEY}", "Values": [SIDESCAN_TAG_VALUE]}],
                OwnerIds=["self"],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("side-scan: orphan sweep describe failed: %s", sanitize_text(exc))
            return deleted

        for snap in resp.get("Snapshots", []):
            snap_id = snap.get("SnapshotId", "")
            if not snap_id:
                continue
            try:
                self._ec2.delete_snapshot(SnapshotId=snap_id)
                deleted.append(snap_id)
                logger.info("side-scan: orphan sweep deleted stranded snapshot %s", snap_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("side-scan: orphan sweep could not delete %s: %s", snap_id, sanitize_text(exc))
        return deleted


_DISK_SCAN_MAX_FILES = 500
_DISK_SCAN_MAX_BYTES_PER_FILE = 256 * 1024

_INTERESTING_RELATIVE_PATHS = (
    "etc/crontab",
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/ssh/sshd_config",
    "etc/systemd/system",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "root/.bashrc",
    "root/.profile",
)

_IOC_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"\b(xmrig|kinsing|kdevtmpfsi|masscan)\b", re.IGNORECASE),
        "known_malware_or_scanner_marker",
        "critical",
    ),
    (re.compile(r"(/dev/tcp/|nc\s+-e\b|bash\s+-i\b)", re.IGNORECASE), "reverse_shell_pattern", "high"),
    (
        re.compile(r"\b(curl|wget)\b[^\n|;&]*(\||;|&&)\s*(sh|bash)\b", re.IGNORECASE),
        "download_execute_startup",
        "high",
    ),
)

_CONFIG_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^\s*PermitRootLogin\s+yes\b", re.IGNORECASE | re.MULTILINE), "ssh_root_login_enabled", "medium"),
    (re.compile(r"^\s*PasswordAuthentication\s+yes\b", re.IGNORECASE | re.MULTILINE), "ssh_password_auth_enabled", "medium"),
)


def _iter_interesting_disk_files(mount_point: Path) -> list[Path]:
    files: list[Path] = []
    for relative in _INTERESTING_RELATIVE_PATHS:
        candidate = mount_point / relative
        try:
            if candidate.is_file():
                files.append(candidate)
            elif candidate.is_dir():
                files.extend(path for path in candidate.rglob("*") if path.is_file())
        except OSError:
            continue
        if len(files) >= _DISK_SCAN_MAX_FILES:
            break
    return files[:_DISK_SCAN_MAX_FILES]


def _relative_disk_path(mount_point: Path, path: Path) -> str:
    try:
        return str(path.relative_to(mount_point))
    except ValueError:
        return path.name


def _read_bounded_text(path: Path) -> str:
    try:
        if path.stat().st_size > _DISK_SCAN_MAX_BYTES_PER_FILE:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def scan_workload_disk_findings(mount_point: Path) -> tuple[list[SideScanDiskFinding], list[SideScanDiskFinding]]:
    """Scan mounted workload config/startup files for metadata-only risk signals.

    The output deliberately records finding type, path, severity, and a stable
    evidence label only. It never returns matched file contents.
    """

    config_findings: list[SideScanDiskFinding] = []
    ioc_findings: list[SideScanDiskFinding] = []
    seen: set[tuple[str, str]] = set()
    for path in _iter_interesting_disk_files(mount_point):
        text = _read_bounded_text(path)
        if not text:
            continue
        relative_path = _relative_disk_path(mount_point, path)
        for pattern, finding_type, severity in _IOC_PATTERNS:
            if not pattern.search(text):
                continue
            key = (relative_path, finding_type)
            if key in seen:
                continue
            seen.add(key)
            ioc_findings.append(
                SideScanDiskFinding(
                    finding_type=finding_type,
                    file_path=relative_path,
                    severity=severity,
                    category="ioc",
                    evidence=f"{finding_type}_matched",
                )
            )
        for pattern, finding_type, severity in _CONFIG_PATTERNS:
            if not pattern.search(text):
                continue
            key = (relative_path, finding_type)
            if key in seen:
                continue
            seen.add(key)
            config_findings.append(
                SideScanDiskFinding(
                    finding_type=finding_type,
                    file_path=relative_path,
                    severity=severity,
                    category="configuration",
                    evidence=f"{finding_type}_matched",
                )
            )
    return config_findings, ioc_findings


# ---------------------------------------------------------------------------
# Thin opt-in entry point — callable from the cloud scan path.
# ---------------------------------------------------------------------------


async def run_side_scan(
    *,
    instance_id: str | None = None,
    volume_id: str | None = None,
    collector_instance_id: str | None = None,
    availability_zone: str | None = None,
    region: str | None = None,
    ec2_client: Any | None = None,
    mount_controller: MountController | None = None,
    scan_secrets_enabled: bool = True,
    sweep_orphans: bool = True,
) -> list[SideScanResult]:
    """Opt-in agentless EBS side-scan entry point.

    Returns one :class:`SideScanResult` per target volume. Raises
    :class:`SideScanDisabledError` (a :class:`CloudDiscoveryError`) with an
    actionable message when ``AGENT_BOM_SIDESCAN`` is not set — callers should
    surface that message rather than crash.

    Guarantees: each volume's lifecycle cleans up in a ``finally``; when
    ``sweep_orphans`` is set, any snapshot stranded by an earlier crash is reaped
    first.
    """
    scanner = AwsEbsSideScanner(
        ec2_client=ec2_client,
        collector_instance_id=collector_instance_id,
        availability_zone=availability_zone,
        mount_controller=mount_controller,
        region=region,
    )

    if sweep_orphans:
        scanner.sweep_orphan_snapshots()

    targets = scanner.enumerate_target_volumes(instance_id=instance_id, volume_id=volume_id)
    results: list[SideScanResult] = []
    for target in targets:
        res = await scanner.scan_volume(
            target["volume_id"],
            instance_id=target.get("instance_id") or instance_id,
            scan_secrets_enabled=scan_secrets_enabled,
        )
        results.append(res)
    return results
