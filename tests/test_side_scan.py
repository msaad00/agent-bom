"""Tests for the agentless AWS EBS disk side-scan (CWPP).

No real AWS, no real mount/umount — boto3 is replaced by a fake EC2 client that
records every call, and the mount boundary is replaced by a controller that
hands back a fixture directory. The tests assert:

- full lifecycle (snapshot → volume → attach → mount → parse → cleanup)
- cleanup runs even when parsing raises (the load-bearing guarantee)
- orphan-snapshot sweep by tag
- metadata-only output (no file contents, no secret values)
- opt-in gating (OFF by default; clear error when disabled)
- missing collector config → actionable error, no crash, still cleans up
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cloud.side_scan import (
    SIDESCAN_TAG_KEY,
    SIDESCAN_TAG_VALUE,
    AwsEbsSideScanner,
    SideScanConfigError,
    SideScanDisabledError,
    is_sidescan_enabled,
    run_side_scan,
)

# ── Fakes ─────────────────────────────────────────────────────────────────────


class FakeEc2Client:
    """Records every EC2 call so tests can assert the full lifecycle ran."""

    def __init__(self, *, volumes: list[dict] | None = None, orphan_snapshots: list[dict] | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._volumes = volumes if volumes is not None else [{"VolumeId": "vol-target", "Attachments": [{"InstanceId": "i-target"}]}]
        self._orphan_snapshots = orphan_snapshots or []
        self._snap_counter = 0
        self._vol_counter = 0

    def _record(self, name: str, **kwargs: object) -> None:
        self.calls.append((name, dict(kwargs)))

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]

    # read-only describe
    def describe_volumes(self, **kwargs: object) -> dict:
        self._record("describe_volumes", **kwargs)
        return {"Volumes": self._volumes}

    def describe_snapshots(self, **kwargs: object) -> dict:
        self._record("describe_snapshots", **kwargs)
        return {"Snapshots": self._orphan_snapshots}

    # snapshot lifecycle
    def create_snapshot(self, **kwargs: object) -> dict:
        self._record("create_snapshot", **kwargs)
        self._snap_counter += 1
        return {"SnapshotId": f"snap-{self._snap_counter}"}

    def delete_snapshot(self, **kwargs: object) -> dict:
        self._record("delete_snapshot", **kwargs)
        return {}

    # volume lifecycle
    def create_volume(self, **kwargs: object) -> dict:
        self._record("create_volume", **kwargs)
        self._vol_counter += 1
        return {"VolumeId": f"vol-temp-{self._vol_counter}"}

    def attach_volume(self, **kwargs: object) -> dict:
        self._record("attach_volume", **kwargs)
        return {}

    def detach_volume(self, **kwargs: object) -> dict:
        self._record("detach_volume", **kwargs)
        return {}

    def delete_volume(self, **kwargs: object) -> dict:
        self._record("delete_volume", **kwargs)
        return {}

    # waiters are optional; omit get_waiter so the scanner skips them


class FakeMountController:
    """Mount boundary replacement — returns a fixture dir, records unmounts."""

    def __init__(self, mount_dir: Path) -> None:
        self._mount_dir = mount_dir
        self.attach_calls: list[tuple[str, str]] = []
        self.unmount_calls: list[Path] = []

    def attach_and_mount(self, volume_id: str, device: str) -> Path:
        self.attach_calls.append((volume_id, device))
        return self._mount_dir

    def unmount(self, mount_point: Path) -> None:
        self.unmount_calls.append(mount_point)


@pytest.fixture()
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")


@pytest.fixture()
def debian_rootfs(tmp_path: Path) -> Path:
    """A minimal mounted-snapshot fixture: dpkg status + a planted secret file."""
    root = tmp_path / "mnt"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text('ID=debian\nVERSION_ID="12"\n')
    dpkg_dir = root / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text("Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1\nSource: openssl\n\n")
    # Planted credential so the secret scanner has something to redact.
    (root / "app.env").write_text("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEDEADBEEFCAFE1234\n")
    return root


# ── Opt-in gating ─────────────────────────────────────────────────────────────


class TestOptInGating:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENT_BOM_SIDESCAN", raising=False)
        assert is_sidescan_enabled() is False

    def test_constructor_raises_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENT_BOM_SIDESCAN", raising=False)
        with pytest.raises(SideScanDisabledError) as exc:
            AwsEbsSideScanner(ec2_client=FakeEc2Client())
        # Actionable, mentions the flag and that it is opt-in.
        assert "AGENT_BOM_SIDESCAN" in str(exc.value)
        assert "opt-in" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_run_side_scan_raises_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENT_BOM_SIDESCAN", raising=False)
        with pytest.raises(SideScanDisabledError):
            await run_side_scan(ec2_client=FakeEc2Client(), volume_id="vol-x")

    def test_enabled_truthy_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for val in ("1", "true", "YES", "on"):
            monkeypatch.setenv("AGENT_BOM_SIDESCAN", val)
            assert is_sidescan_enabled() is True
        for val in ("0", "false", "no", ""):
            monkeypatch.setenv("AGENT_BOM_SIDESCAN", val)
            assert is_sidescan_enabled() is False


# ── Full lifecycle ────────────────────────────────────────────────────────────


class TestFullLifecycle:
    @pytest.mark.asyncio
    async def test_snapshot_mount_parse_cleanup(self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Avoid any network in CVE scan.
        async def _no_cves(_self: object, _pkgs: object) -> int:
            return 0

        monkeypatch.setattr(AwsEbsSideScanner, "_scan_cves", _no_cves)

        ec2 = FakeEc2Client()
        mount = FakeMountController(debian_rootfs)
        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=mount,
        )

        result = await scanner.scan_volume("vol-target", instance_id="i-target")

        names = ec2.names()
        # Full ordered lifecycle present.
        assert "create_snapshot" in names
        assert "create_volume" in names
        assert "attach_volume" in names
        assert "detach_volume" in names
        assert "delete_volume" in names
        assert "delete_snapshot" in names
        # Snapshot is tagged for the orphan sweep.
        snap_call = next(c for c in ec2.calls if c[0] == "create_snapshot")
        tags = snap_call[1]["TagSpecifications"][0]["Tags"]
        assert {"Key": SIDESCAN_TAG_KEY, "Value": SIDESCAN_TAG_VALUE} in tags
        # Mounted, parsed, and torn down.
        assert mount.attach_calls and mount.unmount_calls
        assert result.cleaned_up is True
        assert result.snapshot_id == "snap-1"
        # Native parser found the deb package off the mounted fixture.
        assert any(p.name == "libssl3" for p in result.packages)

    @pytest.mark.asyncio
    async def test_delete_snapshot_targets_created_snapshot(
        self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _no_cves(_self: object, _pkgs: object) -> int:
            return 0

        monkeypatch.setattr(AwsEbsSideScanner, "_scan_cves", _no_cves)
        ec2 = FakeEc2Client()
        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=FakeMountController(debian_rootfs),
        )
        await scanner.scan_volume("vol-target")
        del_snap = next(c for c in ec2.calls if c[0] == "delete_snapshot")
        assert del_snap[1]["SnapshotId"] == "snap-1"


# ── Cleanup guarantee on failure ──────────────────────────────────────────────


class TestCleanupOnFailure:
    @pytest.mark.asyncio
    async def test_parse_raises_snapshot_still_deleted(self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ec2 = FakeEc2Client()
        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=FakeMountController(debian_rootfs),
        )

        # Make parsing blow up after the snapshot + volume + mount exist.
        def _boom(_self: object, _mp: object) -> list:
            raise RuntimeError("parser exploded mid-scan")

        monkeypatch.setattr(AwsEbsSideScanner, "_parse_packages", _boom)

        with pytest.raises(RuntimeError, match="parser exploded"):
            await scanner.scan_volume("vol-target")

        # The load-bearing guarantee: teardown happened despite the raise.
        names = ec2.names()
        assert "delete_volume" in names
        assert "delete_snapshot" in names

    @pytest.mark.asyncio
    async def test_mount_raises_snapshot_still_deleted(self, enabled: None, monkeypatch: pytest.MonkeyPatch) -> None:
        ec2 = FakeEc2Client()

        class ExplodingMount:
            def attach_and_mount(self, volume_id: str, device: str) -> Path:
                raise OSError("mount failed")

            def unmount(self, mount_point: Path) -> None:  # pragma: no cover - never reached
                pass

        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=ExplodingMount(),
        )
        with pytest.raises(OSError):
            await scanner.scan_volume("vol-target")
        # Snapshot + temp volume created before the mount failure must be reaped.
        names = ec2.names()
        assert "delete_snapshot" in names
        assert "delete_volume" in names


# ── Missing config (graceful) ─────────────────────────────────────────────────


class TestMissingConfig:
    @pytest.mark.asyncio
    async def test_missing_collector_raises_actionable_and_cleans_snapshot(self, enabled: None, monkeypatch: pytest.MonkeyPatch) -> None:
        ec2 = FakeEc2Client()
        # No collector_instance_id / AZ — provisioning the temp volume is impossible.
        scanner = AwsEbsSideScanner(ec2_client=ec2, mount_controller=FakeMountController(Path("/tmp")))
        with pytest.raises(SideScanConfigError) as exc:
            await scanner.scan_volume("vol-target")
        assert "collector" in str(exc.value).lower()
        # Snapshot was created before we discovered the missing config — it must
        # still be cleaned up (no temp volume was ever created).
        names = ec2.names()
        assert "create_snapshot" in names
        assert "delete_snapshot" in names
        assert "create_volume" not in names


# ── Orphan sweep ──────────────────────────────────────────────────────────────


class TestOrphanSweep:
    def test_sweep_deletes_tagged_snapshots(self, enabled: None) -> None:
        ec2 = FakeEc2Client(orphan_snapshots=[{"SnapshotId": "snap-orphan-1"}, {"SnapshotId": "snap-orphan-2"}])
        scanner = AwsEbsSideScanner(ec2_client=ec2)
        deleted = scanner.sweep_orphan_snapshots()
        assert deleted == ["snap-orphan-1", "snap-orphan-2"]
        # Filtered by our tag, self-owned only.
        desc = next(c for c in ec2.calls if c[0] == "describe_snapshots")
        assert desc[1]["Filters"][0]["Name"] == f"tag:{SIDESCAN_TAG_KEY}"
        assert desc[1]["OwnerIds"] == ["self"]

    def test_sweep_nothing_to_do(self, enabled: None) -> None:
        ec2 = FakeEc2Client(orphan_snapshots=[])
        scanner = AwsEbsSideScanner(ec2_client=ec2)
        assert scanner.sweep_orphan_snapshots() == []

    @pytest.mark.asyncio
    async def test_run_side_scan_sweeps_then_scans(self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _no_cves(_self: object, _pkgs: object) -> int:
            return 0

        monkeypatch.setattr(AwsEbsSideScanner, "_scan_cves", _no_cves)
        ec2 = FakeEc2Client(orphan_snapshots=[{"SnapshotId": "snap-orphan-1"}])
        mount = FakeMountController(debian_rootfs)
        # Patch the default mount controller construction by injecting via kwargs.
        results = await run_side_scan(
            volume_id="vol-target",
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            ec2_client=ec2,
            mount_controller=mount,
        )
        names = ec2.names()
        assert "describe_snapshots" in names  # the sweep
        assert "create_snapshot" in names  # the actual scan
        assert len(results) == 1
        assert results[0].cleaned_up is True


# ── Metadata-only output ──────────────────────────────────────────────────────


class TestMetadataOnly:
    @pytest.mark.asyncio
    async def test_secrets_carry_no_values_or_content(self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _no_cves(_self: object, _pkgs: object) -> int:
            return 0

        monkeypatch.setattr(AwsEbsSideScanner, "_scan_cves", _no_cves)
        ec2 = FakeEc2Client()
        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=FakeMountController(debian_rootfs),
        )
        result = await scanner.scan_volume("vol-target")

        # The planted AWS secret value must never appear anywhere in the output.
        planted_value = "AKIAIOSFODNN7EXAMPLEDEADBEEFCAFE1234"
        serialized = str(result.to_dict())
        assert planted_value not in serialized
        for secret in result.secrets:
            d = secret.to_dict()
            # Only type/location/severity/category — never a value/preview/content field.
            assert set(d.keys()) == {"type", "file", "line", "severity", "category"}
            assert planted_value not in str(d)

    @pytest.mark.asyncio
    async def test_result_dict_has_no_file_contents(self, enabled: None, debian_rootfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _no_cves(_self: object, _pkgs: object) -> int:
            return 0

        monkeypatch.setattr(AwsEbsSideScanner, "_scan_cves", _no_cves)
        ec2 = FakeEc2Client()
        scanner = AwsEbsSideScanner(
            ec2_client=ec2,
            collector_instance_id="i-collector",
            availability_zone="us-east-1a",
            mount_controller=FakeMountController(debian_rootfs),
        )
        result = await scanner.scan_volume("vol-target")
        d = result.to_dict()
        # Only counts + metadata, no raw blobs.
        assert set(d.keys()) >= {
            "package_count",
            "vulnerability_count",
            "secret_count",
            "cleaned_up",
        }
        assert "content" not in d
        assert "raw" not in d


# ── Enumeration ───────────────────────────────────────────────────────────────


class TestEnumeration:
    def test_enumerate_specific_volume(self, enabled: None) -> None:
        ec2 = FakeEc2Client(volumes=[{"VolumeId": "vol-abc", "Attachments": []}])
        scanner = AwsEbsSideScanner(ec2_client=ec2)
        targets = scanner.enumerate_target_volumes(volume_id="vol-abc")
        assert targets == [{"volume_id": "vol-abc", "instance_id": ""}]
        call = next(c for c in ec2.calls if c[0] == "describe_volumes")
        assert call[1]["VolumeIds"] == ["vol-abc"]

    def test_enumerate_by_instance(self, enabled: None) -> None:
        ec2 = FakeEc2Client(volumes=[{"VolumeId": "vol-1", "Attachments": [{"InstanceId": "i-xyz"}]}])
        scanner = AwsEbsSideScanner(ec2_client=ec2)
        targets = scanner.enumerate_target_volumes(instance_id="i-xyz")
        assert targets[0]["instance_id"] == "i-xyz"
        call = next(c for c in ec2.calls if c[0] == "describe_volumes")
        assert call[1]["Filters"][0]["Name"] == "attachment.instance-id"

    def test_enumerate_all(self, enabled: None) -> None:
        ec2 = FakeEc2Client(volumes=[{"VolumeId": "vol-1", "Attachments": []}, {"VolumeId": "vol-2", "Attachments": []}])
        scanner = AwsEbsSideScanner(ec2_client=ec2)
        targets = scanner.enumerate_target_volumes()
        assert {t["volume_id"] for t in targets} == {"vol-1", "vol-2"}
