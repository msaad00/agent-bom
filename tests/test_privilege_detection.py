"""Tests for Docker privilege detection and PermissionProfile model."""

import json
import subprocess
from unittest.mock import MagicMock, patch

from agent_bom.image import detect_container_privileges, detect_image_privileges
from agent_bom.models import PermissionProfile

# ─── PermissionProfile model tests ───────────────────────────────────────────


class TestPermissionProfile:
    def test_defaults(self):
        p = PermissionProfile()
        assert not p.runs_as_root
        assert not p.container_privileged
        assert not p.shell_access
        assert not p.network_access
        assert not p.filesystem_write
        assert p.tool_permissions == {}
        assert p.capabilities == []
        assert p.security_opt == []

    def test_is_elevated_false_default(self):
        assert not PermissionProfile().is_elevated

    def test_is_elevated_root(self):
        assert PermissionProfile(runs_as_root=True).is_elevated

    def test_is_elevated_privileged(self):
        assert PermissionProfile(container_privileged=True).is_elevated

    def test_is_elevated_shell(self):
        assert PermissionProfile(shell_access=True).is_elevated

    def test_is_elevated_capabilities(self):
        assert PermissionProfile(capabilities=["CAP_NET_RAW"]).is_elevated

    def test_is_elevated_network_only_not_elevated(self):
        assert not PermissionProfile(network_access=True).is_elevated

    def test_is_elevated_fs_write_only_not_elevated(self):
        assert not PermissionProfile(filesystem_write=True).is_elevated

    def test_privilege_level_critical_privileged(self):
        assert PermissionProfile(container_privileged=True).privilege_level == "critical"

    def test_privilege_level_critical_sys_admin(self):
        assert PermissionProfile(capabilities=["CAP_SYS_ADMIN"]).privilege_level == "critical"

    def test_privilege_level_high_root(self):
        assert PermissionProfile(runs_as_root=True).privilege_level == "high"

    def test_privilege_level_high_shell(self):
        assert PermissionProfile(shell_access=True).privilege_level == "high"

    def test_privilege_level_medium_fs_write(self):
        assert PermissionProfile(filesystem_write=True).privilege_level == "medium"

    def test_privilege_level_medium_network(self):
        assert PermissionProfile(network_access=True).privilege_level == "medium"

    def test_privilege_level_medium_other_caps(self):
        assert PermissionProfile(capabilities=["CAP_NET_RAW"]).privilege_level == "medium"

    def test_privilege_level_low(self):
        assert PermissionProfile().privilege_level == "low"


# ─── detect_image_privileges ─────────────────────────────────────────────────


class TestDetectImagePrivileges:
    def _mock_inspect(self, config):
        """Helper: patch _docker_inspect to return given config."""
        return patch(
            "agent_bom.image._docker_inspect",
            return_value={"Config": config},
        )

    def test_root_user_empty(self):
        with self._mock_inspect({"User": "", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert p.runs_as_root

    def test_root_user_zero(self):
        with self._mock_inspect({"User": "0", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert p.runs_as_root

    def test_root_user_explicit(self):
        with self._mock_inspect({"User": "root", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert p.runs_as_root

    def test_nonroot_user(self):
        with self._mock_inspect({"User": "app", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert not p.runs_as_root

    def test_exposed_ports(self):
        with self._mock_inspect({"User": "app", "ExposedPorts": {"80/tcp": {}}, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert p.network_access

    def test_no_exposed_ports(self):
        with self._mock_inspect({"User": "app", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert not p.network_access

    def test_volumes(self):
        with self._mock_inspect({"User": "app", "ExposedPorts": None, "Volumes": {"/data": {}}}):
            p = detect_image_privileges("test:latest")
        assert p.filesystem_write

    def test_no_volumes(self):
        with self._mock_inspect({"User": "app", "ExposedPorts": None, "Volumes": None}):
            p = detect_image_privileges("test:latest")
        assert not p.filesystem_write

    def test_inspect_failure_returns_empty_profile(self):
        from agent_bom.image import ImageScanError
        with patch("agent_bom.image._docker_inspect", side_effect=ImageScanError("nope")):
            p = detect_image_privileges("bad:image")
        assert not p.runs_as_root
        assert not p.network_access
        assert p.privilege_level == "low"


# ─── detect_container_privileges ─────────────────────────────────────────────


class TestDetectContainerPrivileges:
    def _mock_subprocess(self, data, returncode=0):
        result = MagicMock()
        result.returncode = returncode
        result.stdout = json.dumps([data])
        return patch("agent_bom.image.subprocess.run", return_value=result)

    def test_privileged_container(self):
        data = {
            "Config": {"User": ""},
            "HostConfig": {
                "Privileged": True,
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": [],
                "NetworkMode": "bridge",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert p.container_privileged
        assert p.runs_as_root
        assert p.privilege_level == "critical"

    def test_cap_add(self):
        data = {
            "Config": {"User": "app"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["CAP_SYS_ADMIN", "CAP_NET_RAW"],
                "CapDrop": None,
                "SecurityOpt": [],
                "NetworkMode": "bridge",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert "CAP_SYS_ADMIN" in p.capabilities
        assert "CAP_NET_RAW" in p.capabilities
        assert p.privilege_level == "critical"

    def test_cap_drop_filters(self):
        data = {
            "Config": {"User": "app"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["CAP_NET_RAW", "CAP_SYS_PTRACE"],
                "CapDrop": ["CAP_NET_RAW"],
                "SecurityOpt": [],
                "NetworkMode": "bridge",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert "CAP_NET_RAW" not in p.capabilities
        assert "CAP_SYS_PTRACE" in p.capabilities

    def test_host_network(self):
        data = {
            "Config": {"User": "app"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": [],
                "NetworkMode": "host",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert p.network_access

    def test_security_opts(self):
        data = {
            "Config": {"User": "app"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": ["no-new-privileges", "seccomp=unconfined"],
                "NetworkMode": "none",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert "seccomp=unconfined" in p.security_opt

    def test_subprocess_failure_returns_empty(self):
        result = MagicMock()
        result.returncode = 1
        with patch("agent_bom.image.subprocess.run", return_value=result):
            p = detect_container_privileges("bad_container")
        assert not p.container_privileged
        assert p.privilege_level == "low"

    def test_subprocess_timeout_returns_empty(self):
        with patch(
            "agent_bom.image.subprocess.run",
            side_effect=subprocess.TimeoutExpired("docker", 30),
        ):
            p = detect_container_privileges("slow_container")
        assert p.privilege_level == "low"

    def test_nonroot_user(self):
        data = {
            "Config": {"User": "nonroot"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": [],
                "NetworkMode": "none",
            },
        }
        with self._mock_subprocess(data):
            p = detect_container_privileges("abc123")
        assert not p.runs_as_root
        assert not p.network_access
