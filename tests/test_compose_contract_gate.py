"""Contract for the compose gate (`scripts/check_compose_contract.py`).

Nothing in CI parsed these files before. The risk with a new parse gate is that
it degenerates into "it exited 0", so the assertions on the RENDERED model are
tested directly here — a dangling `depends_on`, an imageless service, and a
read-only bind mount of a missing path each have to be caught.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_compose_contract.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_compose_contract", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


def _has_compose() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
    return result.returncode == 0


requires_compose = pytest.mark.skipif(not _has_compose(), reason="docker compose is not available on this runner")


class TestDiscovery:
    def test_every_shipped_compose_file_is_discovered(self):
        """Discovery is structural so a new profile cannot be added unguarded."""
        standalone, overlays = gate.discover()
        found = {p.relative_to(ROOT).as_posix() for p in [*standalone, *overlays]}
        expected = {
            "deploy/docker-compose.yml",
            "deploy/docker-compose.pilot.yml",
            "deploy/docker-compose.fullstack.yml",
            "deploy/docker-compose.platform.yml",
            "deploy/docker-compose.runtime-example.yml",
            "deploy/docker-compose.hosted-poc.yml",
            "deploy/docker-compose.product.yml",
            "deploy/docker-compose.demo-override.yml",
            "deploy/supabase/clickhouse/docker-compose.yml",
            "examples/docker-compose-monitoring.yml",
        }
        assert expected <= found

    def test_overlays_are_classified_as_overlays(self):
        _, overlays = gate.discover()
        names = {p.relative_to(ROOT).as_posix() for p in overlays}
        assert names == set(gate.OVERLAY_BASES)

    def test_every_overlay_is_validated_against_a_base(self):
        """An overlay with no declared base is a target that can never run."""
        for target in gate.build_targets():
            assert not target.problems, target.problems

    def test_an_undeclared_overlay_fails_closed(self, monkeypatch):
        monkeypatch.setattr(gate, "OVERLAY_BASES", {})
        problems = [p for target in gate.build_targets() for p in target.problems]
        assert any("no declared base" in p for p in problems)


class TestRenderedAssertions:
    """`docker compose config` exiting 0 is not proof the graph is usable."""

    def _target(self) -> gate.Target:
        return gate.Target(files=[ROOT / "deploy" / "docker-compose.yml"], label="synthetic")

    def test_service_without_image_or_build_is_caught(self):
        target = self._target()
        gate._assert_rendered(target, {"services": {"api": {}}})
        assert any("neither an image nor a build" in p for p in target.problems)

    def test_dangling_depends_on_is_caught(self):
        target = self._target()
        gate._assert_rendered(target, {"services": {"api": {"image": "x", "depends_on": {"ghost": {}}}}})
        assert any("depends_on 'ghost'" in p for p in target.problems)

    def test_renders_no_services_is_caught(self):
        target = self._target()
        gate._assert_rendered(target, {"services": {}})
        assert any("renders no services" in p for p in target.problems)

    def test_missing_readonly_bind_mount_is_caught(self):
        target = self._target()
        volume = {"type": "bind", "read_only": True, "source": str(ROOT / "deploy" / "does-not-exist")}
        gate._assert_rendered(target, {"services": {"api": {"image": "x", "volumes": [volume]}}})
        assert any("missing path" in p for p in target.problems)

    def test_existing_readonly_bind_mount_passes(self):
        target = self._target()
        volume = {"type": "bind", "read_only": True, "source": str(ROOT / "tests")}
        gate._assert_rendered(target, {"services": {"api": {"image": "x", "volumes": [volume]}}})
        assert target.problems == []

    def test_generated_secret_mounts_are_exempt(self):
        """`make secrets` writes these; they are gitignored by design."""
        target = self._target()
        volume = {"type": "bind", "read_only": True, "source": str(ROOT / "deploy" / "secrets" / "api_key")}
        gate._assert_rendered(target, {"services": {"api": {"image": "x", "volumes": [volume]}}})
        assert target.problems == []

    def test_host_home_mounts_are_not_asserted(self):
        target = self._target()
        volume = {"type": "bind", "read_only": True, "source": "/home/someone/.config"}
        gate._assert_rendered(target, {"services": {"api": {"image": "x", "volumes": [volume]}}})
        assert target.problems == []


class TestRequiredEnvIsDerived:
    def test_required_variables_get_a_placeholder(self):
        """`${VAR:?}` is required by design, not a broken file."""
        clickhouse = ROOT / "deploy" / "supabase" / "clickhouse" / "docker-compose.yml"
        env = gate._env_for([clickhouse])
        assert env.get("GRAFANA_ADMIN_USER") == gate._PLACEHOLDER


class TestTheRepositoryItself:
    @requires_compose
    def test_every_compose_target_parses_and_renders(self):
        failed = [(t.label, t.problems) for t in gate.run() if t.problems]
        assert failed == [], f"compose contract failures: {failed}"
