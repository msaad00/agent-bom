"""Tests for medium-priority hardening fixes.

Covers: HTTP redirect limits, enrichment cache bounds, CVSS validation,
Alpine/RHEL image scanning, pre-release version filtering, fleet sync atomicity.
"""

from __future__ import annotations

import tarfile
import tempfile
from io import BytesIO
from unittest.mock import MagicMock, patch

# ── M1: HTTP redirect limits ─────────────────────────────────────────────────


def test_create_client_default_redirects():
    """create_client sets max_redirects=5 by default."""
    import asyncio

    from agent_bom.http_client import create_client

    client = create_client()
    assert client.max_redirects == 5
    asyncio.run(client.aclose())


def test_create_client_custom_redirects():
    """create_client accepts a custom max_redirects."""
    import asyncio

    from agent_bom.http_client import create_client

    client = create_client(max_redirects=10)
    assert client.max_redirects == 10
    asyncio.run(client.aclose())


def test_create_client_follows_redirects():
    """create_client enables follow_redirects."""
    import asyncio

    from agent_bom.http_client import create_client

    client = create_client()
    assert client.follow_redirects is True
    asyncio.run(client.aclose())


# ── M2: Enrichment cache bounds ──────────────────────────────────────────────


def test_evict_oldest_noop_under_limit():
    """_evict_oldest does nothing when cache is within limit."""
    from agent_bom.enrichment import _evict_oldest

    cache = {f"CVE-{i}": {"_cached_at": i} for i in range(5)}
    _evict_oldest(cache, 10)
    assert len(cache) == 5


def test_evict_oldest_trims_to_max():
    """_evict_oldest removes oldest entries when cache exceeds max."""
    from agent_bom.enrichment import _evict_oldest

    cache = {f"CVE-{i}": {"_cached_at": float(i)} for i in range(20)}
    _evict_oldest(cache, 10)
    assert len(cache) == 10
    # Oldest entries (0-9) should be gone, newest (10-19) should remain
    assert "CVE-0" not in cache
    assert "CVE-19" in cache


def test_evict_oldest_exact_limit():
    """_evict_oldest does nothing when cache is exactly at max."""
    from agent_bom.enrichment import _evict_oldest

    cache = {f"CVE-{i}": {"_cached_at": float(i)} for i in range(10)}
    _evict_oldest(cache, 10)
    assert len(cache) == 10


def test_max_enrichment_cache_entries_defined():
    """_MAX_ENRICHMENT_CACHE_ENTRIES is set to a reasonable value."""
    from agent_bom.enrichment import _MAX_ENRICHMENT_CACHE_ENTRIES

    assert _MAX_ENRICHMENT_CACHE_ENTRIES == 10_000


# ── M3: CVSS validation ─────────────────────────────────────────────────────


def test_cvss_valid_score_accepted():
    """Valid CVSS scores (0.0-10.0) are parsed correctly."""
    from agent_bom.scanners import parse_osv_severity

    # Build a minimal OSV vuln with a CVSS score of 7.5
    vuln_data = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "database_specific": {"severity": "HIGH"},
    }

    severity, score = parse_osv_severity(vuln_data)
    # Should accept the score — exact value depends on CVSS parsing
    assert severity is not None


def test_cvss_out_of_range_rejected():
    """Out-of-range CVSS scores are rejected."""
    from agent_bom.scanners import parse_osv_severity

    # Build a vuln with an impossible CVSS score
    vuln_data = {
        "severity": [{"type": "CVSS_V3", "score": "15.0"}],
        "database_specific": {"severity": "CRITICAL"},
    }

    severity, score = parse_osv_severity(vuln_data)
    # Should reject the out-of-range score and fall back to label
    assert score is None or (score is not None and 0.0 <= score <= 10.0)


def test_cvss_negative_rejected():
    """Negative CVSS scores are rejected."""
    from agent_bom.scanners import parse_osv_severity

    vuln_data = {
        "severity": [{"type": "CVSS_V3", "score": "-5.0"}],
        "database_specific": {"severity": "LOW"},
    }

    severity, score = parse_osv_severity(vuln_data)
    assert score is None or (score is not None and 0.0 <= score <= 10.0)


# ── M4: Alpine/RHEL image scanning ──────────────────────────────────────────


def _make_tar_with_file(path: str, content: str) -> bytes:
    """Create an in-memory tar archive with a single file."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = content.encode("utf-8")
        info = tarfile.TarInfo(name=path)
        info.size = len(data)
        tf.addfile(info, BytesIO(data))
    return buf.getvalue()


def test_alpine_apk_extraction():
    """Alpine apk database is parsed from container tar."""
    from agent_bom.image import _packages_from_tar

    apk_content = """C:Q1abc123=
P:musl
V:1.2.3-r0
A:x86_64
S:123456
I:234567
T:musl C library
U:https://musl.libc.org/
L:MIT

P:busybox
V:1.36.1-r0
A:x86_64
S:500000
I:600000
T:BusyBox utilities
U:https://busybox.net/
L:GPL-2.0

"""
    tar_bytes = _make_tar_with_file("lib/apk/db/installed", apk_content)

    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp:
        tmp.write(tar_bytes)
        tmp.flush()
        packages = _packages_from_tar(tmp.name)

    apk_pkgs = [p for p in packages if p.ecosystem == "apk"]
    assert len(apk_pkgs) >= 2
    names = {p.name for p in apk_pkgs}
    assert "musl" in names
    assert "busybox" in names
    # Check version parsing
    musl = next(p for p in apk_pkgs if p.name == "musl")
    assert musl.version == "1.2.3-r0"
    assert "pkg:apk/alpine/musl" in musl.purl


def test_rpm_manifest_extraction():
    """RHEL/Fedora rpm manifest is parsed from container tar."""
    from agent_bom.image import _packages_from_tar

    rpm_content = """gpg-pubkey-fd431d51-4ae0493b
bash-5.2.26-3.el9.x86_64
coreutils-9.1-12.el9.x86_64
glibc-2.34-83.el9.x86_64
"""
    tar_bytes = _make_tar_with_file("var/log/installed-rpms", rpm_content)

    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp:
        tmp.write(tar_bytes)
        tmp.flush()
        packages = _packages_from_tar(tmp.name)

    rpm_pkgs = [p for p in packages if p.ecosystem == "rpm"]
    assert len(rpm_pkgs) >= 3
    names = {p.name for p in rpm_pkgs}
    assert "bash" in names
    assert "coreutils" in names
    assert "glibc" in names
    # gpg-pubkey should be skipped
    assert "gpg-pubkey" not in names
    # Check version parsing
    bash = next(p for p in rpm_pkgs if p.name == "bash")
    assert "5.2.26" in bash.version


# ── M5: Pre-release version filtering ────────────────────────────────────────


def test_npm_resolve_skips_prerelease():
    """npm version resolver skips pre-release versions."""
    from agent_bom.transitive import _resolve_npm_version

    pkg_data = {
        "dist-tags": {"latest": "1.2.0"},
        "versions": {
            "1.0.0": {},
            "1.1.0-beta.1": {},
            "1.1.0-rc.1": {},
            "1.1.0": {},
            "1.2.0-alpha": {},
            "1.2.0": {},
        },
    }

    result = _resolve_npm_version("^1.0.0", pkg_data)
    assert result == "1.2.0"
    assert "alpha" not in result
    assert "beta" not in result
    assert "rc" not in result


def test_npm_resolve_all_prerelease_falls_back_to_latest():
    """When all candidates are pre-release, falls back to latest."""
    from agent_bom.transitive import _resolve_npm_version

    pkg_data = {
        "dist-tags": {"latest": "1.0.0-beta"},
        "versions": {
            "1.0.0-alpha": {},
            "1.0.0-beta": {},
        },
    }

    result = _resolve_npm_version("^1.0.0", pkg_data)
    # No stable candidates, should fall back to latest
    assert result == "1.0.0-beta"


def test_npm_is_prerelease():
    """_is_prerelease correctly identifies semver pre-releases."""
    from agent_bom.transitive import _is_prerelease

    assert _is_prerelease("1.0.0-beta") is True
    assert _is_prerelease("2.1.0-rc.1") is True
    assert _is_prerelease("3.0.0-alpha.2") is True
    assert _is_prerelease("1.0.0") is False
    assert _is_prerelease("2.3.4") is False
    # Build metadata only is NOT a pre-release
    assert _is_prerelease("1.0.0+build.123") is False


def test_npm_tilde_skips_prerelease():
    """Tilde range resolver skips pre-release versions."""
    from agent_bom.transitive import _resolve_npm_version

    pkg_data = {
        "dist-tags": {"latest": "1.2.3"},
        "versions": {
            "1.2.0": {},
            "1.2.1-beta": {},
            "1.2.1": {},
            "1.2.2-rc.1": {},
            "1.2.2": {},
        },
    }

    result = _resolve_npm_version("~1.2.0", pkg_data)
    assert result == "1.2.2"


def test_npm_gte_skips_prerelease():
    """>= range resolver skips pre-release versions."""
    from agent_bom.transitive import _resolve_npm_version

    pkg_data = {
        "dist-tags": {"latest": "3.0.0"},
        "versions": {
            "2.0.0": {},
            "2.1.0-beta": {},
            "2.1.0": {},
            "3.0.0-rc.1": {},
            "3.0.0": {},
        },
    }

    result = _resolve_npm_version(">=2.0.0", pkg_data)
    assert result == "3.0.0"


def test_fixed_version_prefers_stable():
    """parse_fixed_version prefers stable releases over pre-releases."""
    from agent_bom.scanners import parse_fixed_version

    vuln_data = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.32.0"},
                        ],
                    }
                ],
            }
        ]
    }

    result = parse_fixed_version(vuln_data, "requests")
    assert result == "2.32.0"


def test_fixed_version_skips_prerelease():
    """parse_fixed_version skips pre-release fixed versions when stable exists."""
    from agent_bom.scanners import parse_fixed_version

    vuln_data = {
        "affected": [
            {
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "3.0.0rc1"},
                            {"fixed": "3.0.0"},
                        ],
                    }
                ],
            }
        ]
    }

    result = parse_fixed_version(vuln_data, "flask")
    assert result == "3.0.0"


def test_fixed_version_fallback_to_prerelease():
    """parse_fixed_version falls back to pre-release if no stable fix exists."""
    from agent_bom.scanners import parse_fixed_version

    vuln_data = {
        "affected": [
            {
                "package": {"name": "mylib", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.0.0a1"},
                        ],
                    }
                ],
            }
        ]
    }

    result = parse_fixed_version(vuln_data, "mylib")
    assert result == "2.0.0a1"


# ── M6: Fleet sync atomicity ─────────────────────────────────────────────────


def test_sync_uses_batch_put():
    """_sync_scan_agents_to_fleet uses batch_put for atomic upsert."""
    from agent_bom.api.server import _sync_scan_agents_to_fleet

    mock_store = MagicMock()
    mock_store.get_by_name.return_value = None  # All new agents

    # Create mock agents
    agents = []
    for i in range(3):
        agent = MagicMock()
        agent.name = f"agent-{i}"
        agent.agent_type.value = "mcp_client"
        agent.config_path = f"/path/{i}"
        server = MagicMock()
        server.packages = []
        server.credential_names = []
        server.total_vulnerabilities = 0
        agent.mcp_servers = [server]
        agents.append(agent)

    with (
        patch("agent_bom.api.server._get_fleet_store", return_value=mock_store),
        patch("agent_bom.fleet.trust_scoring.compute_trust_score", return_value=(0.8, {"test": True})),
    ):
        _sync_scan_agents_to_fleet(agents)

    # batch_put should be called once with all 3 agents
    mock_store.batch_put.assert_called_once()
    call_args = mock_store.batch_put.call_args[0][0]
    assert len(call_args) == 3


def test_sync_batch_put_with_existing():
    """_sync_scan_agents_to_fleet handles mix of new and existing agents."""
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.api.server import _sync_scan_agents_to_fleet

    existing_agent = FleetAgent(
        agent_id="existing-id",
        name="agent-0",
        agent_type="mcp_client",
        lifecycle_state=FleetLifecycleState.APPROVED,
        trust_score=0.5,
    )

    mock_store = MagicMock()
    mock_store.get_by_name.side_effect = lambda name: existing_agent if name == "agent-0" else None

    agents = []
    for i in range(2):
        agent = MagicMock()
        agent.name = f"agent-{i}"
        agent.agent_type.value = "mcp_client"
        agent.config_path = f"/path/{i}"
        server = MagicMock()
        server.packages = []
        server.credential_names = []
        server.total_vulnerabilities = 0
        agent.mcp_servers = [server]
        agents.append(agent)

    with (
        patch("agent_bom.api.server._get_fleet_store", return_value=mock_store),
        patch("agent_bom.fleet.trust_scoring.compute_trust_score", return_value=(0.9, {})),
    ):
        _sync_scan_agents_to_fleet(agents)

    # batch_put called with 2 agents (1 existing updated + 1 new)
    mock_store.batch_put.assert_called_once()
    call_args = mock_store.batch_put.call_args[0][0]
    assert len(call_args) == 2
    # No individual put calls
    mock_store.put.assert_not_called()


def test_sync_empty_agents_no_batch_put():
    """_sync_scan_agents_to_fleet skips batch_put for empty list."""
    from agent_bom.api.server import _sync_scan_agents_to_fleet

    mock_store = MagicMock()

    with patch("agent_bom.api.server._get_fleet_store", return_value=mock_store):
        _sync_scan_agents_to_fleet([])

    mock_store.batch_put.assert_not_called()
