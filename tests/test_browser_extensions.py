"""Tests for browser extension discovery and security assessment."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.parsers.browser_extensions import (
    _assess_extension_risk,
    _build_extension,
    _chrome_profile_dirs,
    _firefox_profile_dirs,
    _scan_chrome_profile,
    _scan_firefox_profile,
    discover_browser_extensions,
)

# ─── _assess_extension_risk ───────────────────────────────────────────────────


def test_critical_native_messaging_with_broad_host():
    manifest = {
        "permissions": ["nativeMessaging", "<all_urls>"],
    }
    level, reasons, has_nm, has_ai = _assess_extension_risk(manifest)
    assert level == "critical"
    assert has_nm is True
    assert any("nativeMessaging" in r for r in reasons)
    assert any("<all_urls>" in r for r in reasons)


def test_critical_debugger_permission():
    manifest = {"permissions": ["debugger"]}
    level, reasons, has_nm, _ = _assess_extension_risk(manifest)
    assert level == "critical"
    assert has_nm is False
    assert any("debugger" in r for r in reasons)


def test_critical_web_request_blocking():
    manifest = {"permissions": ["webRequestBlocking", "https://*/*"]}
    level, reasons, _, _ = _assess_extension_risk(manifest)
    assert level == "critical"


def test_high_cookies_and_history():
    manifest = {"permissions": ["cookies", "history"]}
    level, reasons, _, _ = _assess_extension_risk(manifest)
    assert level in ("critical", "high")
    assert any("cookies" in r for r in reasons)
    assert any("history" in r for r in reasons)


def test_high_ai_assistant_host_access():
    manifest = {"host_permissions": ["https://claude.ai/*"]}
    level, reasons, _, has_ai = _assess_extension_risk(manifest)
    assert has_ai is True
    assert any("claude.ai" in r for r in reasons)
    assert level in ("critical", "high")


def test_high_broad_host_mv3():
    manifest = {"host_permissions": ["<all_urls>"]}
    level, reasons, _, has_ai = _assess_extension_risk(manifest)
    assert has_ai is True
    assert any("<all_urls>" in r for r in reasons)
    assert level in ("critical", "high", "medium")


def test_medium_many_permissions():
    manifest = {"permissions": ["tabs", "notifications", "contextMenus", "storage", "alarms"]}
    level, _, _, _ = _assess_extension_risk(manifest)
    assert level in ("medium", "high")


def test_low_safe_extension():
    manifest = {"permissions": ["storage"]}
    level, reasons, has_nm, has_ai = _assess_extension_risk(manifest)
    assert level == "low"
    assert has_nm is False
    assert has_ai is False
    assert reasons == []


def test_mv2_inline_host_patterns():
    """MV2 extensions put host patterns directly in permissions[]."""
    manifest = {"permissions": ["cookies", "http://*/*"]}
    level, reasons, _, _ = _assess_extension_risk(manifest)
    assert any("http://*/*" in r for r in reasons)
    assert level in ("critical", "high")


def test_no_permissions_key():
    manifest = {}
    level, reasons, has_nm, has_ai = _assess_extension_risk(manifest)
    assert level == "low"
    assert reasons == []


# ─── _build_extension ─────────────────────────────────────────────────────────


def test_build_extension_populates_fields():
    manifest = {
        "name": "My Extension",
        "version": "1.2.3",
        "manifest_version": 3,
        "permissions": ["cookies"],
        "host_permissions": ["https://chatgpt.com/*"],
    }
    ext = _build_extension(manifest, "abcdef123", "chrome", "/tmp/ext")
    assert ext.id == "abcdef123"
    assert ext.name == "My Extension"
    assert ext.version == "1.2.3"
    assert ext.manifest_version == 3
    assert ext.browser == "chrome"
    assert ext.has_ai_host_access is True
    assert ext.risk_level in ("critical", "high")
    assert ext.path == "/tmp/ext"


def test_build_extension_to_dict():
    manifest = {"name": "Safe", "version": "0.1", "permissions": ["storage"]}
    ext = _build_extension(manifest, "xyz", "firefox", "/tmp/safe")
    d = ext.to_dict()
    assert d["id"] == "xyz"
    assert d["browser"] == "firefox"
    assert d["risk_level"] == "low"
    assert isinstance(d["permissions"], list)
    assert isinstance(d["host_permissions"], list)


# ─── Chrome profile scanner ───────────────────────────────────────────────────


def test_scan_chrome_profile_reads_manifest(tmp_path):
    ext_id = "aaabbbccc111222333"
    version = "1.0.0_0"
    ext_dir = tmp_path / "Extensions" / ext_id / version
    ext_dir.mkdir(parents=True)
    manifest = {
        "name": "Test Chrome Ext",
        "version": "1.0.0",
        "manifest_version": 2,
        "permissions": ["nativeMessaging", "<all_urls>"],
    }
    (ext_dir / "manifest.json").write_text(json.dumps(manifest))

    results = _scan_chrome_profile(tmp_path)
    assert len(results) == 1
    assert results[0].name == "Test Chrome Ext"
    assert results[0].has_native_messaging is True
    assert results[0].risk_level == "critical"


def test_scan_chrome_profile_picks_newest_version(tmp_path):
    ext_id = "extidxxx"
    for ver in ["1.0.0_0", "2.0.0_0", "1.5.0_0"]:
        d = tmp_path / "Extensions" / ext_id / ver
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({"name": f"v{ver}", "version": ver}))

    results = _scan_chrome_profile(tmp_path)
    # Should only return 1 result (newest version)
    assert len(results) == 1


def test_scan_chrome_profile_skips_invalid_json(tmp_path):
    ext_dir = tmp_path / "Extensions" / "badext" / "1.0.0_0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "manifest.json").write_text("{invalid json")

    results = _scan_chrome_profile(tmp_path)
    assert results == []


def test_scan_chrome_profile_no_extensions_dir(tmp_path):
    results = _scan_chrome_profile(tmp_path)
    assert results == []


# ─── Firefox profile scanner ──────────────────────────────────────────────────


def test_scan_firefox_profile_unpacked_dir(tmp_path):
    ext_dir = tmp_path / "extensions" / "my-ext@example.com"
    ext_dir.mkdir(parents=True)
    manifest = {
        "name": "FF Extension",
        "version": "2.0",
        "permissions": ["cookies", "history"],
    }
    (ext_dir / "manifest.json").write_text(json.dumps(manifest))

    results = _scan_firefox_profile(tmp_path)
    assert len(results) == 1
    assert results[0].name == "FF Extension"
    assert results[0].browser == "firefox"
    assert results[0].risk_level in ("critical", "high")


def test_scan_firefox_profile_xpi(tmp_path):
    ext_dir = tmp_path / "extensions"
    ext_dir.mkdir()
    xpi_path = ext_dir / "my-addon.xpi"
    manifest = {
        "name": "XPI Extension",
        "version": "1.0",
        "permissions": ["debugger"],
    }
    with zipfile.ZipFile(xpi_path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))

    results = _scan_firefox_profile(tmp_path)
    assert len(results) == 1
    assert results[0].name == "XPI Extension"
    assert results[0].risk_level == "critical"


def test_scan_firefox_profile_bad_xpi(tmp_path):
    ext_dir = tmp_path / "extensions"
    ext_dir.mkdir()
    (ext_dir / "corrupt.xpi").write_bytes(b"not a zip")

    results = _scan_firefox_profile(tmp_path)
    assert results == []


def test_scan_firefox_profile_no_extensions_dir(tmp_path):
    results = _scan_firefox_profile(tmp_path)
    assert results == []


# ─── discover_browser_extensions ─────────────────────────────────────────────


def test_discover_returns_list(monkeypatch):
    """discover_browser_extensions returns a list even if no profiles exist."""
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._chrome_profile_dirs", lambda: [])
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._firefox_profile_dirs", lambda: [])
    result = discover_browser_extensions()
    assert isinstance(result, list)
    assert result == []


def test_browser_extensions_cli_reports_empty_scan(monkeypatch, tmp_path):
    """--browser-extensions should leave observable JSON even when no profiles match."""
    monkeypatch.setattr("agent_bom.parsers.browser_extensions.discover_browser_extensions", lambda include_low_risk=False: [])
    monkeypatch.setattr("agent_bom.cli.agents._discovery._discover_all_default", lambda *args, **kwargs: [])
    out_file = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--browser-extensions",
            "--project",
            str(tmp_path),
            "--format",
            "json",
            "--output",
            str(out_file),
            "--no-auto-update-db",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(out_file.read_text())
    assert data["browser_extensions"] == {
        "extensions": [],
        "total": 0,
        "critical_count": 0,
        "high_count": 0,
    }
    assert "browser_extensions" in data["scan_sources"]


def test_discover_filters_low_risk(monkeypatch, tmp_path):
    """Only medium+ risk extensions are returned by default."""
    low_manifest = {"name": "Safe", "version": "0.1", "permissions": ["storage"]}
    high_manifest = {
        "name": "Dangerous",
        "version": "1.0",
        "permissions": ["cookies", "history", "tabs"],
    }
    # Build chrome profile with two extensions
    for ext_id, manifest in [("low_ext", low_manifest), ("high_ext", high_manifest)]:
        d = tmp_path / "Extensions" / ext_id / "1.0.0_0"
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps(manifest))

    monkeypatch.setattr("agent_bom.parsers.browser_extensions._chrome_profile_dirs", lambda: [tmp_path])
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._firefox_profile_dirs", lambda: [])

    result = discover_browser_extensions(include_low_risk=False)
    names = [e.name for e in result]
    assert "Dangerous" in names
    assert "Safe" not in names


def test_discover_include_low_risk(monkeypatch, tmp_path):
    """include_low_risk=True returns all extensions including low risk."""
    low_manifest = {"name": "Safe", "version": "0.1", "permissions": ["storage"]}
    d = tmp_path / "Extensions" / "low_ext" / "1.0.0_0"
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps(low_manifest))

    monkeypatch.setattr("agent_bom.parsers.browser_extensions._chrome_profile_dirs", lambda: [tmp_path])
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._firefox_profile_dirs", lambda: [])

    result = discover_browser_extensions(include_low_risk=True)
    names = [e.name for e in result]
    assert "Safe" in names


def test_discover_sorted_by_risk(monkeypatch, tmp_path):
    """Results are sorted critical → high → medium → low."""
    manifests = {
        "crit_ext": {"name": "Crit", "version": "1.0", "permissions": ["debugger"]},
        "high_ext": {"name": "High", "version": "1.0", "permissions": ["cookies", "history"]},
        "med_ext": {"name": "Med", "version": "1.0", "host_permissions": ["https://*/*"]},
    }
    for ext_id, manifest in manifests.items():
        d = tmp_path / "Extensions" / ext_id / "1.0.0_0"
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps(manifest))

    monkeypatch.setattr("agent_bom.parsers.browser_extensions._chrome_profile_dirs", lambda: [tmp_path])
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._firefox_profile_dirs", lambda: [])

    result = discover_browser_extensions(include_low_risk=True)
    risk_levels = [e.risk_level for e in result]
    assert risk_levels == sorted(risk_levels, key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r, 4))


def test_discover_deduplicates(monkeypatch, tmp_path):
    """Same extension in two different profiles should appear only once."""
    manifest = {"name": "Dup Ext", "version": "1.0", "permissions": ["debugger"]}
    for profile in ["Default", "Profile 1"]:
        d = tmp_path / profile / "Extensions" / "dupid" / "1.0.0_0"
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps(manifest))

    monkeypatch.setattr(
        "agent_bom.parsers.browser_extensions._chrome_profile_dirs",
        lambda: [tmp_path / "Default", tmp_path / "Profile 1"],
    )
    monkeypatch.setattr("agent_bom.parsers.browser_extensions._firefox_profile_dirs", lambda: [])

    result = discover_browser_extensions()
    ids = [e.id for e in result]
    assert ids.count("dupid") == 1


# ─── Profile directory discovery (smoke tests) ────────────────────────────────


def test_chrome_profile_dirs_returns_list():
    dirs = _chrome_profile_dirs()
    assert isinstance(dirs, list)
    for d in dirs:
        assert isinstance(d, Path)


def test_firefox_profile_dirs_returns_list():
    dirs = _firefox_profile_dirs()
    assert isinstance(dirs, list)
    for d in dirs:
        assert isinstance(d, Path)
