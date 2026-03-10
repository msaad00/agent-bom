"""Discover and audit browser extensions for AI-infrastructure security risks.

Scans Chrome, Chromium, Brave, Edge (Chromium), and Firefox extension
directories.  Parses ``manifest.json`` (Manifest V2 and V3) and flags
dangerous permission combinations that could expose AI assistant sessions,
MCP tool calls, or locally stored credentials.

CLI usage::

    agent-bom scan --browser-extensions

No network calls are made — all analysis is local/static.
"""

from __future__ import annotations

import json
import logging
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── Permission risk taxonomy ─────────────────────────────────────────────────

_CRITICAL_PERMISSIONS: frozenset[str] = frozenset(
    [
        "debugger",  # full devtools access = arbitrary JS execution in any tab
        "nativeMessaging",  # IPC to local binaries / could communicate with MCP servers
        "proxy",  # intercept and redirect all browser traffic
        "webRequestBlocking",  # block or modify any HTTP request (MV2)
    ]
)

_HIGH_PERMISSIONS: frozenset[str] = frozenset(
    [
        "cookies",  # read all cookies, including auth session tokens
        "clipboardRead",  # read clipboard — frequently contains copied API keys / tokens
        "history",  # full browsing history
        "tabs",  # access all tab URLs and content
        "webRequest",  # observe all HTTP requests (read-only but still high risk)
        "downloads",  # intercept file downloads
        "pageCapture",  # capture full rendered page content
        "management",  # install/uninstall/enable/disable other extensions
        "contentSettings",  # override per-site content policies
    ]
)

# Broad host patterns that grant access to all or most sites
_BROAD_HOST_PATTERNS: frozenset[str] = frozenset(
    [
        "<all_urls>",
        "*://*/*",
        "http://*/*",
        "https://*/*",
    ]
)

# AI assistant web UI domains — access to these is especially sensitive
_AI_ASSISTANT_HOSTS: list[str] = [
    "claude.ai",
    "chatgpt.com",
    "chat.openai.com",
    "cursor.sh",
    "copilot.github.com",
    "copilot.microsoft.com",
    "gemini.google.com",
    "poe.com",
    "perplexity.ai",
    "anthropic.com",
]

_RISK_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ─── Data model ───────────────────────────────────────────────────────────────


@dataclass
class BrowserExtension:
    """Parsed browser extension with security risk assessment."""

    id: str
    name: str
    version: str
    browser: str  # "chrome" | "firefox"
    manifest_version: int = 2
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    has_native_messaging: bool = False
    has_ai_host_access: bool = False
    risk_level: str = "low"  # "critical" | "high" | "medium" | "low"
    risk_reasons: list[str] = field(default_factory=list)
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "browser": self.browser,
            "manifest_version": self.manifest_version,
            "permissions": self.permissions,
            "host_permissions": self.host_permissions,
            "has_native_messaging": self.has_native_messaging,
            "has_ai_host_access": self.has_ai_host_access,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "path": self.path,
        }


# ─── Risk assessment ──────────────────────────────────────────────────────────


def _assess_extension_risk(
    manifest: dict,
) -> tuple[str, list[str], bool, bool]:
    """Return ``(risk_level, reasons, has_native_messaging, has_ai_host_access)``.

    Handles both Manifest V2 (permissions may contain host patterns) and
    Manifest V3 (host_permissions is a separate key).
    """
    reasons: list[str] = []

    raw_perms = manifest.get("permissions", [])
    if not isinstance(raw_perms, list):
        raw_perms = []
    host_perms_raw_val = manifest.get("host_permissions", [])
    if not isinstance(host_perms_raw_val, list):
        host_perms_raw_val = []
    host_perms_raw: list = list(host_perms_raw_val)  # MV3

    # MV2: host patterns can appear inline in permissions[]
    mv2_host_perms = [p for p in raw_perms if isinstance(p, str) and p.startswith(("http", "https", "ftp", "<", "*"))]
    non_host_perms: set[str] = {p for p in raw_perms if isinstance(p, str)} - set(mv2_host_perms)
    all_hosts: set[str] = set(host_perms_raw) | set(mv2_host_perms)

    has_native_messaging = "nativeMessaging" in non_host_perms

    # Critical permissions
    crit_found = non_host_perms & _CRITICAL_PERMISSIONS
    for p in sorted(crit_found):
        reasons.append(f"Critical permission: {p}")

    # High-risk permissions
    high_found = non_host_perms & _HIGH_PERMISSIONS
    for p in sorted(high_found):
        reasons.append(f"High-risk permission: {p}")

    # Broad host access
    broad_found = all_hosts & _BROAD_HOST_PATTERNS
    if broad_found:
        reasons.append(f"Broad host access: {', '.join(sorted(broad_found))}")

    # AI assistant host access (proper domain suffix matching)
    def _host_matches_domain(host_pattern: str, domain: str) -> bool:
        """Check if a host permission pattern matches a domain or its subdomains."""
        # Strip protocol and wildcard prefixes: *://*.claude.ai/* → claude.ai
        h = host_pattern.split("://")[-1].lstrip("*.").rstrip("/*").lower()
        return h == domain or h.endswith(f".{domain}")

    ai_hosts_matched = [h for h in all_hosts if any(_host_matches_domain(h, ai) for ai in _AI_ASSISTANT_HOSTS)]
    for h in sorted(ai_hosts_matched):
        reasons.append(f"Access to AI assistant domain: {h}")
    has_ai_access = bool(ai_hosts_matched) or bool(broad_found)

    # Determine overall risk level
    if crit_found or (has_native_messaging and broad_found) or (has_ai_access and high_found):
        risk_level = "critical"
    elif high_found or (broad_found and non_host_perms) or ai_hosts_matched:
        risk_level = "high"
    elif broad_found or len(non_host_perms) > 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    return risk_level, reasons, has_native_messaging, has_ai_access


def _build_extension(manifest: dict, ext_id: str, browser: str, path: str) -> BrowserExtension:
    """Construct a ``BrowserExtension`` from a parsed manifest dict."""
    risk_level, reasons, has_nm, has_ai = _assess_extension_risk(manifest)

    raw_perms: list = manifest.get("permissions", [])
    non_host = [p for p in raw_perms if isinstance(p, str) and not p.startswith(("http", "https", "ftp", "<", "*"))]
    host_perms = list(manifest.get("host_permissions", [])) + [
        p for p in raw_perms if isinstance(p, str) and p.startswith(("http", "https", "ftp", "<", "*"))
    ]

    return BrowserExtension(
        id=ext_id,
        name=manifest.get("name", ext_id),
        version=str(manifest.get("version", "unknown")),
        browser=browser,
        manifest_version=int(manifest.get("manifest_version", 2)),
        permissions=non_host,
        host_permissions=host_perms,
        has_native_messaging=has_nm,
        has_ai_host_access=has_ai,
        risk_level=risk_level,
        risk_reasons=reasons,
        path=path,
    )


# ─── Chrome / Chromium / Brave / Edge scanner ─────────────────────────────────


def _scan_chrome_profile(profile_dir: Path) -> list[BrowserExtension]:
    """Scan a single Chromium-based profile Extensions directory."""
    extensions_dir = profile_dir / "Extensions"
    if not extensions_dir.is_dir():
        return []

    results: list[BrowserExtension] = []
    for ext_id_dir in extensions_dir.iterdir():
        if not ext_id_dir.is_dir():
            continue
        ext_id = ext_id_dir.name
        # Each extension may have multiple version sub-dirs; use the newest
        version_dirs = sorted(
            [d for d in ext_id_dir.iterdir() if d.is_dir()],
            key=lambda d: d.name,
            reverse=True,
        )
        for version_dir in version_dirs:
            manifest_path = version_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
                ext = _build_extension(manifest, ext_id, "chrome", str(version_dir))
                results.append(ext)
            except (json.JSONDecodeError, OSError, ValueError) as exc:
                logger.debug("Failed to parse Chrome extension %s: %s", manifest_path, exc)
            break  # most recent version only
    return results


def _chrome_profile_dirs() -> list[Path]:
    """Return candidate Chromium-family profile directories for the current user."""
    home = Path.home()
    candidates: list[Path] = []

    sysname = ""
    try:
        sysname = os.uname().sysname
    except AttributeError:
        pass  # Windows: os.uname() not available

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(home)))
        candidates = [
            base / "Google" / "Chrome" / "User Data",
            base / "Microsoft" / "Edge" / "User Data",
            base / "BraveSoftware" / "Brave-Browser" / "User Data",
        ]
    elif sysname == "Darwin":
        lib = home / "Library" / "Application Support"
        candidates = [
            lib / "Google" / "Chrome",
            lib / "Microsoft Edge",
            lib / "BraveSoftware" / "Brave-Browser",
        ]
    else:  # Linux / BSD
        config = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        candidates = [
            config / "google-chrome",
            config / "chromium",
            config / "microsoft-edge",
            config / "BraveSoftware" / "Brave-Browser",
        ]

    profile_dirs: list[Path] = []
    for base in candidates:
        if not base.exists():
            continue
        if (base / "Default").is_dir():
            profile_dirs.append(base / "Default")
        for d in base.iterdir():
            if d.is_dir() and d.name.startswith("Profile "):
                profile_dirs.append(d)
    return profile_dirs


# ─── Firefox scanner ──────────────────────────────────────────────────────────


def _scan_firefox_profile(profile_dir: Path) -> list[BrowserExtension]:
    """Scan a single Firefox profile for extensions (unpacked dirs + XPI zips)."""
    results: list[BrowserExtension] = []
    ext_dir = profile_dir / "extensions"
    if not ext_dir.is_dir():
        return results

    for entry in ext_dir.iterdir():
        if entry.is_dir():
            manifest_path = entry / "manifest.json"
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
                    results.append(_build_extension(manifest, entry.name, "firefox", str(entry)))
                except (json.JSONDecodeError, OSError, ValueError) as exc:
                    logger.debug("Failed to parse Firefox extension %s: %s", entry, exc)
        elif entry.suffix.lower() == ".xpi":
            try:
                with zipfile.ZipFile(entry, "r") as zf:
                    if "manifest.json" in zf.namelist():
                        manifest = json.loads(zf.read("manifest.json").decode("utf-8", errors="replace"))
                        results.append(_build_extension(manifest, entry.stem, "firefox", str(entry)))
            except (zipfile.BadZipFile, json.JSONDecodeError, OSError, ValueError, KeyError) as exc:
                logger.debug("Failed to parse Firefox XPI %s: %s", entry, exc)
    return results


def _firefox_profile_dirs() -> list[Path]:
    """Return candidate Firefox profile directories for the current user."""
    home = Path.home()
    sysname = ""
    try:
        sysname = os.uname().sysname
    except AttributeError:
        pass

    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(home))) / "Mozilla" / "Firefox" / "Profiles"
    elif sysname == "Darwin":
        base = home / "Library" / "Application Support" / "Firefox" / "Profiles"
    else:
        base = home / ".mozilla" / "firefox"

    if not base.is_dir():
        return []
    return [d for d in base.iterdir() if d.is_dir()]


# ─── Public API ───────────────────────────────────────────────────────────────


def discover_browser_extensions(
    include_low_risk: bool = False,
) -> list[BrowserExtension]:
    """Discover installed browser extensions and assess their security risk.

    Scans Chrome, Chromium, Brave, Edge (Chromium), and Firefox profiles
    for the current user.  No network calls are made.

    Args:
        include_low_risk: If ``False`` (default), returns only medium+ risk
                          extensions to reduce noise.

    Returns:
        Extensions sorted by risk level: critical → high → medium → low.
    """
    all_extensions: list[BrowserExtension] = []
    seen: set[tuple[str, str]] = set()  # (browser, id) dedup

    for profile_dir in _chrome_profile_dirs():
        for ext in _scan_chrome_profile(profile_dir):
            key = ("chrome", ext.id)
            if key not in seen:
                seen.add(key)
                all_extensions.append(ext)

    for profile_dir in _firefox_profile_dirs():
        for ext in _scan_firefox_profile(profile_dir):
            key = ("firefox", ext.id)
            if key not in seen:
                seen.add(key)
                all_extensions.append(ext)

    if not include_low_risk:
        all_extensions = [e for e in all_extensions if e.risk_level != "low"]

    all_extensions.sort(key=lambda e: _RISK_ORDER.get(e.risk_level, 4))

    logger.debug(
        "Browser extension scan: %d extensions (%d medium+)",
        len(all_extensions),
        sum(1 for e in all_extensions if e.risk_level in ("critical", "high", "medium")),
    )
    return all_extensions
