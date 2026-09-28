"""Redaction rules for discovery provenance markers.

``MCPServer.discovery_sources`` records where a server was found as
``<source>:<location>`` (for example ``project-config:/repo/.mcp.json``). The
marker as a whole is not a secret candidate: digit runs in a directory name can
push it over the entropy threshold. The location is a filesystem path, so it
gets the same label as every other exported path.
"""

from __future__ import annotations

import re

from agent_bom import security

PROVENANCE_KEYS = frozenset({"discovery_sources"})
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_PATH_LABEL_RE = re.compile(r"<path:[^<>]+>")


def sanitize_provenance_marker(value: str) -> str | None:
    """Return ``<source>:<path:basename>``, or ``None`` for any other shape.

    ``None`` leaves the value to the generic field rules, so URLs, bare
    labels and anything carrying a credential-shaped label keep today's
    handling.
    """
    label, sep, location = value.partition(":")
    if not sep or not _LABEL_RE.fullmatch(label) or security._looks_sensitive_value(label):
        return None
    if not (security._looks_like_path_value(location) or _PATH_LABEL_RE.fullmatch(location)):
        return None
    return f"{label}:{security.sanitize_path_label(location)}"
