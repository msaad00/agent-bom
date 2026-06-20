"""Non-human-identity (NHI) discovery connectors.

These connectors enumerate *existing* non-human identities (service accounts,
machine principals, API tokens) from an identity provider so they can be
projected into the unified graph as ``managed_identity`` nodes and consumed by
the governance / effective-permissions overlays.

Discovery is read-only, reference-only, and token-authenticated. No passwords
are ever read, no write APIs are ever called, and a missing SDK / credential
degrades to a clear status rather than raising.
"""

from __future__ import annotations

from agent_bom.identity.entra_nhi import discover_entra_non_human_identities
from agent_bom.identity.okta_nhi import (
    DiscoveredNonHumanIdentity,
    NHIDiscoveryResult,
    NHIDiscoveryStatus,
    discover_okta_non_human_identities,
)

__all__ = [
    "DiscoveredNonHumanIdentity",
    "NHIDiscoveryResult",
    "NHIDiscoveryStatus",
    "discover_entra_non_human_identities",
    "discover_okta_non_human_identities",
]
