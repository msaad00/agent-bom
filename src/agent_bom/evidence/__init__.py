"""Two-bucket evidence redaction policy (issue #2261).

Evidence rows attached to findings split across two persistence tiers:

* :data:`EvidenceTier.SAFE_TO_STORE` (tier A) — package versions, lockfile
  paths, tool / scope names, host names, env-var *names*, ids, timestamps,
  status codes. Safe to keep indefinitely in the audit log, exports, and
  the compliance hub.
* :data:`EvidenceTier.REPLAY_ONLY` (tier B) — raw prompts, tool inputs /
  outputs, full file paths, full URLs with paths / queries, command args,
  response bodies, anything copied from the user's workspace. Captured
  only when ``--capture-replay`` is enabled and rotated on a short TTL
  (default 7 days, ``AGENT_BOM_REPLAY_TTL_DAYS``).

Driven by community feedback on r/mcp (anderson_the_one, 455 upvotes).
"""

from agent_bom.evidence.policy import (
    DEFAULT_REPLAY_TTL_DAYS,
    REPLAY_TTL_ENV,
    TIER_A_FIELDS,
    TIER_B_FIELDS,
    EvidenceTier,
    classify_field,
    classify_payload,
    has_tier_b_fields,
    redact_for_persistence,
    replay_not_after,
    replay_ttl_days,
    tier_badge,
)

__all__ = [
    "DEFAULT_REPLAY_TTL_DAYS",
    "REPLAY_TTL_ENV",
    "TIER_A_FIELDS",
    "TIER_B_FIELDS",
    "EvidenceTier",
    "classify_field",
    "classify_payload",
    "has_tier_b_fields",
    "redact_for_persistence",
    "replay_not_after",
    "replay_ttl_days",
    "tier_badge",
]
