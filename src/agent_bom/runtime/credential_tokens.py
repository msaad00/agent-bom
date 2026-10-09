"""Token-boundary building blocks for the credential patterns.

A vendor prefix only marks a credential at the start of a token. Without a
boundary ``sk-`` fires inside ``task-``/``risk-``/``disk-`` and ``key-`` inside
``monkey-``, turning ordinary identifiers into CRITICAL findings.
"""

from __future__ import annotations

import re

TOKEN_CHARS = "A-Za-z0-9_-"


def token(prefix: str, width: int, boundary: str = TOKEN_CHARS) -> str:
    """``prefix`` (exactly ``width`` chars) when no token char precedes it.

    The boundary is a lookbehind *after* the prefix so the pattern still
    starts with a literal and keeps the regex engine's fast prefix scan;
    a leading lookbehind made every pattern probe every character.
    """
    return prefix + rf"(?<![{boundary}][\s\S]{{{width}}})"


# OpenAI keys are random base62/base64url bodies. A body with no digit, or one
# that is a lowercase hyphenated slug (``sk-campaign-evidence-label``), is a
# CSS class or identifier, not a key. ``sk-ant-`` belongs to Anthropic.
OPENAI_KEY = re.compile(
    token("sk-", 3) + r"(?!ant-)(?:proj-)?"
    r"(?=[A-Za-z0-9_-]*[0-9])"
    r"(?![a-z0-9]+(?:-[a-z0-9]+)+(?![A-Za-z0-9_-]))"
    r"[A-Za-z0-9\-_]{20,}"
)
