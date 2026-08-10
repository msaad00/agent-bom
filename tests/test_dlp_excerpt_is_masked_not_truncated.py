"""A DLP excerpt must not carry the secret it detected.

`_redact_excerpt` was `match_text[:12] + "***"` — a *truncation*, not a
redaction. Every pattern shorter than the cut survived in full:

    SSN         '123-45-6789'       -> '123-45-6789***'
    phone       '415-555-1234'      -> '415-555-1234***'
    internal ip '10.1.2.3'          -> '10.1.2.3***'
    PAN (visa)  '4111111111111111'  -> '411111111111***'   (12 of 16 digits)
    long token  (40 chars)         -> first 12 characters, verbatim

The SSN, phone and private-IP patterns are all at most 12 characters, so the
"redacted" preview *was* the finding. Worse, redaction was applied only at the
durable-storage boundary: the same alert object also goes to the alert webhook,
the control-plane push, disk spillover, and `runtime_alerts` — which is what
`/ws/proxy/alerts` streams.

The rule this encodes: an excerpt exists to let a human recognise *which* rule
fired and roughly where, never to reproduce the matched value. PCI DSS allows
at most first-6/last-4 of a PAN; nothing here needs even that, so the excerpt
keeps a short tail for correlation and masks everything else. A value short
enough that any tail would identify it is masked entirely.
"""

from __future__ import annotations

import pytest

from agent_bom.proxy_scanner import _redact_excerpt

# The exact values the audit recovered from the shipped implementation.
LEAKED_IN_FULL = [
    ("ssn", "123-45-6789"),
    ("phone", "415-555-1234"),
    ("internal_ip", "10.1.2.3"),
    ("short_key", "EXAMPLEKEYID0"),
]

# Built from parts, and labelled neutrally, so no long literal sits next to a
# credential-shaped keyword. Real fixtures here previously tripped our own
# secret scanning in CI — the values only need the right *length*, since
# `_redact_excerpt` is a pure string function.
_LONG_40 = "abcdefghij" * 4
_SLASHED_40 = "aaaaaaaaaa" + "/" + "bbbbbbbbbbbbbbbbbb" + "/" + "cccccccccc"

PARTIALLY_LEAKED = [
    ("pan_visa", "4111111111111111"),
    ("long_opaque_value", _LONG_40),
    ("slashed_opaque_value", _SLASHED_40),
]


@pytest.mark.parametrize("rule,secret", LEAKED_IN_FULL + PARTIALLY_LEAKED)
def test_the_secret_never_appears_in_the_excerpt(rule: str, secret: str) -> None:
    excerpt = _redact_excerpt(secret)
    assert secret not in excerpt, f"{rule}: the whole value survived redaction"


@pytest.mark.parametrize("rule,secret", LEAKED_IN_FULL + PARTIALLY_LEAKED)
def test_no_long_run_of_the_secret_survives(rule: str, secret: str) -> None:
    """Not just the whole value — no substring long enough to be the secret."""
    masked = _redact_excerpt(secret)
    revealed = "".join(ch for ch in masked if ch not in "*")
    assert len(revealed) <= 6, f"{rule}: {len(revealed)} characters of the value survived: {masked!r}"


def test_a_pan_keeps_at_most_the_last_four() -> None:
    """PCI DSS 3.4 permits first-6/last-4; we need far less than that."""
    masked = _redact_excerpt("4111111111111111")
    assert "411111111111" not in masked
    digits = "".join(ch for ch in masked if ch.isdigit())
    assert len(digits) <= 4, masked


def test_a_short_value_is_masked_entirely() -> None:
    """Below a useful length, any tail identifies the value."""
    assert _redact_excerpt("1234") == "***"
    assert _redact_excerpt("") == "***"


def test_the_excerpt_still_says_something_useful() -> None:
    """Redaction must not make the alert unrecognisable — it is triage evidence."""
    masked = _redact_excerpt(_LONG_40)
    assert masked, "an empty excerpt tells an operator nothing"
    assert "*" in masked, "the excerpt should read as redacted, not as a value"


def test_length_is_not_recoverable_from_the_mask() -> None:
    """A mask that mirrors length leaks the length of the secret."""
    short = _redact_excerpt(_LONG_40[:16])
    long = _redact_excerpt(_LONG_40 + "extra")
    assert len(short) == len(long), (short, long)
