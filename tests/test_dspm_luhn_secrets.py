"""Tests for Luhn-validated PAN + secret/credential DSPM detection (#3880).

Deepens dataset data classification beyond bare tag/regex:
- Payment cards are Luhn-checksum + IIN/length validated so an invalid
  16-digit sequence does NOT classify (kills the ``\\d{16}`` false positives).
- Curated high-signal secret/credential detectors are surfaced as a
  ``secret:`` data-class, reusing the runtime credential pattern library.
- Every detection carries a confidence tier (regex-only = lower,
  Luhn/structural-validated = higher).
- Matched card / secret values are NEVER echoed in the output.
"""

from __future__ import annotations

from agent_bom.parsers.dataset_pii_scanner import (
    _card_brand,
    _detect_payment_cards,
    _detect_secrets,
    _luhn_valid,
    _scan_cell,
)

# ─── Luhn checksum ────────────────────────────────────────────────────────────


def test_luhn_valid_true_for_known_test_pans():
    # Classic brand test PANs — all valid Luhn.
    assert _luhn_valid("4111111111111111")  # Visa
    assert _luhn_valid("5555555555554444")  # Mastercard
    assert _luhn_valid("378282246310005")  # Amex
    assert _luhn_valid("6011111111111117")  # Discover


def test_luhn_invalid_for_off_by_one():
    # Same IIN/length, checksum broken -> must be rejected.
    assert not _luhn_valid("4111111111111112")
    assert not _luhn_valid("5555555555554445")


def test_luhn_rejects_non_digits():
    assert not _luhn_valid("41111111111111x1")


# ─── IIN / length brand sanity ───────────────────────────────────────────────


def test_card_brand_recognizes_major_networks():
    assert _card_brand("4111111111111111") == "visa"
    assert _card_brand("5555555555554444") == "mastercard"
    assert _card_brand("378282246310005") == "amex"
    assert _card_brand("6011111111111117") == "discover"


def test_card_brand_rejects_unknown_iin_or_length():
    # Valid Luhn but no recognized IIN/length pairing.
    assert _card_brand("1234567812345670") is None
    # Visa IIN but wrong length.
    assert _card_brand("411111111111") is None


# ─── Luhn-validated PAN detection (the FP-reduction win) ──────────────────────


def test_detect_payment_cards_accepts_valid_pan():
    findings = _detect_payment_cards("card 4111111111111111 on file", 0, "c", "f.csv")
    assert len(findings) == 1
    assert findings[0].pii_type == "credit_card"
    assert findings[0].confidence == "high"
    assert findings[0].severity == "high"


def test_detect_payment_cards_rejects_invalid_16_digit():
    # Bare 16-digit number that fails Luhn must NOT classify — this is exactly
    # the false positive a naive \d{16} regex produces.
    findings = _detect_payment_cards("order id 4111111111111112 shipped", 0, "c", "f.csv")
    assert findings == []


def test_detect_payment_cards_rejects_random_16_digits():
    findings = _detect_payment_cards("1234567812345678", 0, "c", "f.csv")
    assert findings == []


def test_detect_payment_cards_accepts_separated_pan():
    findings = _detect_payment_cards("4111 1111 1111 1111", 0, "c", "f.csv")
    assert len(findings) == 1
    assert findings[0].pii_type == "credit_card"


def test_detect_payment_cards_redacts_value():
    pan = "4111111111111111"
    findings = _detect_payment_cards(pan, 0, "c", "f.csv")
    assert findings[0].sample == "[credit_card:REDACTED]"
    for digit in pan:
        assert digit not in findings[0].sample


# ─── Secret / credential detection ───────────────────────────────────────────


def test_detect_secrets_aws_access_key():
    findings = _detect_secrets("AKIAIOSFODNN7EXAMPLE", 0, "c", "f.csv")
    types = {f.pii_type for f in findings}
    assert "secret:aws_access_key" in types
    hit = next(f for f in findings if f.pii_type == "secret:aws_access_key")
    assert hit.confidence == "high"


def test_detect_secrets_github_token():
    tok = "ghp_" + "a" * 36
    findings = _detect_secrets(tok, 0, "c", "f.csv")
    assert "secret:github_token" in {f.pii_type for f in findings}


def test_detect_secrets_slack_token():
    findings = _detect_secrets("xoxb-1234567890-abcdefghijkl", 0, "c", "f.csv")
    assert "secret:slack_token" in {f.pii_type for f in findings}


def test_detect_secrets_private_key_pem():
    findings = _detect_secrets("-----BEGIN RSA PRIVATE KEY-----", 0, "c", "f.csv")
    assert "secret:private_key_block" in {f.pii_type for f in findings}


def test_detect_secrets_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123_-xyz"
    findings = _detect_secrets(jwt, 0, "c", "f.csv")
    assert "secret:jwt_token" in {f.pii_type for f in findings}


def test_detect_secrets_generic_api_key_lower_confidence():
    findings = _detect_secrets("api_key=abcdefghijklmnopqrstuvwx", 0, "c", "f.csv")
    hit = next(f for f in findings if f.pii_type == "secret:generic_api_key")
    assert hit.confidence == "low"


def test_detect_secrets_rejects_near_miss_aws():
    # AKIA prefix but too short to be a real access key id.
    findings = _detect_secrets("AKIA123", 0, "c", "f.csv")
    assert findings == []


def test_detect_secrets_rejects_near_miss_github():
    # ghp_ prefix but far too short.
    findings = _detect_secrets("ghp_short", 0, "c", "f.csv")
    assert findings == []


def test_detect_secrets_rejects_plain_prose():
    findings = _detect_secrets("this is just a normal sentence with no secrets", 0, "c", "f.csv")
    assert findings == []


def test_detect_secrets_redacts_value():
    key = "AKIAIOSFODNN7EXAMPLE"
    findings = _detect_secrets(key, 0, "c", "f.csv")
    hit = next(f for f in findings if f.pii_type == "secret:aws_access_key")
    assert hit.sample == "[secret:aws_access_key:REDACTED]"
    assert "AKIA" not in hit.sample
    assert key not in hit.sample


# ─── _scan_cell integration ──────────────────────────────────────────────────


def test_scan_cell_valid_card_classifies():
    findings = _scan_cell("4111111111111111", 0, "card", "f.csv")
    assert "credit_card" in {f.pii_type for f in findings}


def test_scan_cell_invalid_card_does_not_classify_as_card():
    findings = _scan_cell("4111111111111112", 0, "card", "f.csv")
    assert "credit_card" not in {f.pii_type for f in findings}


def test_scan_cell_surfaces_secret():
    findings = _scan_cell("AKIAIOSFODNN7EXAMPLE", 0, "creds", "f.csv")
    assert "secret:aws_access_key" in {f.pii_type for f in findings}


def test_scan_cell_all_findings_carry_confidence():
    findings = _scan_cell("alice@example.com 4111111111111111 AKIAIOSFODNN7EXAMPLE", 0, "mix", "f.csv")
    assert findings
    for f in findings:
        assert f.confidence in {"low", "medium", "high"}


def test_scan_cell_never_leaks_matched_values():
    secret = "AKIAIOSFODNN7EXAMPLE"
    pan = "4111111111111111"
    findings = _scan_cell(f"{secret} {pan}", 0, "mix", "f.csv")
    for f in findings:
        assert secret not in f.sample
        assert pan not in f.sample
        assert "REDACTED" in f.sample
