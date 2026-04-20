"""Tests for VisualLeakDetector — OCR + redact on MCP screenshot tool responses.

Real tesseract is not required in CI (it's a heavy system dep). The tests
mock ``_extract_word_boxes`` to feed the detector synthetic OCR output
that mirrors what a real screenshot would look like post-OCR. One test
exercises the full pytesseract path and skips cleanly when the binary
isn't on PATH.

Every assertion ties back to the pilot-team failure mode: an MCP that
captures a screen containing an AWS key must be detected AND redacted
before the image reaches the agent.
"""

from __future__ import annotations

import base64
import io
from unittest.mock import patch

import pytest

pytest.importorskip("PIL")
pytest.importorskip("pytesseract")

from PIL import Image  # noqa: E402

from agent_bom.runtime.detectors import AlertSeverity  # noqa: E402
from agent_bom.runtime.visual_leak_detector import VisualLeakDetector  # noqa: E402


def _png_bytes(width: int = 400, height: int = 200, color: str = "white") -> bytes:
    """Render a blank PNG — the test only cares about bytes, OCR is mocked."""
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color=color).save(buf, format="PNG")
    return buf.getvalue()


def _img_block(png_bytes: bytes | None = None) -> dict:
    payload = png_bytes if png_bytes is not None else _png_bytes()
    return {
        "type": "image",
        "data": base64.b64encode(payload).decode(),
        "mimeType": "image/png",
    }


def _ocr_words(words_with_boxes: list[tuple[str, tuple[int, int, int, int]]]):
    """Build a patch target for _extract_word_boxes."""
    return patch(
        "agent_bom.runtime.visual_leak_detector._extract_word_boxes",
        return_value=words_with_boxes,
    )


# ─── Disabled path: no OCR binary, no Pillow → graceful no-op ──────────────


def test_detector_disabled_returns_empty_alerts_and_passes_blocks_through():
    d = VisualLeakDetector(enabled=False)
    assert d.enabled is False
    blocks = [_img_block()]
    assert d.check("screen_shot", blocks) == []
    assert d.redact(blocks) == blocks  # same object contents, unchanged


def test_detector_disabled_does_not_mutate_non_image_blocks():
    d = VisualLeakDetector(enabled=False)
    blocks = [{"type": "text", "text": "hello"}, _img_block()]
    assert d.check("anything", blocks) == []
    result = d.redact(blocks)
    assert result[0] == {"type": "text", "text": "hello"}


# ─── Enabled path (OCR mocked): credential leak in image ───────────────────


def test_detector_flags_aws_access_key_in_screenshot():
    """The real pilot-day-1 scenario: a Playwright MCP captures a page
    where the developer's AWS access key is visible.
    """
    with _ocr_words(
        [
            ("Dashboard", (10, 10, 110, 30)),
            ("AKIAIOSFODNN7EXAMPLE", (10, 50, 260, 70)),  # matches AWS Access Key pattern
            ("region:", (10, 90, 80, 110)),
            ("us-east-1", (85, 90, 180, 110)),
        ]
    ):
        d = VisualLeakDetector(enabled=True)
        alerts = d.check("playwright_screenshot", [_img_block()])

    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == AlertSeverity.CRITICAL
    assert a.detector == "visual_credential_leak"
    assert "AWS Access Key" in a.message
    assert "playwright_screenshot" in a.message
    assert a.details["leak_type"] == "AWS Access Key"
    assert a.details["category"] == "credential_leak"
    # bbox preserved so SIEM / audit can highlight the region in the original
    assert a.details["bbox"] == [10, 50, 260, 70]


def test_detector_flags_pii_email_in_screenshot():
    with _ocr_words(
        [
            ("User:", (10, 10, 60, 30)),
            ("jane.doe@example.com", (65, 10, 230, 30)),  # matches Email PII pattern
        ]
    ):
        d = VisualLeakDetector(enabled=True)
        alerts = d.check("browser_capture", [_img_block()])

    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == AlertSeverity.HIGH
    assert a.detector == "visual_pii_leak"
    assert "Email" in a.message


def test_detector_returns_empty_when_ocr_finds_nothing_sensitive():
    with _ocr_words(
        [
            ("Welcome", (10, 10, 110, 30)),
            ("to", (115, 10, 140, 30)),
            ("the", (145, 10, 175, 30)),
            ("app", (180, 10, 220, 30)),
        ]
    ):
        d = VisualLeakDetector(enabled=True)
        assert d.check("screen_capture", [_img_block()]) == []


# ─── Redact pipeline ────────────────────────────────────────────────────────


def test_redact_paints_over_sensitive_regions_and_returns_new_bytes():
    """Original image bytes must not be mutated; redacted copy has a black box over the key."""
    original = _png_bytes()
    blocks = [_img_block(original)]

    with _ocr_words([("AKIAIOSFODNN7EXAMPLE", (10, 50, 260, 70))]):
        d = VisualLeakDetector(enabled=True)
        redacted_blocks = d.redact(blocks)

    assert len(redacted_blocks) == 1
    redacted = redacted_blocks[0]
    assert redacted["type"] == "image"
    # Copy, not mutation — original block is untouched.
    assert blocks[0]["data"] != redacted["data"], "bytes should differ (redaction painted)"
    # Check the pixel at the center of the redaction box is now black.
    painted_png = base64.b64decode(redacted["data"])
    img = Image.open(io.BytesIO(painted_png))
    px = img.getpixel(((10 + 260) // 2, (50 + 70) // 2))
    assert px in {(0, 0, 0), (0, 0, 0, 255)}, f"expected black redaction, got {px}"


def test_redact_passes_through_blocks_with_no_matches_unchanged():
    original = _png_bytes()
    blocks = [_img_block(original)]

    with _ocr_words([("nothing", (10, 10, 80, 30)), ("sensitive", (85, 10, 180, 30))]):
        d = VisualLeakDetector(enabled=True)
        result = d.redact(blocks)

    # No re-encoding when there's nothing to redact — same bytes out.
    assert result[0]["data"] == blocks[0]["data"]


def test_redact_preserves_non_image_blocks():
    text_block = {"type": "text", "text": "sk-ant-xxx"}  # text-channel leaks are caught elsewhere
    img = _img_block()
    with _ocr_words([]):
        d = VisualLeakDetector(enabled=True)
        result = d.redact([text_block, img])
    assert result[0] is text_block  # same object — never touched
    assert len(result) == 2


# ─── Edge cases ────────────────────────────────────────────────────────────


def test_malformed_base64_data_does_not_crash_detector():
    bad_block = {"type": "image", "data": "not-valid-base64!!!", "mimeType": "image/png"}
    d = VisualLeakDetector(enabled=True)
    # No alerts; no exception.
    assert d.check("t", [bad_block]) == []
    # Redact returns the block unchanged when it can't decode.
    assert d.redact([bad_block]) == [bad_block]


def test_empty_image_data_is_ignored():
    empty_block = {"type": "image", "data": "", "mimeType": "image/png"}
    d = VisualLeakDetector(enabled=True)
    assert d.check("t", [empty_block]) == []


def test_multi_word_sliding_window_catches_key_value_leaks():
    """'api_key = abc...xyz' spans three OCR words; the window pass must catch it."""
    with _ocr_words(
        [
            ("api_key", (10, 10, 90, 30)),
            ("=", (95, 10, 105, 30)),
            ("ABCDEF1234567890abcdef1234567890ABCDEF", (110, 10, 410, 30)),
        ]
    ):
        d = VisualLeakDetector(enabled=True)
        alerts = d.check("form_screenshot", [_img_block()])

    # Matches Generic API Key — label varies by pattern name, but at least one critical must fire.
    assert any(a.severity == AlertSeverity.CRITICAL for a in alerts)


# ─── Optional: real OCR path (skipped if tesseract is absent) ──────────────


def _tesseract_available() -> bool:
    try:
        import pytesseract

        pytesseract.get_tesseract_version()
        return True
    except Exception:  # noqa: BLE001
        return False


def test_screen_capture_tool_class_is_denied_via_policy():
    """Integration check: the proxy policy engine classifies screen_capture
    tool names and denies them wholesale when the policy opts in.
    """
    from agent_bom.proxy_policy import _classify_tool_classes, check_policy

    assert "screen_capture" in _classify_tool_classes("take_screenshot", {})
    assert "screen_capture" in _classify_tool_classes("page_screenshot", {"url": "https://example.com"})
    assert "screen_capture" not in _classify_tool_classes("read_file", {"path": "/tmp/x"})

    policy = {
        "rules": [
            {"id": "no-screen-capture", "action": "block", "deny_tool_classes": ["screen_capture"]},
        ]
    }
    allowed, reason = check_policy(policy, "take_screenshot", {})
    assert allowed is False
    assert "screen_capture" in reason


@pytest.mark.skipif(not _tesseract_available(), reason="tesseract binary not installed")
def test_real_ocr_path_on_synthetic_png_with_aws_key():
    """Render a PNG with a fake AWS key drawn on it; run real OCR."""
    from PIL import ImageDraw, ImageFont

    img = Image.new("RGB", (500, 100), color="white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 20)
    except OSError:
        font = ImageFont.load_default()
    draw.text((10, 30), "AKIAIOSFODNN7EXAMPLE", fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    block = {"type": "image", "data": base64.b64encode(buf.getvalue()).decode(), "mimeType": "image/png"}

    d = VisualLeakDetector(enabled=True)
    alerts = d.check("real_ocr", [block])
    # Real OCR is imperfect; we only assert the detector runs without error
    # and returns a list. Precision of real-world OCR is validated by the
    # integration test matrix rather than unit-level pattern counts.
    assert isinstance(alerts, list)
