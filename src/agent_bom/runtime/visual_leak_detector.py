"""Visual-leak detection for MCP screenshot / image tool responses.

Any MCP that wraps a browser or screen-capture tool (Playwright-MCP,
Puppeteer-MCP, Cursor / Claude screen-read tools) can capture
credentials, PII, customer data, and internal URLs through pixels.
``CredentialLeakDetector`` only scans text responses; this detector
closes the visual channel.

Design: see ``docs/SECURITY_AUTH_TENANCY_AUDIT.md`` §Appendix and
issue #1568.

Opt-in install:

    pip install 'agent-bom[visual]'

This adds ``Pillow`` + ``pytesseract``. The detector degrades
gracefully when either is missing — it returns an empty alert list
rather than crashing, so pilots can enable it incrementally.

Wire shape:

    from agent_bom.runtime.visual_leak_detector import VisualLeakDetector

    detector = VisualLeakDetector()
    alerts = detector.check(tool_name, mcp_content_blocks)
    redacted = detector.redact(mcp_content_blocks)

Where ``mcp_content_blocks`` is the list the MCP protocol wraps image
tool responses in::

    [{"type": "image", "data": "<base64 png/jpg>", "mimeType": "image/png"}]

The redactor paints opaque boxes over the OCR bounding rectangles that
matched a credential or PII pattern and returns a new list with updated
``data`` — the original blocks are never mutated.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable

from agent_bom.runtime.detectors import Alert, AlertSeverity
from agent_bom.runtime.patterns import CREDENTIAL_PATTERNS, PII_PATTERNS

logger = logging.getLogger(__name__)

# MCP content-block keys
_IMAGE_TYPE = "image"
_DATA_KEY = "data"
_MIMETYPE_KEY = "mimeType"


@dataclass(frozen=True)
class _Match:
    """One OCR region that matched a credential or PII pattern."""

    bbox: tuple[int, int, int, int]  # (left, top, right, bottom) in pixels
    label: str  # e.g. "AWS Access Key" or "Email Address"
    category: str  # "credential_leak" | "pii_leak"


def _ocr_available() -> bool:
    """Return True if pytesseract + Pillow are importable and tesseract is on PATH."""
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    try:
        import pytesseract  # noqa: PLC0415

        pytesseract.get_tesseract_version()
    except (FileNotFoundError, OSError, RuntimeError):
        return False
    return True


def visual_leak_runtime_ready() -> bool:
    """Return True when OCR/image deps are actually available for enforcement."""
    return _ocr_available()


def require_visual_leak_runtime() -> None:
    """Raise when visual-leak enforcement is requested without OCR runtime support."""
    if visual_leak_runtime_ready():
        return
    raise RuntimeError(
        "Visual leak detection requires 'agent-bom[visual]' and the tesseract binary on PATH. "
        "Install the visual extra or disable screenshot OCR enforcement."
    )


def visual_leak_runtime_health() -> dict[str, Any]:
    """Operator-facing readiness metadata for health endpoints and startup checks."""
    ready = visual_leak_runtime_ready()
    return {
        "enabled": ready,
        "ready": ready,
        "mode": "enforcing" if ready else "unavailable",
        "reason": None if ready else "install agent-bom[visual] and ensure tesseract is on PATH",
    }


def _decode_image(block: dict[str, Any]):
    """Decode a single MCP image content block into a PIL Image, or None."""
    from PIL import Image

    raw = block.get(_DATA_KEY)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        buf = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        return None
    try:
        return Image.open(io.BytesIO(buf))
    except OSError:
        return None


def _encode_image(img, mime_type: str) -> str:
    """Re-encode a PIL Image back to the MCP data URI base64 shape."""
    from PIL import Image  # noqa: F401

    fmt = "PNG" if mime_type.endswith("png") else "JPEG"
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format=fmt)
    return base64.b64encode(buf.getvalue()).decode()


def _extract_word_boxes(img) -> list[tuple[str, tuple[int, int, int, int]]]:
    """Return [(word, bbox)] for every OCR-recognised word above the confidence floor."""
    import pytesseract

    raw = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    out: list[tuple[str, tuple[int, int, int, int]]] = []
    words = raw.get("text", [])
    confs = raw.get("conf", [])
    lefts = raw.get("left", [])
    tops = raw.get("top", [])
    widths = raw.get("width", [])
    heights = raw.get("height", [])
    for word, conf_raw, left, top, width, height in zip(words, confs, lefts, tops, widths, heights, strict=False):
        if not word or not word.strip():
            continue
        try:
            conf = float(conf_raw)
            bbox = (int(left), int(top), int(left) + int(width), int(top) + int(height))
        except (TypeError, ValueError):
            conf = -1.0
            bbox = None
        if conf < 40.0:
            continue
        if bbox is None:
            continue
        out.append((word, bbox))
    return out


def _match_patterns(
    words: list[tuple[str, tuple[int, int, int, int]]],
    patterns: Iterable[tuple[str, re.Pattern]],
    category: str,
) -> list[_Match]:
    """For each pattern, join OCR words into line-ish fragments and emit matches.

    Two passes:
      1. Single-word — matches single-token secrets like AWS access keys.
      2. 3-word sliding window — matches patterns that span whitespace
         (``api_key = ABCD...``). Windows that fully contain an
         already-matched single-word bbox are skipped, so one secret on
         the image produces one alert, not three.
    """
    matches: list[_Match] = []
    matched_word_indices: set[int] = set()

    # Single-word pass
    for idx, (word, bbox) in enumerate(words):
        for label, pat in patterns:
            if pat.search(word):
                matches.append(_Match(bbox=bbox, label=label, category=category))
                matched_word_indices.add(idx)
                break  # avoid double-counting one word under two patterns

    # Multi-word sliding window (3-word)
    for i in range(len(words) - 2):
        # Skip windows that already contain a single-word hit — the inner
        # match is the authoritative bbox; widening to the window doesn't
        # help the redactor.
        if matched_word_indices & {i, i + 1, i + 2}:
            continue
        joined = " ".join(w for w, _ in words[i : i + 3])
        for label, pat in patterns:
            if pat.search(joined):
                # Union the three word boxes into one redaction rectangle.
                boxes = [words[i][1], words[i + 1][1], words[i + 2][1]]
                left = min(b[0] for b in boxes)
                top = min(b[1] for b in boxes)
                right = max(b[2] for b in boxes)
                bottom = max(b[3] for b in boxes)
                matches.append(_Match(bbox=(left, top, right, bottom), label=label, category=category))
                break
    return matches


def _paint_redactions(img, matches: list[_Match]):
    """Return a new PIL Image with black boxes painted over the matched bboxes."""
    from PIL import ImageDraw

    out = img.copy()
    draw = ImageDraw.Draw(out)
    for m in matches:
        draw.rectangle(m.bbox, fill="black")
    return out


class VisualLeakDetector:
    """Detect + redact credentials and PII in MCP image tool responses.

    Use ``check(tool_name, content_blocks)`` to get ``Alert`` objects
    without mutating the response. Use ``redact(content_blocks)`` to
    get a new content-block list with the sensitive regions painted
    black — the original list is unchanged.
    """

    def __init__(self, *, enabled: bool | None = None) -> None:
        # Explicit enabled=True forces the detector on even without OCR deps
        # so callers can log a warning; enabled=False disables entirely.
        self._enabled = _ocr_available() if enabled is None else enabled
        if not self._enabled:
            logger.debug("VisualLeakDetector disabled (install 'agent-bom[visual]' and ensure tesseract is on PATH)")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _scan_block(self, block: dict[str, Any]) -> list[_Match]:
        if block.get("type") != _IMAGE_TYPE:
            return []
        img = _decode_image(block)
        if img is None:
            return []
        try:
            words = _extract_word_boxes(img)
        except (OSError, RuntimeError, ValueError):
            logger.warning("OCR failed on image block; skipping")
            return []
        matches = _match_patterns(words, CREDENTIAL_PATTERNS, "credential_leak")
        matches.extend(_match_patterns(words, PII_PATTERNS, "pii_leak"))
        return matches

    def check(self, tool_name: str, content_blocks: list[dict[str, Any]]) -> list[Alert]:
        """Emit CRITICAL/HIGH alerts per visual leak found across all image blocks."""
        if not self._enabled or not content_blocks:
            return []
        alerts: list[Alert] = []
        for block in content_blocks:
            for m in self._scan_block(block):
                severity = AlertSeverity.CRITICAL if m.category == "credential_leak" else AlertSeverity.HIGH
                alerts.append(
                    Alert(
                        detector=f"visual_{m.category}",
                        severity=severity,
                        message=f"Visual leak detected: {m.label} in screenshot from {tool_name}",
                        details={
                            "tool": tool_name,
                            "leak_type": m.label,
                            "category": m.category,
                            "bbox": list(m.bbox),
                        },
                    )
                )
        return alerts

    def redact(self, content_blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return a copy of ``content_blocks`` with matched regions painted over.

        Non-image blocks pass through unchanged. Blocks with no matches also
        pass through unchanged (no re-encoding, no quality loss).
        """
        if not self._enabled or not content_blocks:
            return list(content_blocks)
        out: list[dict[str, Any]] = []
        for block in content_blocks:
            if block.get("type") != _IMAGE_TYPE:
                out.append(block)
                continue
            img = _decode_image(block)
            if img is None:
                out.append(block)
                continue
            try:
                words = _extract_word_boxes(img)
            except (OSError, RuntimeError, ValueError):
                out.append(block)
                continue
            matches = _match_patterns(words, CREDENTIAL_PATTERNS, "credential_leak")
            matches.extend(_match_patterns(words, PII_PATTERNS, "pii_leak"))
            if not matches:
                out.append(block)
                continue
            painted = _paint_redactions(img, matches)
            mime = block.get(_MIMETYPE_KEY, "image/png")
            new_block = dict(block)
            new_block[_DATA_KEY] = _encode_image(painted, mime)
            new_block[_MIMETYPE_KEY] = mime
            out.append(new_block)
        return out


def _visual_leak_timeout_seconds() -> float:
    raw = os.environ.get("AGENT_BOM_VISUAL_LEAK_TIMEOUT_SECONDS", "1.5").strip()
    try:
        return max(0.1, float(raw))
    except ValueError:
        return 1.5


async def run_visual_leak_check(detector: VisualLeakDetector, tool_name: str, content_blocks: list[dict[str, Any]]) -> list[Alert]:
    timeout = _visual_leak_timeout_seconds()
    return await asyncio.wait_for(asyncio.to_thread(detector.check, tool_name, content_blocks), timeout=timeout)


async def run_visual_leak_redact(detector: VisualLeakDetector, content_blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeout = _visual_leak_timeout_seconds()
    return await asyncio.wait_for(asyncio.to_thread(detector.redact, content_blocks), timeout=timeout)


__all__ = [
    "VisualLeakDetector",
    "require_visual_leak_runtime",
    "run_visual_leak_check",
    "run_visual_leak_redact",
    "visual_leak_runtime_health",
    "visual_leak_runtime_ready",
]
