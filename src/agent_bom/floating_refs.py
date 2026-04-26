"""Shared floating-reference policy helpers.

Mutable package, image, and model references are useful during development but
weak evidence for security review. These helpers classify the posture without
blocking discovery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FLOATING_TAGS = frozenset(
    {
        "latest",
        "main",
        "master",
        "dev",
        "develop",
        "stable",
        "current",
        "edge",
        "nightly",
        "snapshot",
        "canary",
        "rolling",
    }
)

_HEX_DIGEST_RE = re.compile(r"^[a-fA-F0-9]{40,128}$")


@dataclass(frozen=True)
class FloatingReferenceFinding:
    """Policy finding for a mutable reference."""

    reference: str
    reference_type: str
    reason: str
    severity: str = "MEDIUM"

    @property
    def type(self) -> str:
        return f"FLOATING_{self.reference_type.upper()}_REFERENCE"

    def to_security_warning(self) -> str:
        return f"{self.type}: {self.reference} is mutable ({self.reason}); pin to an immutable digest or commit."

    def to_security_flag(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "type": self.type,
            "reference": self.reference,
            "reference_type": self.reference_type,
            "description": f"{self.reference} is mutable ({self.reason}); pin to an immutable digest or commit.",
        }


def is_hex_digest(value: str | None) -> bool:
    """Return True for git/SHA-style immutable refs."""

    return bool(value and _HEX_DIGEST_RE.fullmatch(value.strip()))


def classify_image_reference(reference: str | None) -> FloatingReferenceFinding | None:
    """Classify mutable OCI/Docker image references.

    A digest reference is immutable. A missing tag implies ``latest``. Known
    moving tags such as ``latest`` and ``main`` are treated as floating.
    """

    if not reference:
        return None
    ref = reference.strip()
    if not ref:
        return None
    if "@sha256:" in ref:
        return None

    tail = ref.rsplit("/", 1)[-1]
    if ":" not in tail:
        return FloatingReferenceFinding(ref, "image", "implicit latest tag")

    tag = tail.rsplit(":", 1)[1].strip().lower()
    if tag in FLOATING_TAGS:
        return FloatingReferenceFinding(ref, "image", f"moving tag '{tag}'")
    return None


def classify_model_revision(reference: str | None, revision: str | None = None) -> FloatingReferenceFinding | None:
    """Classify mutable model revisions.

    Hugging Face and similar model registries allow branches/tags. We only
    flag explicit mutable branch-style values here; missing revisions may be
    lineage metadata rather than a fetch instruction.
    """

    if not reference or not revision:
        return None
    ref = reference.strip()
    rev = revision.strip()
    if not ref or not rev or is_hex_digest(rev):
        return None
    if rev.lower() in FLOATING_TAGS:
        return FloatingReferenceFinding(f"{ref}@{rev}", "model", f"moving revision '{rev}'")
    return None
