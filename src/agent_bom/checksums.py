"""Pure helpers for package checksum / integrity normalization.

Used by lockfile parsers to capture per-component integrity and by the SBOM
emitters (CycloneDX, SPDX 2.x, SPDX 3.0) to surface those checksums in the
shape each standard expects. No network or heavy imports — keep it cheap so
hot parser paths can import it freely.

Canonical algorithm labels use the CycloneDX dashed style (e.g. ``SHA-256``).
The emitters translate to the per-standard spelling.
"""

from __future__ import annotations

import base64
import binascii
import re

# Expected lowercase-hex digest length per algorithm (used to reject garbage).
_HEX_LEN_BY_ALG = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-224": 56,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
}

# Map a variety of caller spellings to the canonical dashed label.
_ALG_ALIASES = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "shasum": "SHA-1",  # npm registry "shasum" is a SHA-1 hex digest
    "sha224": "SHA-224",
    "sha-224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SRI_TOKEN_RE = re.compile(r"^(sha512|sha384|sha256|sha1)-(.+)$")


def canonical_algorithm(name: str) -> str | None:
    """Return the canonical dashed algorithm label, or ``None`` if unknown."""
    return _ALG_ALIASES.get((name or "").strip().lower().replace("_", "-"))


def add_checksum(checksums: dict[str, str], algorithm: str, value: str) -> None:
    """Validate and store a hex digest under its canonical algorithm key.

    Silently ignores unknown algorithms, non-hex values, or values whose
    length does not match the algorithm — keeping SBOM output trustworthy.
    """
    alg = canonical_algorithm(algorithm)
    if alg is None:
        return
    hexval = (value or "").strip().lower()
    if not hexval or not _HEX_RE.match(hexval):
        return
    expected = _HEX_LEN_BY_ALG.get(alg)
    if expected is not None and len(hexval) != expected:
        return
    checksums[alg] = hexval


def parse_sri(integrity: str) -> dict[str, str]:
    """Parse a Subresource Integrity string into ``{algorithm: hex}``.

    SRI values (npm/yarn/pnpm lockfiles) look like ``sha512-<base64>`` and may
    contain several space-separated tokens. The base64 payload is decoded to a
    lowercase hex digest. Malformed tokens are skipped.
    """
    out: dict[str, str] = {}
    for token in (integrity or "").split():
        match = _SRI_TOKEN_RE.match(token.strip())
        if not match:
            continue
        alg_raw, b64 = match.group(1), match.group(2)
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            continue
        add_checksum(out, alg_raw, raw.hex())
    return out


def cyclonedx_hashes(checksums: dict[str, str]) -> list[dict[str, str]]:
    """Render checksums as CycloneDX ``hashes`` entries (dashed ``alg``)."""
    return [{"alg": alg, "content": value} for alg, value in sorted(checksums.items()) if alg in _HEX_LEN_BY_ALG]


def spdx2_checksums(checksums: dict[str, str]) -> list[dict[str, str]]:
    """Render checksums as SPDX 2.x ``checksums`` entries (no-dash algorithm)."""
    return [
        {"algorithm": alg.replace("-", ""), "checksumValue": value} for alg, value in sorted(checksums.items()) if alg in _HEX_LEN_BY_ALG
    ]


def spdx3_verified_using(checksums: dict[str, str]) -> list[dict[str, str]]:
    """Render checksums as SPDX 3.0 ``verifiedUsing`` Hash objects."""
    return [
        {"type": "Hash", "algorithm": alg.replace("-", "").lower(), "hashValue": value}
        for alg, value in sorted(checksums.items())
        if alg in _HEX_LEN_BY_ALG
    ]
