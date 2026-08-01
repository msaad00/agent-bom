"""Shared Unicode folding for adversarial text.

Detection already normalized text before matching (tool-poisoning scans in
``agent_bom.enforcement``, prompt-injection scans in
``agent_bom.parsers.prompt_scanner``). Enforcement did not, so a look-alike
tool name walked past the policy engine that was meant to stop it.

The folds live here so all three read the same definition. Nothing in this
module imports from the rest of the package: it is a leaf, safe to import from
the policy engine, the scanners, and the gateway alike.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width and invisible characters commonly used for evasion.
INVISIBLE_RE = re.compile(r"[​‌‍‎‏⁠⁡⁢⁣⁤﻿­͏ᅟᅠ឴឵]")

# Cyrillic/Greek/other script confusables → Latin. Unicode normalization does
# not fold these: they are distinct letters that merely *look* identical.
HOMOGLYPHS = {
    ord(src): dst
    for src, dst in {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ո": "n",
        "һ": "h",
        "ɡ": "g",
        "ⅼ": "l",
        "α": "a",
        "ε": "e",
        "ο": "o",
        "ρ": "p",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "τ": "t",
    }.items()
}


def normalize_text(text: str) -> str:
    """Strip invisible characters and apply NFKD.

    Decomposes ligatures and folds fullwidth forms. Script confusables are left
    alone — this projection is used for pattern scanning, where folding letters
    across scripts would broaden the patterns themselves.
    """
    return unicodedata.normalize("NFKD", INVISIBLE_RE.sub("", text))


def normalize_identifier(name: str) -> str:
    """Fold a tool/identifier name to its canonical comparison form.

    Adds confusable folding and case folding on top of :func:`normalize_text`,
    because an identifier is compared for equality rather than scanned for
    patterns: ``dеlete_file`` (Cyrillic ``е``) and ``ｄｅｌｅｔｅ_file`` name the
    same tool as ``delete_file`` and must be governed as such.

    Only ever widen a DENY with this. Folding both sides of an *allowlist*
    comparison would let a look-alike unlock the tool the operator allowed.

    Case folding runs before the confusable table so an uppercase look-alike
    (``Е``, U+0415) folds through its lowercase form; the table only needs the
    lowercase mapping.
    """
    return normalize_text(name).casefold().translate(HOMOGLYPHS)
