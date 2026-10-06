"""Email masking that preserves validated package coordinates."""

from __future__ import annotations

import re

from agent_bom.redaction.package_coordinates import package_coordinate_spans

# Email is sensitive PII. We mask the local part and the domain label while
# preserving enough shape to keep records correlatable (first char + TLD).
# Conservative on purpose: only well-formed addresses are masked so legitimate
# non-PII fields (versions, identifiers containing "@" such as scoped npm
# package names like "@scope/pkg") are left untouched.
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+)\.([A-Za-z]{2,})\b")


def _mask_email_match(local: str, domain: str, tld: str) -> str:
    """Mask one parsed email address into ``a***@e***.com`` shape."""
    local_masked = f"{local[0]}***" if local else "***"
    domain_masked = f"{domain[0]}***" if domain else "***"
    return f"{local_masked}@{domain_masked}.{tld}"


def mask_email(value: object) -> str:
    """Mask every email address in *value*, preserving non-email text.

    ``alice@example.com`` → ``a***@e***.com``. Strings without a well-formed
    address pass through unchanged, so scoped package names (``@scope/pkg``)
    and version specifiers are not corrupted.
    """
    text = str(value)
    spans = package_coordinate_spans(text) if ":" in text else []
    return _EMAIL_RE.sub(
        lambda m: (
            m.group()
            if any(start <= m.start() and m.end() <= end for start, end in spans)
            else _mask_email_match(m.group(1), m.group(2), m.group(3))
        ),
        text,
    )


def _contains_email(value: str) -> bool:
    return bool(_EMAIL_RE.search(value)) and mask_email(value) != value
