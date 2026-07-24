"""Export-side sanitization for published advisory prose.

Advisory text — OSV/NVD vulnerability summaries, CIS benchmark remediation
guidance, IaC rule messages — is upstream *published* data. It is not captured
runtime evidence, so it must not be routed through
:func:`agent_bom.evidence.redact_for_persistence`: that redactor's tier-A
allowlist protects the runtime-capture path by dropping every field name it
does not recognise, and ``description`` / ``recommendation`` are deliberately
absent from it. Sending advisory prose through it discarded the text wholesale.

Export still needs defensive redaction, so this module applies it directly:
credential-shaped substrings, credentials and query strings inside URLs,
absolute filesystem paths, e-mail addresses, control characters, and disguised
Markdown links are removed, and the result is length-capped.

The split is by provenance, not by output format. Scanner free text that can
quote the repository being scanned — SAST and secret finding descriptions,
model-authored triage rationale — is *not* advisory prose and keeps the
conservative allowlist at its own call sites.
"""

from __future__ import annotations

import re
from typing import Any

from agent_bom.security import sanitize_path_label, sanitize_sensitive_payload

ADVISORY_TEXT_MAX_LEN = 1000
ADVISORY_HELP_MAX_LEN = 4000

# Absolute filesystem paths embedded mid-sentence are scanning-host detail, not
# published advisory content. The lookbehind keeps URL paths (preceded by ``:``
# or ``/``) and relative traversal such as ``../../etc/passwd`` intact, and the
# ``{2,}`` floor keeps single generic roots like ``/tmp`` readable.
_EMBEDDED_ABSOLUTE_PATH_RE = re.compile(r"(?<![\w:/~.\-])(?:(?:/[\w.\-+@]+){2,}/?|[A-Za-z]:[\\/][\w.\-+@]+(?:[\\/][\w.\-+@]+)*)")

# A Markdown link lets an advisory render arbitrary text over an attacker-chosen
# target in GitHub's alert pane. Keep the label, drop the target; a bare URL is
# left alone because the reader can see where it points.
_MARKDOWN_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")

# Only an http(s) URI with no Markdown-significant characters is safe to inline
# as a link target; anything else would let the target break out of ``(...)``.
_SAFE_LINK_URI_RE = re.compile(r"https?://[^\s()\[\]<>\"'\\]+\Z")


def sanitize_advisory_text(
    field_name: str,
    value: Any,
    *,
    fallback: str = "",
    max_len: int = ADVISORY_TEXT_MAX_LEN,
) -> str:
    """Return *value* as advisory prose that is safe to publish in an export.

    ``field_name`` is passed to :func:`sanitize_sensitive_payload` as a key hint
    so URL-, path-, and secret-named fields get their stricter treatment.
    Returns *fallback* when nothing survives sanitization.
    """
    sanitized = sanitize_sensitive_payload(str(value or ""), key=field_name, max_str_len=max_len)
    text = _EMBEDDED_ABSOLUTE_PATH_RE.sub(lambda match: sanitize_path_label(match.group(0)), str(sanitized))
    text = _MARKDOWN_LINK_RE.sub(r"\1", text).strip()
    return text[:max_len] if text else fallback


def advisory_help(
    description: str,
    *,
    remediation: str = "",
    reference_uri: str = "",
    max_len: int = ADVISORY_HELP_MAX_LEN,
) -> dict[str, str] | None:
    """Build a SARIF ``help`` object, or ``None`` when there is nothing to say.

    SARIF 2.1.0 §3.49.13 defines ``reportingDescriptor.help`` as a
    multiformatMessageString (``text`` required, ``markdown`` optional); GitHub
    code scanning renders it as the alert detail pane. *description* and
    *remediation* must already be sanitized. *reference_uri* becomes the only
    link in the pane, and is dropped unless it is a plain http(s) URI — an
    upstream-supplied target carrying ``)`` would otherwise break out of the
    Markdown link and render an advisory-controlled one.
    """
    body = (description or "").strip()
    if not body:
        return None
    plain = [body]
    markdown = [body]
    fix = (remediation or "").strip()
    if fix and fix != body:
        plain.append(f"Remediation: {fix}")
        markdown.append(f"**Remediation:** {fix}")
    reference = (reference_uri or "").strip()
    if _SAFE_LINK_URI_RE.fullmatch(reference):
        plain.append(f"Reference: {reference}")
        markdown.append(f"[Reference]({reference})")
    return {
        "text": "\n\n".join(plain)[:max_len],
        "markdown": "\n\n".join(markdown)[:max_len],
    }
