"""Blank out comments and string literals before regex call-site extraction.

Conservative reachability analyzers must not treat identifiers mentioned inside
comments or string literals as executable call sites. A ``Class::method(`` token
inside a ``//`` comment, a quoted SQL template, or a PHP heredoc body is text,
not a call, and emitting it as a call site produces a false ``function_reachable``
verdict — the highest-confidence upgrade — at CVE join time.

Masked spans are replaced character-for-character with spaces (newlines are
preserved) so that line and column offsets of the surviving code are unchanged.
The masker is language-parameterised so regex parsers across ecosystems can
reuse it without pulling in a full lexer.
"""

from __future__ import annotations

import re

__all__ = [
    "mask_php_source",
    "mask_source",
    "mask_swift_source",
]


def _blank_preserving_newlines(text: str) -> str:
    """Replace every non-newline character with a space, keeping line count."""
    return "".join("\n" if ch == "\n" else " " for ch in text)


def _consume_heredoc(source: str, start: int) -> tuple[str, int] | None:
    """Mask a PHP heredoc/nowdoc block starting at ``<<<`` (index ``start``).

    Returns ``(masked_text, next_index)`` covering the opener through the
    closing label, or ``None`` if ``start`` is not a valid heredoc opener.
    Newlines are preserved so downstream line numbers stay accurate.
    """
    length = len(source)
    j = start + 3  # past '<<<'
    while j < length and source[j] in " \t":
        j += 1
    quote = ""
    if j < length and source[j] in "'\"":
        quote = source[j]
        j += 1
    label_start = j
    while j < length and (source[j].isalnum() or source[j] == "_"):
        j += 1
    label = source[label_start:j]
    if not label or not (source[label_start].isalpha() or source[label_start] == "_"):
        return None
    if quote and j < length and source[j] == quote:
        j += 1
    # Closing marker: line start, optional indent, the label, then a
    # non-identifier char (PHP 7.3+ allows the closing label to be indented).
    close = re.compile(r"^[ \t]*" + re.escape(label) + r"(?![A-Za-z0-9_])", re.MULTILINE)
    match = close.search(source, j)
    end = match.end() if match else length
    return _blank_preserving_newlines(source[start:end]), end


def mask_source(
    source: str,
    *,
    hash_comments: bool = False,
    heredoc: bool = False,
    nested_block_comments: bool = False,
    triple_quote: bool = False,
    quote_chars: str = "'\"",
) -> str:
    """Return ``source`` with comments and quoted literals blanked to spaces.

    Parameters
    ----------
    hash_comments:
        Also mask ``#`` line comments (PHP/Ruby/shell-adjacent). A ``#`` inside
        a string literal is *not* a comment and is left to the string handler.
    heredoc:
        Mask PHP heredoc/nowdoc (``<<<EOT`` / ``<<<'EOT'``) bodies. An
        identifier such as ``$client->request`` inside a SQL/HTML template must
        not be mistaken for a call site.
    nested_block_comments:
        Treat ``/* ... */`` as nesting (Swift). ``/* a /* b */ c */`` is a
        single comment; a non-nesting parser would stop early at the first
        ``*/`` and re-expose ``c``.
    triple_quote:
        Recognise triple-quoted (multiline) string literals (Swift). Checked
        before single-character quotes so the opener is consumed whole.
    quote_chars:
        Characters that open single-line string literals. PHP uses ``'`` and
        ``"``; Swift uses only ``"``.
    """
    result: list[str] = []
    i = 0
    length = len(source)
    state = "code"
    quote = ""
    block_depth = 0
    quotes = set(quote_chars)

    while i < length:
        char = source[i]
        nxt = source[i + 1] if i + 1 < length else ""

        if state == "code":
            if heredoc and char == "<" and source[i : i + 3] == "<<<":
                consumed = _consume_heredoc(source, i)
                if consumed is not None:
                    masked, end = consumed
                    result.append(masked)
                    i = end
                    continue
            if char == "/" and nxt == "/":
                state = "line_comment"
                result.append("  ")
                i += 2
                continue
            if char == "/" and nxt == "*":
                state = "block_comment"
                block_depth = 1
                result.append("  ")
                i += 2
                continue
            if hash_comments and char == "#":
                state = "line_comment"
                result.append(" ")
                i += 1
                continue
            if triple_quote and char == '"' and source[i : i + 3] == '"""':
                state = "triple_string"
                result.append("   ")
                i += 3
                continue
            if char in quotes:
                state = "string"
                quote = char
                result.append(" ")
                i += 1
                continue
            result.append(char)
            i += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if nested_block_comments and char == "/" and nxt == "*":
                block_depth += 1
                result.append("  ")
                i += 2
                continue
            if char == "*" and nxt == "/":
                block_depth -= 1
                result.append("  ")
                i += 2
                if block_depth <= 0:
                    state = "code"
                continue
            result.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "triple_string":
            if char == "\\" and i + 1 < length:
                result.append("\n" if nxt == "\n" else " ")
                result.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if char == '"' and source[i : i + 3] == '"""':
                state = "code"
                result.append("   ")
                i += 3
                continue
            result.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < length:
                result.append("\n" if nxt == "\n" else " ")
                result.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if char == quote:
                state = "code"
                result.append(" ")
                i += 1
                continue
            result.append("\n" if char == "\n" else " ")
            i += 1
            continue

        result.append(char)
        i += 1

    return "".join(result)


def mask_php_source(source: str) -> str:
    """Mask PHP comments (``//``, ``#``, ``/* */``), strings and heredoc/nowdoc."""
    return mask_source(source, hash_comments=True, heredoc=True, quote_chars="'\"")


def mask_swift_source(source: str) -> str:
    """Mask Swift comments (``//``, nested ``/* */``) and single/triple strings."""
    return mask_source(
        source,
        nested_block_comments=True,
        triple_quote=True,
        quote_chars='"',
    )
