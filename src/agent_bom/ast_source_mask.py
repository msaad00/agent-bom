"""Strip comments and string literals before regex call-site extraction.

Conservative reachability analyzers must not treat identifiers mentioned inside
comments or string literals as executable call sites.
"""

from __future__ import annotations

import re


def _mask_preserving_newlines(text: str) -> str:
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
    # Closing marker: line start, optional indent, the label, then a non-identifier char.
    close = re.compile(r"^[ \t]*" + re.escape(label) + r"(?![A-Za-z0-9_])", re.MULTILINE)
    match = close.search(source, j)
    end = match.end() if match else length
    return _mask_preserving_newlines(source[start:end]), end


def _closes_on_same_line(source: str, start: int, quote: str) -> bool:
    """Return whether ``quote`` opened at ``start`` is closed before the newline."""
    i = start + 1
    length = len(source)
    while i < length:
        char = source[i]
        if char == "\n":
            return False
        if char == "\\":
            i += 2
            continue
        if char == quote:
            return True
        i += 1
    return False


def mask_line_comments_and_strings(
    source: str,
    *,
    hash_comments: bool = False,
    hash_attributes: bool = False,
    heredoc: bool = False,
    backtick_strings: bool = False,
    single_line_quotes: bool = False,
) -> str:
    """Return ``source`` with comments and quoted literals replaced by spaces.

    ``hash_comments`` also masks ``#`` line comments (PHP/Ruby/Swift-adjacent).
    ``hash_attributes`` refines that for PHP, where ``#[`` opens an attribute
    rather than a comment: a ``#`` is a comment only when the next character is
    not ``[``. Without it a commented-out ``# #[McpTool(…)]`` still reads as a
    live tool registration; with plain ``hash_comments`` the real attribute
    would be masked away instead. It has no effect unless ``hash_comments``
    is also set.
    ``heredoc`` masks PHP heredoc/nowdoc (``<<<EOT`` / ``<<<'EOT'``) bodies,
    where an identifier such as ``$client->request`` inside a SQL/HTML template
    must not be mistaken for a call site.
    ``backtick_strings`` masks Go backtick-delimited raw string literals
    (``` `...` ```), where backslashes are literal and a sink token such as
    ``exec.Command`` inside the raw string must not be mistaken for a call site.
    It is opt-in because a backtick means something else in other languages
    (e.g. a Swift keyword-escaped identifier), so only Go enables it.
    ``single_line_quotes`` treats a ``'``/``"`` that is not closed on its own
    line as ordinary text rather than opening a string. JS/TS quoted strings
    cannot span a raw newline (multi-line uses backtick templates), so without
    this an apostrophe in JSX text -- ``<p>Here's the panel</p>`` -- would mask
    every real call after it.
    """
    result: list[str] = []
    i = 0
    length = len(source)
    state = "code"
    quote = ""

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
                result.extend("  ")
                i += 2
                continue
            if char == "/" and nxt == "*":
                state = "block_comment"
                result.extend("  ")
                i += 2
                continue
            if hash_comments and char == "#" and not (hash_attributes and nxt == "["):
                state = "line_comment"
                result.append(" ")
                i += 1
                continue
            if backtick_strings and char == "`":
                state = "raw_string"
                result.append(" ")
                i += 1
                continue
            if char in {"'", '"'}:
                if single_line_quotes and not _closes_on_same_line(source, i, char):
                    result.append(char)
                    i += 1
                    continue
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
            if char == "*" and nxt == "/":
                state = "code"
                result.extend("  ")
                i += 2
                continue
            result.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "raw_string":
            # Go backtick raw strings have no escapes; a literal backtick ends them.
            if char == "`":
                state = "code"
                result.append(" ")
            else:
                result.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < length:
                result.extend("  ")
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
