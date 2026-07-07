"""Strip comments and string literals before regex call-site extraction.

Conservative reachability analyzers must not treat identifiers mentioned inside
comments or string literals as executable call sites.
"""

from __future__ import annotations


def mask_line_comments_and_strings(source: str, *, hash_comments: bool = False) -> str:
    """Return ``source`` with comments and quoted literals replaced by spaces."""
    result: list[str] = []
    i = 0
    length = len(source)
    state = "code"
    quote = ""

    while i < length:
        char = source[i]
        nxt = source[i + 1] if i + 1 < length else ""

        if state == "code":
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
            if hash_comments and char == "#":
                state = "line_comment"
                result.append(" ")
                i += 1
                continue
            if char in {"'", '"'}:
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
