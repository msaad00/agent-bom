"""Terminal encoding helpers without scanner or report-renderer imports."""


def safe_emoji(emoji: str, fallback: str = "*") -> str:
    """Return ``emoji`` only when the active stdout encoding can render it.

    On terminals/locales whose encoding cannot encode the glyph (for example a
    ``cp1252``/``ascii`` Windows console or a stripped CI locale) a raw emoji
    prints as a mojibake box or raises ``UnicodeEncodeError`` mid-line. Fall
    back to a plain ASCII marker so the line stays readable everywhere.
    """
    import sys

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        emoji.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return fallback
    return emoji
