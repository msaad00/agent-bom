"""Write large JSON report documents quickly with bounded peak memory."""

from __future__ import annotations

import json
from typing import Any, TextIO


def write_json_document(data: dict[str, Any], fh: TextIO) -> None:
    """Write exactly ``json.dump(data, fh, indent=2)`` followed by a newline.

    ``json.dump`` always runs the pure-Python encoder; ``json.dumps`` uses the C
    encoder. Encoding each top-level member separately keeps that speed while
    holding only the largest section in memory rather than the whole document.
    """
    if not data:
        fh.write(json.dumps(data, indent=2) + "\n")
        return
    fh.write("{\n")
    for index, (key, value) in enumerate(data.items()):
        if index:
            fh.write(",\n")
        # ``{"k": v}`` at indent=2 renders the member exactly as it appears in
        # the full document; strip the enclosing "{\n" and "\n}".
        fh.write(json.dumps({key: value}, indent=2)[2:-2])
    fh.write("\n}\n")
