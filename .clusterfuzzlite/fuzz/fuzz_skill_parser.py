"""Atheris fuzz target for agent-bom skill file parser.

Fuzzes _parse_frontmatter() — the YAML frontmatter parser for SKILL.md files.
Skill files are user-supplied (or third-party) and fed directly into the
skill_trust tool, making the parser a high-value fuzz target.
"""

import sys

import atheris

with atheris.instrument_imports():
    import os
    import tempfile
    from pathlib import Path

    from agent_bom.parsers.skills import _parse_frontmatter, parse_skill_file


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 1)

    if choice == 0:
        # Fuzz the frontmatter parser directly with arbitrary strings
        content = fdp.ConsumeUnicodeNoSurrogates(4096)
        try:
            _parse_frontmatter(content)
        except (ValueError, TypeError, KeyError, AttributeError):
            pass

    else:
        # Fuzz full parse_skill_file via a temp file
        content = fdp.ConsumeBytes(4096)
        try:
            with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="wb") as f:
                f.write(content)
                tmp_path = f.name
            try:
                parse_skill_file(Path(tmp_path))
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeDecodeError):
                pass
            finally:
                os.unlink(tmp_path)
        except OSError:
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
