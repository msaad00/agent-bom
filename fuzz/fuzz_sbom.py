"""Atheris fuzz target for agent-bom SBOM ingestion.

Fuzzes:
1. parse_cyclonedx() — CycloneDX 1.x JSON parser
2. parse_spdx() — SPDX 2.x/3.0 JSON parser
3. load_sbom() path — end-to-end SBOM load from bytes

Both parsers accept user-supplied files from external tooling (Syft, Grype,
Trivy, etc.) and must handle malformed input safely.
"""

import json
import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from agent_bom.sbom import load_sbom, parse_cyclonedx, parse_spdx


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 2)

    if choice == 0:
        # Fuzz parse_cyclonedx with arbitrary JSON
        raw = fdp.ConsumeUnicodeNoSurrogates(2048)
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parse_cyclonedx(obj)
        except (json.JSONDecodeError, ValueError, TypeError, KeyError, AttributeError):
            pass

    elif choice == 1:
        # Fuzz parse_spdx with arbitrary JSON
        raw = fdp.ConsumeUnicodeNoSurrogates(2048)
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parse_spdx(obj)
        except (json.JSONDecodeError, ValueError, TypeError, KeyError, AttributeError):
            pass

    else:
        # Fuzz end-to-end load_sbom via a temp file
        content = fdp.ConsumeBytes(2048)
        suffix = fdp.PickValueInList([".json", ".cdx.json", ".spdx.json"])
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                f.write(content)
                tmp_path = f.name
            try:
                load_sbom(tmp_path)
            except (ValueError, KeyError, TypeError, AttributeError):
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
