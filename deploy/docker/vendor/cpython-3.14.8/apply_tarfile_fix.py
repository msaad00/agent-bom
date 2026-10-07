"""Apply the exact CPython 3.14 tarfile filter fix to the pinned 3.14.8 image."""

from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import sys
import sysconfig
import tempfile

BEFORE_SHA256 = "825de0990d0bedf6ed8db97b4a0fc98f25617a692c3d38c0bbba800beb9952fb"
AFTER_SHA256 = "82ac045a2d97396a295405268a5f14393620b0ebf50e9305e56f34731e1d89ea"
BEFORE = b"""                filter_function(
                    unfiltered.replace(name=tarinfo.name, deep=False),
                    extraction_root)
                filtered = filter_function(unfiltered, extraction_root)
"""
AFTER = b"""                filtered = filter_function(
                    unfiltered.replace(name=tarinfo.name, deep=False),
                    extraction_root)
                if filtered is None:
                    return
                filtered = filter_function(unfiltered, extraction_root)
"""


def patched_source(source: bytes) -> bytes:
    digest = hashlib.sha256(source).hexdigest()
    if digest == AFTER_SHA256:
        return source
    if digest != BEFORE_SHA256 or source.count(BEFORE) != 1:
        raise ValueError("Unexpected CPython tarfile source; review the upstream fix before changing this overlay")
    patched = source.replace(BEFORE, AFTER, 1)
    if hashlib.sha256(patched).hexdigest() != AFTER_SHA256:
        raise ValueError("Patched tarfile does not match the pinned upstream fix")
    compile(patched, "tarfile.py", "exec")
    return patched


def verify_filter_rejection() -> None:
    """A rejected regular member must stay absent during hardlink fallback."""
    import tarfile

    payload = b"bounded extraction filter regression\n"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as stream:
        target = tarfile.TarInfo("target.txt")
        target.size = len(payload)
        stream.addfile(target, io.BytesIO(payload))
        link = tarfile.TarInfo("link.txt")
        link.type = tarfile.LNKTYPE
        link.linkname = "target.txt"
        stream.addfile(link)
    archive.seek(0)
    rejected: list[str] = []

    def extraction_filter(member: tarfile.TarInfo, destination: str) -> tarfile.TarInfo | None:
        if member.isreg() and member.name == "link.txt":
            rejected.append(member.name)
            return None
        return member

    with tempfile.TemporaryDirectory() as directory:
        with tarfile.open(fileobj=archive, mode="r") as stream:
            stream.extract("link.txt", path=directory, filter=extraction_filter)
        if not rejected or pathlib.Path(directory, "link.txt").exists():
            raise ValueError("CPython tarfile ignored extraction filter rejection")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Run the behavior check without patching")
    args = parser.parse_args()
    if not args.check:
        if sys.version_info[:3] != (3, 14, 8):
            raise ValueError("This security overlay requires CPython 3.14.8; review it with the next base update")
        path = pathlib.Path(sysconfig.get_path("stdlib")) / "tarfile.py"
        source = path.read_bytes()
        patched = patched_source(source)
        if patched != source:
            path.write_bytes(patched)
    verify_filter_rejection()
    sys.stdout.write("CPython tarfile extraction filter rejection verified\n")


if __name__ == "__main__":
    main()
