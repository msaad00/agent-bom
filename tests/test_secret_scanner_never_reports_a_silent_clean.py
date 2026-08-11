"""A file the secret scanner did not read must not be counted as clean.

`_scan_file` returned `[]` in three situations that a caller cannot tell apart:

* the file was scanned and genuinely holds no secrets;
* the file was **larger than 1MB**, so it was never opened for scanning;
* the file raised `OSError`, so it was never read at all.

`scan_secrets` then counted every one of them in ``files_scanned``. A repo whose
only leaked credential sits in a 1.2MB ``terraform.tfstate`` — a file that
routinely exceeds 1MB and routinely holds plaintext provider credentials —
reported "42 files scanned, 0 findings". That is the false-clean class: the
scanner is most confident exactly where it looked least.

The same function already knows how to be honest about a bound it hit. Its
file-count cap appends ``"Stopped at N files"`` to ``result.warnings``. The size
cap and the read error simply never used it.

Two changes, in the order the project prefers — accuracy first, then honesty
about what is left:

* the ceiling rises from 1MB to 10MB, and the size is now checked with
  ``stat()`` before the read rather than after it, so a 1.2MB tfstate is
  actually scanned. The read is still whole-file; 10MB is the point where that
  stays reasonable.
* ``.tfstate`` and ``.tfvars`` join the scanned extensions. ``.tf`` was already
  there, so the two files in a Terraform repo most likely to hold a plaintext
  provider credential were the two never opened — a false clean independent of
  any size cap, and the reason the first test below failed twice.
* anything still skipped — over the raised ceiling, or unreadable — is named in
  ``warnings`` and excluded from ``files_scanned``, so coverage is not claimed
  for a file nobody opened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_secrets

# A real-shaped AWS key, assembled so the literal never appears in this file.
LEAKED_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def write_padded(path: Path, *, size: int, payload: str) -> None:
    """A file of *size* bytes whose last line carries *payload*."""
    filler = "# padding to make this file large\n"
    body = filler * (1 + size // len(filler))
    path.write_text(body + payload + "\n", encoding="utf-8")
    assert path.stat().st_size > size, path.stat().st_size


def test_a_secret_in_a_large_state_file_is_found(tmp_path: Path) -> None:
    """The motivating case: terraform state above the old 1MB ceiling."""
    write_padded(
        tmp_path / "terraform.tfstate",
        size=1_200_000,
        payload=f'  "access_key": "{LEAKED_KEY}",',
    )
    result = scan_secrets(tmp_path)
    assert result.total > 0, "the leaked key in a 1.2MB state file was not reported"


def test_a_small_file_is_still_scanned(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(f'{{"access_key": "{LEAKED_KEY}"}}', encoding="utf-8")
    assert scan_secrets(tmp_path).total > 0


def test_a_file_too_large_even_for_the_raised_ceiling_is_declared(tmp_path: Path) -> None:
    write_padded(tmp_path / "huge.json", size=11_000_000, payload='  "note": "x",')
    result = scan_secrets(tmp_path)
    assert any("huge.json" in warning for warning in result.warnings), result.warnings
    assert result.files_scanned == 0, "a file that was never read was counted as scanned"


def test_an_unreadable_file_is_declared_rather_than_counted_clean(tmp_path: Path) -> None:
    target = tmp_path / "locked.env"
    target.write_text(f"AWS_ACCESS_KEY_ID={LEAKED_KEY}\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        if Path(target).is_file() and _can_still_read(target):
            pytest.skip("running as a user that bypasses file permissions")
        result = scan_secrets(tmp_path)
        assert any("locked.env" in warning for warning in result.warnings), result.warnings
        assert result.files_scanned == 0
    finally:
        target.chmod(0o600)


def _can_still_read(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return True


def test_a_genuinely_clean_repo_warns_about_nothing(tmp_path: Path) -> None:
    """Honesty must not become noise: a clean scan stays clean and quiet."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    result = scan_secrets(tmp_path)
    assert result.total == 0
    assert result.warnings == []
    assert result.files_scanned == 1
