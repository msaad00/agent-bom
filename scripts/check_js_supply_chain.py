from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_NEXT_CONFIG = REPO_ROOT / "ui" / "next.config.ts"
SDK_TSCONFIG = REPO_ROOT / "sdks" / "typescript" / "tsconfig.json"
UI_DIR = REPO_ROOT / "ui"
SDK_DIR = REPO_ROOT / "sdks" / "typescript"


def _fail(message: str) -> None:
    print(f"::error::{message}")
    raise SystemExit(1)


def _check_repo_source_maps() -> None:
    result = subprocess.run(
        ["git", "ls-files", "*.map"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    map_files = [
        Path(line.strip())
        for line in result.stdout.splitlines()
        if line.strip().startswith("ui/") or line.strip().startswith("sdks/typescript/")
    ]
    if map_files:
        rendered = ", ".join(str(path) for path in map_files[:10])
        suffix = "" if len(map_files) <= 10 else f" (+{len(map_files) - 10} more)"
        _fail(f"Unexpected JavaScript source map files found: {rendered}{suffix}")


def _check_sdk_tsconfig() -> None:
    config = json.loads(SDK_TSCONFIG.read_text())
    compiler_options = config.get("compilerOptions", {})
    if compiler_options.get("sourceMap") is not False:
        _fail("sdks/typescript/tsconfig.json must set compilerOptions.sourceMap to false")
    if compiler_options.get("declarationMap") is not False:
        _fail("sdks/typescript/tsconfig.json must set compilerOptions.declarationMap to false")


def _check_ui_config() -> None:
    text = UI_NEXT_CONFIG.read_text()
    if "productionBrowserSourceMaps: false" not in text:
        _fail("ui/next.config.ts must disable productionBrowserSourceMaps")


def main() -> int:
    _check_repo_source_maps()
    _check_sdk_tsconfig()
    _check_ui_config()
    print("JavaScript supply-chain guard checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
