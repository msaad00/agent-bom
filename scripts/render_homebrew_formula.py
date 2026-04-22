"""Render a Homebrew formula for agent-bom release packaging."""

from __future__ import annotations

import argparse
from pathlib import Path


def render_formula(*, version: str, url: str, sha256: str) -> str:
    return f"""class AgentBom < Formula
  desc "Security scanner for AI infrastructure"
  homepage "https://github.com/msaad00/agent-bom"
  url "{url}"
  sha256 "{sha256}"
  license "Apache-2.0"
  depends_on "python@3.13"

  def install
    system Formula["python@3.13"].opt_bin/"python3.13", "-m", "pip", "install", *std_pip_args(build_isolation: true), "."
  end

  test do
    assert_match "{version}", shell_output("#{{bin}}/agent-bom --version")
  end
end
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    formula = render_formula(version=args.version, url=args.url, sha256=args.sha256)
    if args.output:
        args.output.write_text(formula, encoding="utf-8")
    else:
        print(formula)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
