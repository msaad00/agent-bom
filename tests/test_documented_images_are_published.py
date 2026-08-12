"""Every image reference we document must name a registry the release publishes to.

`check_release_consistency.py` already asserts the *version* in
`ghcr.io/msaad00/agent-bom:<version>` equals the release. It never asserted the
image exists. The result was a number kept perfectly in sync with an artifact
that had never been published: GHCR carried only a stale `latest`, while nine
OpenClaw skills told users to run a versioned tag and the hosted-demo deploy
pulled that same reference.

Consistency is not truth. This asserts the registry half.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
DEMO_WORKFLOW = ROOT / ".github" / "workflows" / "demo-deploy-cloudrun.yml"

# `owner/name` for a documented reference, ignoring the tag.
_IMAGE_REF = re.compile(r"(?P<repo>(?:ghcr\.io/)?[a-z0-9][a-z0-9._-]*/agent-bom(?:-[a-z]+)?):(?P<tag>[^\s\"'`]+)")


OWNER = "msaad00"


def _expand(text: str) -> str:
    """Resolve the one workflow expression that appears inside an image name."""
    return re.sub(r"\$\{\{\s*github\.repository_owner\s*\}\}", OWNER, text)


def _published_repositories() -> set[str]:
    """Every image repository the release workflow actually pushes to."""
    text = _expand(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    published: set[str] = set()
    for line in text.splitlines():
        # `tags:` block entries are bare `repo:tag` lines.
        match = _IMAGE_REF.fullmatch(line.strip())
        if match:
            published.add(match.group("repo"))
    return published


def test_release_publishes_the_image_the_demo_deploy_pulls() -> None:
    published = _published_repositories()
    demo = _expand(DEMO_WORKFLOW.read_text(encoding="utf-8"))
    match = re.search(r"^\s*image:\s*(\S+?):\$\{\{", demo, re.M)
    assert match, "demo deploy no longer names an image to pull"
    pulled = match.group(1)
    assert pulled in published, (
        f"the hosted demo deploys {pulled!r}, which the release workflow never pushes. Published: {sorted(published)}"
    )


def test_documented_image_references_name_a_published_registry() -> None:
    published = _published_repositories()
    offenders: list[str] = []
    for path in sorted(ROOT.glob("integrations/openclaw/**/SKILL.md")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for match in _IMAGE_REF.finditer(line):
                repo = match.group("repo")
                if repo not in published:
                    offenders.append(f"{path.relative_to(ROOT)}:{number} -> {repo}")
    assert not offenders, (
        "documented image references name a registry the release does not publish to:\n  "
        + "\n  ".join(offenders)
        + f"\nPublished: {sorted(published)}"
    )
