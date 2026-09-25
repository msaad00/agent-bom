#!/usr/bin/env python3
"""Bump agent-bom version across all files in one command.

Usage:
    python scripts/bump-version.py 0.29.0                # prepare the next release
    python scripts/bump-version.py 0.29.0 --dry-run
    python scripts/bump-version.py --published 0.29.0    # after 0.29.0 is published
    python scripts/bump-version.py 0.29.0 --check        # CI drift gate

User-facing copy-paste surfaces track PUBLISHED_VERSION, not the source version,
so docs on main never point at a tag or image that does not exist yet. See
scripts/check_version_alignment.py for the split.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every file + regex pattern that contains the version string.
# Each entry: (relative_path, compiled_regex, replacement_template)
# The replacement_template uses \g<1> for the prefix capture group.
VERSION_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # Core
    ("pyproject.toml", re.compile(r'^(version\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("src/agent_bom/__init__.py", re.compile(r'(__version__\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Dockerfiles
    ("deploy/docker/Dockerfile.runtime", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.sse", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.mcp", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.collector", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    # MCP Registry server.json (version field + pypi identifier version)
    ("integrations/mcp-registry/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("integrations/glama/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Snowpark Dockerfile
    ("deploy/docker/Dockerfile.snowpark", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.native-app", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("Dockerfile", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    # Compose + packaged manifests
    ("deploy/docker-compose.runtime-example.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/docker-compose.fullstack.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/docker-compose.platform.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    # Helm chart — both chart `version:` and `appVersion:` track the platform release
    ("deploy/helm/agent-bom/Chart.yaml", re.compile(r"^(version:\s*)\S+", re.M), r"\g<1>{v}"),
    ("deploy/helm/agent-bom/Chart.yaml", re.compile(r'^(appVersion:\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("deploy/helm/agent-bom/values.yaml", re.compile(r'^(\s*tag:\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Frontend package — UI version tracks the platform release so the docker image and
    # the Next.js build manifest agree on what version is shipping
    ("ui/package.json", re.compile(r'^(\s*"version":\s*")[^"]+(",?)', re.M), r"\g<1>{v}\g<2>"),
    (
        "ui/package-lock.json",
        re.compile(r'(\A\{\n  "name": "ui",\n  "version": ")[^"]+(")', re.M),
        r"\g<1>{v}\g<2>",
    ),
    (
        "ui/package-lock.json",
        re.compile(r'(\n    "": \{\n      "name": "ui",\n      "version": ")[^"]+(")', re.M),
        r"\g<1>{v}\g<2>",
    ),
    ("uv.lock", re.compile(r'(\[\[package\]\]\nname = "agent-bom"\nversion = ")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # `agent-bom-sdk` is a thin alias that re-exports the packaged control-plane
    # client, so it ships the platform's version. It was bumped by hand once and
    # then forgotten, drifting to 0.92.0 while the platform reached 0.100.0.
    # scripts/check_release_consistency.py now sweeps for this structurally; this
    # entry is the writer half, so the sweep has nothing to catch.
    ("sdks/python/pyproject.toml", re.compile(r'^(version\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
]

OPENCLAW_SKILL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("integrations/openclaw/**/SKILL.md", re.compile(r"^(version:\s*)\S+", re.M), r"\g<1>{v}"),
    ("integrations/openclaw/**/SKILL.md", re.compile(r"(ghcr\.io/msaad00/agent-bom:)\S+"), r"\g<1>{v}"),
    ("integrations/openclaw/**/SKILL.md", re.compile(r"(agent-bom verify agent-bom@)[^`\s]+(`)"), r"\g<1>{v}\g<2>"),
]

# Patterns that reference the version in docs/tests (updated separately)
DOC_TEST_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # README.md + docs — GitHub Action version references
    (
        "README.md",
        re.compile(r"(CLI walkthrough</b> — )\d+\.\d+\.\d+( console demo</summary>)"),
        r"\g<1>{v}\g<2>",
    ),
    (
        "deploy/snowflake/native-app/manifest.yml",
        re.compile(r"(:v)\d+_\d+_\d+"),
        r"\g<1>{v_underscore}",
    ),
    (
        "deploy/snowflake/native-app/manifest.yml",
        re.compile(r"^(  name: v)\d+_\d+_\d+$", re.M),
        r"\g<1>{v_underscore}",
    ),
    (
        "deploy/snowflake/native-app/manifest.yml",
        re.compile(r'^(  label: "agent-bom )\d+\.\d+\.\d+("$)', re.M),
        r"\g<1>{v}\g<2>",
    ),
    (
        "deploy/snowflake/native-app/service-spec.yaml",
        re.compile(r"(:v)\d+_\d+_\d+"),
        r"\g<1>{v_underscore}",
    ),
    (
        "deploy/snowflake/native-app/service-specs/scanner-service.yaml",
        re.compile(r"(:v)\d+_\d+_\d+"),
        r"\g<1>{v_underscore}",
    ),
    (
        "deploy/snowflake/native-app/service-specs/mcp-runtime-service.yaml",
        re.compile(r"(:v)\d+_\d+_\d+"),
        r"\g<1>{v_underscore}",
    ),
    ("docs/PRODUCT_METRICS.md", re.compile(r"(- Version: `)\d+\.\d+\.\d+(`)"), r"\g<1>{v}\g<2>"),
    ("docs/PRODUCT_METRICS.json", re.compile(r'("version":\s*")\d+\.\d+\.\d+(")'), r"\g<1>{v}\g<2>"),
    (
        "docs/images/product-screenshots.json",
        re.compile(r'("release_version":\s*")\d+\.\d+\.\d+(")'),
        r"\g<1>{v}\g<2>",
    ),
    # The storefront row carries one of TWO phrasings depending on where the
    # release is: lifecycle-neutral before the image is published, "Current
    # stable version (pinned)" after. Matching only the published phrasing meant
    # a pre-release bump silently skipped this file, and the drift surfaced as a
    # `check_release_consistency` failure at tag time instead of being fixed by
    # the bump that was supposed to own it.
    ("DOCKER_HUB_README.md", re.compile(r"(\| `)\d+\.\d+\.\d+(` \| Current stable version \(pinned\) \|)"), r"\g<1>{v}\g<2>"),
    (
        "DOCKER_HUB_README.md",
        re.compile(r"(\| `)\d+\.\d+\.\d+(` \| Version used by the examples below; verify registry availability before pinning \|)"),
        r"\g<1>{v}\g<2>",
    ),
    # PUBLISHING.md — version examples
    ("docs/PUBLISHING.md", re.compile(r'(--version\s+")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("docs/PUBLISHING.md", re.compile(r"(--expected\s+)\d+\.\d+\.\d+", re.M), r"\g<1>{v}"),
    ("docs/PUBLISHING.md", re.compile(r"(git tag v)\S+", re.M), r"\g<1>{v}"),
    ("docs/PUBLISHING.md", re.compile(r"(git push origin v)\S+", re.M), r"\g<1>{v}"),
    ("ui/tests/nav.test.tsx", re.compile(r"(version:\s*')\d+\.\d+\.\d+(')"), r"\g<1>{v}\g<2>"),
    ("site-docs/reference/remediate-output.md", re.compile(r'("version":\s*")\d+\.\d+\.\d+(")'), r"\g<1>{v}\g<2>"),
    # docs/demo.tape — version header
    ("docs/demo.tape", re.compile(r"^(# agent-bom v)\d+\.\d+\.\d+(\s+.*demo.*)$", re.M), r"\g<1>{v}\g<2>"),
]

# Copy-paste commands that fetch a released artifact (chart, bundle, tag
# archive) and therefore must name the latest PUBLISHED release, never the
# unreleased source version on main. Action refs, pull-only image pins,
# consumer pre-commit revs and README's "Latest release" line are covered
# structurally by the check_version_alignment sweep instead of listed here.
PUBLISHED_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    ("site-docs/deployment/control-plane-helm.md", re.compile(r"(--version\s+)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("docs/RELEASE_VERIFICATION.md", re.compile(r"^(TAG=v)\d+\.\d+\.\d+$", re.M), r"\g<1>{v}"),
    (
        "site-docs/deployment/airgapped-image-bundle.md",
        re.compile(
            r"(?:"
            r"(--version\s+)|"
            r"(agent-bom-airgap-)|"
            r"(VERSION=)|"
            r"(tag:\s*\")|"
            r"(agent-bom-ui:\")"
            r")\d+\.\d+\.\d+"
        ),
        r"\g<1>\g<2>\g<3>\g<4>\g<5>{v}",
    ),
    (
        "site-docs/deployment/aws-company-rollout.md",
        re.compile(r"((?:--version\s+|refs/tags/v))\d+\.\d+\.\d+"),
        r"\g<1>{v}",
    ),
]

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _load_alignment():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_version_alignment as cva

    return cva


def _apply(locations: list[tuple[str, re.Pattern, str]], version: str, *, dry_run: bool, check: bool) -> int:
    underscore_version = version.replace(".", "_")
    changed = 0
    for rel_path, pattern, template in locations:
        path = ROOT / rel_path
        if not path.exists():
            print(f"  SKIP (not found): {rel_path}")
            continue

        text = path.read_text()
        replacement = template.format(v=version, v_underscore=underscore_version)
        new_text, count = pattern.subn(replacement, text)

        if count == 0:
            print(f"  WARN (no match):  {rel_path}  pattern={pattern.pattern!r}")
        elif new_text == text:
            print(f"  OK (already {version}): {rel_path}")
        else:
            changed += count
            if dry_run or check:
                print(f"  {'DRIFT' if check else 'DRY-RUN'} ({count} hit): {rel_path}")
            else:
                path.write_text(new_text)
                print(f"  UPDATED ({count} hit): {rel_path}")
    return changed


def bump(
    new_version: str | None = None,
    *,
    published: str | None = None,
    dry_run: bool = False,
    check: bool = False,
) -> int:
    """Align the source version and/or the published version across tracked files.

    ``new_version`` is the release being PREPARED (pyproject, images built from
    this tree, chart, manifests). ``published`` is the latest release that
    actually EXISTS; only the release run advances it, after publishing.
    Whichever one is omitted is read from the repository as-is.
    """
    cva = _load_alignment()
    source = new_version or cva.canonical_version()
    target_published = published or cva.published_version()
    for label, value in (("version", source), ("published version", target_published)):
        if not _SEMVER.match(value):
            print(f"ERROR: Invalid semver for {label}: {value}", file=sys.stderr)
            return 1
    if cva.parse_semver(target_published) > cva.parse_semver(source):
        print(f"ERROR: published version {target_published} is ahead of the source version {source}", file=sys.stderr)
        return 1

    source_locations = VERSION_LOCATIONS + DOC_TEST_LOCATIONS
    for glob_pattern, pattern, template in OPENCLAW_SKILL_PATTERNS:
        for path in sorted(ROOT.glob(glob_pattern)):
            text = path.read_text()
            if pattern.search(text):
                source_locations.append((str(path.relative_to(ROOT)), pattern, template))

    changed = _apply(source_locations, source, dry_run=dry_run, check=check)
    changed += _apply(PUBLISHED_LOCATIONS, target_published, dry_run=dry_run, check=check)

    published_file = cva.PUBLISHED_VERSION_FILE
    current_published = published_file.read_text(encoding="utf-8").strip() if published_file.exists() else ""
    if current_published != target_published:
        changed += 1
        if dry_run or check:
            print(f"  {'DRIFT' if check else 'DRY-RUN'}: {published_file.name} {current_published or '<missing>'} -> {target_published}")
        else:
            published_file.write_text(f"{target_published}\n", encoding="utf-8")
            print(f"  UPDATED: {published_file.name} -> {target_published}")

    # Structural sweep: align every managed image pin / GitHub Action ref across
    # the whole shipping-surface tree (deploy + docs + site-docs + integrations),
    # so files not enumerated above — or added in a future release — can never
    # silently drift. This is the same scan the CI version-alignment gate runs.
    if dry_run or check:
        sweep_drift = cva.find_drift(source, published=target_published)
        for line in sweep_drift:
            print(f"  {'DRIFT' if check else 'DRY-RUN'} (align sweep): {line}")
        changed += len(sweep_drift)
    else:
        sweep_count, sweep_files = cva.rewrite(source, published=target_published)
        for path in sweep_files:
            print(f"  UPDATED (align sweep): {path.relative_to(ROOT)}")
        changed += sweep_count

    # ``--check`` writes nothing, so reporting "Updated N" for it described work
    # that did not happen — during a release that reads as "the bump is done."
    verb = "Would update" if (dry_run or check) else "Updated"
    print(f"\n{verb} {changed} occurrence(s)")

    if check:
        if changed > 0:
            print(
                f"\nERROR: release-managed files drift from source {source} / published {target_published}. "
                f"Run: python scripts/bump-version.py {source} --published {target_published}",
                file=sys.stderr,
            )
            return 1
        return 0

    if not dry_run and changed > 0 and new_version:
        print("\nNext steps:")
        print(f"  git add -A && git commit -m 'chore: bump version to {new_version}'")
        print(f"  git tag v{new_version}")
        print(f"  git push origin main v{new_version}")
        print(f"  (after the release publishes, the release run opens a PR running: bump-version.py --published {new_version})")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Bump agent-bom version everywhere")
    parser.add_argument("version", nargs="?", help="Source version being prepared (e.g. 0.29.0)")
    parser.add_argument(
        "--published",
        metavar="VERSION",
        help="Latest release that is actually published; only advance after the release exists",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    parser.add_argument("--check", action="store_true", help="Fail if managed files are not already aligned")
    args = parser.parse_args()
    if not args.version and not args.published:
        parser.error("give a source VERSION, --published VERSION, or both")
    sys.exit(bump(args.version, published=args.published, dry_run=args.dry_run, check=args.check))


if __name__ == "__main__":
    main()
