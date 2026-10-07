"""SwiftURL query aliases must preserve package identity and range boundaries."""

import pytest

from agent_bom.models import Package
from agent_bom.scanners.osv import package_lookup_names
from agent_bom.scanners.package_scan import build_vulnerabilities


def package(version="1.26.0"):
    return Package(
        name="swift-nio-http2",
        version=version,
        ecosystem="swift",
        purl=f"pkg:swift/swift-nio-http2@{version}",
        repository_url="https://github.com/apple/swift-nio-http2.git",
    )


def advisory(name="github.com/apple/swift-nio-http2"):
    return {
        "id": "GHSA-qppj-fm5r-hxr3",
        "affected": [
            {
                "package": {"name": name, "ecosystem": "SwiftURL"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.28.0"}]}],
            }
        ],
    }


def test_repository_query_alias_retains_short_name_and_stable_purl():
    pkg = package()
    assert package_lookup_names(pkg) == ["swift-nio-http2", "github.com/apple/swift-nio-http2"]
    assert pkg.name == "swift-nio-http2"
    assert pkg.purl == "pkg:swift/swift-nio-http2@1.26.0"


@pytest.mark.parametrize("name", ["github.com/apple/swift-nio-http2", "swift-nio-http2"])
def test_swift_alias_advisories_preserve_fix_and_version_exclusion(name):
    matches = build_vulnerabilities([advisory(name)], package())
    assert len(matches) == 1
    assert matches[0].fixed_version == "1.28.0"
    assert build_vulnerabilities([advisory(name)], package("1.28.0")) == []


@pytest.mark.parametrize(
    "url", ["https://token@github.com/apple/swift-nio-http2.git?secret=x#fragment", "git@github.com:apple/swift-nio-http2.git"]
)
def test_repository_query_alias_excludes_transport_credentials(url):
    pkg = package()
    pkg.repository_url = url
    assert package_lookup_names(pkg) == ["swift-nio-http2", "github.com/apple/swift-nio-http2"]
