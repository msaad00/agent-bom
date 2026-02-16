#!/usr/bin/env python3
"""
Test Vulnerability Matching Logic
Demonstrates how packages are matched to CVEs/vulnerabilities
"""

import asyncio
import json
from agent_bom.models import Package
from agent_bom.scanners import query_osv_batch, build_vulnerabilities

async def test_vulnerability_matching():
    """Test vulnerability matching with known vulnerable packages."""

    print("🧪 Testing Vulnerability Matching Logic")
    print("=" * 50)
    print()

    # Test Case 1: Known vulnerable npm package
    print("📦 Test 1: express@4.18.2 (known vulnerabilities)")
    express_pkg = Package(
        name="express",
        version="4.18.2",
        ecosystem="npm",
        purl="pkg:npm/express@4.18.2"
    )

    # Test Case 2: Another vulnerable package
    print("📦 Test 2: axios@1.6.0 (known vulnerabilities)")
    axios_pkg = Package(
        name="axios",
        version="1.6.0",
        ecosystem="npm",
        purl="pkg:npm/axios@1.6.0"
    )

    # Test Case 3: Python package with vulns
    print("📦 Test 3: flask@2.0.0 (known vulnerabilities)")
    flask_pkg = Package(
        name="flask",
        version="2.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/flask@2.0.0"
    )

    # Test Case 4: Safe package (should have no vulns)
    print("📦 Test 4: lodash@4.17.21 (patched, should be safe)")
    lodash_pkg = Package(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        purl="pkg:npm/lodash@4.17.21"
    )

    packages = [express_pkg, axios_pkg, flask_pkg, lodash_pkg]

    print("\n🔍 Querying OSV.dev API...")
    print()

    # Query OSV
    results = await query_osv_batch(packages)

    # Build vulnerabilities
    for pkg in packages:
        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        vuln_data = results.get(key, [])

        if vuln_data:
            pkg.vulnerabilities = build_vulnerabilities(vuln_data, pkg)

        print(f"📦 {pkg.name}@{pkg.version} ({pkg.ecosystem})")
        print(f"   Vulnerabilities found: {len(pkg.vulnerabilities)}")

        if pkg.vulnerabilities:
            for vuln in pkg.vulnerabilities[:3]:  # Show first 3
                print(f"   ├─ {vuln.id} ({vuln.severity.value})")
                print(f"   │  Summary: {vuln.summary[:80]}...")
                if vuln.fixed_version:
                    print(f"   │  Fix: Upgrade to {vuln.fixed_version}")
                if vuln.cvss_score:
                    print(f"   │  CVSS: {vuln.cvss_score}")

            if len(pkg.vulnerabilities) > 3:
                print(f"   └─ ...and {len(pkg.vulnerabilities) - 3} more")
        else:
            print(f"   └─ ✓ No known vulnerabilities")

        print()

    # Show JSON structure
    print("\n📄 JSON Structure Example (express@4.18.2):")
    print("-" * 50)
    if express_pkg.vulnerabilities:
        example_vuln = {
            "id": express_pkg.vulnerabilities[0].id,
            "severity": express_pkg.vulnerabilities[0].severity.value,
            "summary": express_pkg.vulnerabilities[0].summary,
            "cvss_score": express_pkg.vulnerabilities[0].cvss_score,
            "fixed_version": express_pkg.vulnerabilities[0].fixed_version,
            "references": express_pkg.vulnerabilities[0].references[:2]
        }
        print(json.dumps(example_vuln, indent=2))

    print("\n" + "=" * 50)
    print("✓ Vulnerability matching test complete!")
    print()
    print("Key Findings:")
    total_vulns = sum(len(p.vulnerabilities) for p in packages)
    print(f"  • Total packages tested: {len(packages)}")
    print(f"  • Total vulnerabilities found: {total_vulns}")
    print(f"  • Vulnerable packages: {sum(1 for p in packages if p.vulnerabilities)}")
    print(f"  • Safe packages: {sum(1 for p in packages if not p.vulnerabilities)}")
    print()
    print("🔗 Vulnerability Sources:")
    print("  • OSV.dev aggregates from:")
    print("    - National Vulnerability Database (NVD)")
    print("    - GitHub Security Advisories")
    print("    - npm Security Advisories")
    print("    - PyPI Security Advisories")
    print("    - Go Vulnerability Database")
    print("    - RustSec Advisory Database")

if __name__ == "__main__":
    asyncio.run(test_vulnerability_matching())
