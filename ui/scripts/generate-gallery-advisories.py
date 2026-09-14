"""Refresh published advisory facts for simulated gallery workloads.

Run explicitly with ``uv run python ui/scripts/generate-gallery-advisories.py``.
Requires the GitHub CLI; fetches public advisories only, never runs exploits.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from packaging.specifiers import SpecifierSet

# Real historical affected releases. These are fixture inputs, not dependencies
# installed by the app or recommendations for a current production upgrade.
SCENARIOS = [
    (
        "CVE-2025-29927",
        "next",
        "15.2.2",
        "15.2.3",
        "credential-access",
        "Self-hosted application relies on Next.js middleware for authorization.",
    ),
    (
        "CVE-2024-37891",
        "urllib3",
        "2.2.1",
        "2.2.2",
        "data-leak",
        "Proxy-Authorization is supplied manually and a request redirects across origins.",
    ),
    ("CVE-2025-4565", "protobuf", "6.31.0", "6.31.1", "availability", "The pure-Python backend parses untrusted nested messages."),
    ("CVE-2020-14343", "pyyaml", "5.3", "5.4", "code-execution", "Untrusted YAML is passed to the affected full_load implementation."),
    ("CVE-2023-32681", "requests", "2.30.0", "2.31.0", "data-leak", "Requests with proxy credentials redirect to an HTTPS destination."),
    (
        "CVE-2023-50782",
        "cryptography",
        "41.0.7",
        "42.0.0",
        "data-leak",
        "RSA PKCS#1 v1.5 decryption is exposed to repeated timing measurements.",
    ),
    ("CVE-2023-45857", "axios", "1.4.0", "1.6.0", "data-leak", "Browser requests can send the XSRF token to a different origin."),
    ("CVE-2024-23334", "aiohttp", "3.9.1", "3.9.2", "file-access", "Static file serving enables follow_symlinks."),
    ("CVE-2023-43804", "urllib3", "2.0.5", "2.0.6", "data-leak", "A manually supplied Cookie header follows a cross-origin redirect."),
    (
        "CVE-2025-32434",
        "torch",
        "2.5.1",
        "2.6.0",
        "code-execution",
        "An untrusted model is loaded using the affected torch.load implementation.",
    ),
    ("CVE-2024-3651", "idna", "3.6", "3.7", "availability", "Attacker-controlled domain names reach idna.encode."),
    ("CVE-2024-47874", "starlette", "0.39.2", "0.40.0", "availability", "The service accepts untrusted multipart form data."),
    ("CVE-2022-45199", "pillow", "9.2.0", "9.3.0", "availability", "The service opens untrusted TIFF images."),
    (
        "CVE-2024-56326",
        "jinja2",
        "3.1.4",
        "3.1.5",
        "code-execution",
        "Untrusted sandboxed templates can use an indirect reference to a format method.",
    ),
    (
        "CVE-2023-36258",
        "langchain",
        "0.0.150",
        "0.0.247",
        "code-execution",
        "Untrusted prompts reach the affected PALChain Python evaluation.",
    ),
]


def main() -> None:
    rows = []
    for cve, package, version, fixed, impact, condition in SCENARIOS:
        result = subprocess.run(["gh", "api", f"/advisories?cve_id={cve}"], check=True, capture_output=True, text=True)
        advisories = json.loads(result.stdout)
        matches = [
            (advisory, affected)
            for advisory in advisories
            for affected in advisory["vulnerabilities"]
            if affected["package"]["name"].lower() == package and affected["first_patched_version"] == fixed
        ]
        if len(matches) != 1:
            raise ValueError(f"Expected one published affected package range for {cve}")
        advisory, affected = matches[0]
        bounds = SpecifierSet(affected["vulnerable_version_range"])
        if version not in bounds or fixed in bounds:
            raise ValueError(f"Scenario versions fall outside the published range for {cve}")
        scores = advisory["cvss_severities"]
        cvss = scores["cvss_v4"] if scores["cvss_v4"].get("score") else scores["cvss_v3"]
        rows.append(
            {
                "id": cve,
                "package": package,
                "version": version,
                "fixed_version": fixed,
                "ecosystem": "pypi" if affected["package"]["ecosystem"] == "pip" else affected["package"]["ecosystem"],
                "severity": advisory["severity"],
                "cvss_score": cvss["score"],
                "cvss_vector": cvss["vector_string"],
                "affected_range": affected["vulnerable_version_range"],
                "summary": advisory["summary"],
                "impact_category": impact,
                "precondition": condition,
                "reference": advisory["html_url"],
            }
        )
    destination = Path(__file__).resolve().parents[1] / "fixtures/gallery-advisories.json"
    destination.write_text(
        json.dumps(
            {
                "evidence": "Published advisories; workloads and exposure conditions are simulated, not observed exploitation.",
                "generator": "uv run python ui/scripts/generate-gallery-advisories.py",
                "advisories": rows,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
