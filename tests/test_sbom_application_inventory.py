"""SPDX package purpose is not permission to discard software inventory."""

import json

import pytest

from agent_bom.parsers.sbom_context import load_sbom_agents
from agent_bom.sbom import parse_cyclonedx, parse_spdx


@pytest.mark.parametrize("version", ["2.3", "3.0.1"])
@pytest.mark.parametrize("purl", [None, "pkg:pypi/jinja2@2.10"])
def test_spdx_application_packages_survive_import(tmp_path, version, purl):
    if version == "2.3":
        package = {"SPDXID": "SPDXRef-jinja2", "name": "jinja2", "versionInfo": "2.10", "primaryPackagePurpose": "APPLICATION"}
        if purl:
            package["externalRefs"] = [{"referenceType": "purl", "referenceLocator": purl}]
        document = {"spdxVersion": "SPDX-2.3", "packages": [package]}
    else:
        package = {
            "type": "software_Package",
            "spdxId": "SPDXRef-jinja2",
            "name": "jinja2",
            "software_packageVersion": "2.10",
            "software_primaryPurpose": "application",
        }
        if purl:
            package["software_packageUrl"] = purl
        document = {"spdxVersion": "SPDX-3.0.1", "elements": [package]}
    packages = parse_spdx(document)
    assert [(p.name, p.version, p.purl) for p in packages] == [("jinja2", "2.10", purl)]
    counterpart = parse_cyclonedx(
        {
            "bomFormat": "CycloneDX",
            "components": [{"type": "application", "name": "jinja2", "version": "2.10", **({"purl": purl} if purl else {})}],
        }
    )
    assert [(p.name, p.version, p.purl) for p in counterpart] == [(p.name, p.version, p.purl) for p in packages]
    path = tmp_path / "application.spdx.json"
    path.write_text(json.dumps(document))
    agents, _ = load_sbom_agents(str(path))
    assert [(p.name, p.version) for a in agents for s in a.mcp_servers for p in s.packages] == [("jinja2", "2.10")]


def test_context_description_does_not_discard_a_package_url():
    packages = parse_spdx(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-package",
                    "name": "jinja2",
                    "versionInfo": "2.10",
                    "primaryPackagePurpose": "APPLICATION",
                    "comment": "MCP Server (stdio)",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/jinja2@2.10"}],
                }
            ],
        }
    )
    assert [(p.name, p.ecosystem, p.version) for p in packages] == [("jinja2", "pypi", "2.10")]
