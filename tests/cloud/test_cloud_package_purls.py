from __future__ import annotations

import io
import sys
import types
import zipfile
from types import SimpleNamespace
from unittest.mock import patch


def test_cloud_package_purl_encodes_scoped_npm_and_skips_unknown() -> None:
    from agent_bom.cloud.normalization import build_package_purl

    assert build_package_purl(ecosystem="npm", name="@types/node", version="22.0.0") == "pkg:npm/%40types/node@22.0.0"
    assert build_package_purl(ecosystem="container-image", name="gcr.io/acme/app/worker", version="v1.2.3") == (
        "pkg:docker/gcr.io/acme/app/worker@v1.2.3"
    )
    assert build_package_purl(ecosystem="azure-runtime", name="python", version="3.11") == "pkg:generic/python@3.11"
    assert build_package_purl(ecosystem="pypi", name="requests", version="unknown") is None
    assert build_package_purl(ecosystem="azure-runtime", name="python", version="0.0") is None


def test_aws_zip_package_parsers_emit_purls() -> None:
    from agent_bom.cloud.aws import _parse_node_packages_from_zip, _parse_python_packages_from_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("python/Requests_OAuthlib-1.3.0.dist-info/METADATA", "Name: Requests_OAuthlib\nVersion: 1.3.0\n")
        zf.writestr("nodejs/node_modules/@types/node/package.json", '{"name": "@types/node", "version": "22.0.0"}')

    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        pypi_pkg = _parse_python_packages_from_zip(zf)[0]
        npm_pkg = _parse_node_packages_from_zip(zf)[0]

    assert pypi_pkg.purl == "pkg:pypi/requests-oauthlib@1.3.0"
    assert npm_pkg.purl == "pkg:npm/%40types/node@22.0.0"


def test_azure_function_runtime_package_has_purl() -> None:
    from agent_bom.cloud.azure import _discover_azure_functions

    app = SimpleNamespace(
        name="fn",
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/fn",
        kind="functionapp,linux",
        location="eastus",
    )
    config = SimpleNamespace(linux_fx_version="PYTHON|3.11")
    web_apps = SimpleNamespace(list=lambda: [app], get_configuration=lambda _rg, _app: config)
    client = SimpleNamespace(web_apps=web_apps)

    azure_web = types.ModuleType("azure.mgmt.web")
    setattr(azure_web, "WebSiteManagementClient", lambda _credential, _subscription_id: client)

    with patch.dict(
        sys.modules, {"azure": types.ModuleType("azure"), "azure.mgmt": types.ModuleType("azure.mgmt"), "azure.mgmt.web": azure_web}
    ):
        agents, warnings = _discover_azure_functions(object(), "sub")

    assert warnings == []
    pkg = agents[0].mcp_servers[0].packages[0]
    assert pkg.purl == "pkg:generic/python@3.11"


def test_gcp_cloud_run_container_package_has_purl() -> None:
    from agent_bom.cloud.gcp import _discover_cloud_run

    container = SimpleNamespace(image="us-docker.pkg.dev/acme/app/worker:v1.2.3")
    template = SimpleNamespace(containers=[container], service_account="worker@acme.iam.gserviceaccount.com")
    service = SimpleNamespace(name="projects/acme/locations/us-central1/services/worker", template=template)
    client = SimpleNamespace(list_services=lambda parent: [service])

    run_v2 = types.ModuleType("google.cloud.run_v2")
    setattr(run_v2, "ServicesClient", lambda: client)

    with patch.dict(
        sys.modules,
        {
            "google": types.ModuleType("google"),
            "google.cloud": types.ModuleType("google.cloud"),
            "google.cloud.run_v2": run_v2,
        },
    ):
        agents, warnings = _discover_cloud_run("acme", "us-central1")

    assert warnings == []
    pkg = agents[0].mcp_servers[0].packages[0]
    assert pkg.name == "us-docker.pkg.dev/acme/app/worker"
    assert pkg.purl == "pkg:docker/us-docker.pkg.dev/acme/app/worker@v1.2.3"


def test_databricks_library_parsers_emit_purls_only_for_known_versions() -> None:
    from agent_bom.cloud.databricks import _parse_jar_path, _parse_maven_coords, _parse_pypi_spec

    assert _parse_pypi_spec("Requests_OAuthlib==1.3.0").purl == "pkg:pypi/requests-oauthlib@1.3.0"  # type: ignore[union-attr]
    assert _parse_maven_coords("com.google.guava:guava:32.1.3-jre").purl == "pkg:maven/com.google.guava/guava@32.1.3-jre"  # type: ignore[union-attr]
    assert _parse_jar_path("/dbfs/jars/spark-nlp_2.12-5.3.2.jar").purl == "pkg:maven/spark-nlp_2.12@5.3.2"  # type: ignore[union-attr]
    assert _parse_pypi_spec("langchain").purl is None  # type: ignore[union-attr]


def test_cloud_ml_package_parsers_emit_purls_for_pinned_versions() -> None:
    from agent_bom.cloud.mlflow_provider import _parse_requirements_txt
    from agent_bom.cloud.wandb_provider import _parse_requirement

    wandb_pkg = _parse_requirement("transformers[torch]==4.39.0")
    mlflow_pkg = _parse_requirements_txt("scikit-learn==1.4.1\npandas\n")

    assert wandb_pkg is not None
    assert wandb_pkg.purl == "pkg:pypi/transformers@4.39.0"
    assert [pkg.purl for pkg in mlflow_pkg] == ["pkg:pypi/scikit-learn@1.4.1", None]
