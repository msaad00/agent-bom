#!/usr/bin/env python3
"""Validate and reproducibly package the Snowflake Native App release assets."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "deploy" / "snowflake" / "native-app"
PROJECT = APP / "snowflake.yml"
IMAGES = APP / "images.yml"
MANIFEST = APP / "manifest.yml"
LISTING = ROOT / "docs" / "snowflake-native-app" / "listing-template.yml"

EXPECTED_IMAGES = {
    "agent-bom",
    "agent-bom-ui",
    "agent-bom-scanner",
    "agent-bom-mcp-runtime",
}


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return value


def semantic_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(project["project"]["version"])


def package_version(version: str | None = None) -> str:
    resolved = (version or semantic_version()).strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", resolved):
        raise ValueError("version must use MAJOR.MINOR.PATCH")
    return "v" + resolved.replace(".", "_")


def image_contract(version: str | None = None) -> dict[str, Any]:
    contract = _yaml(IMAGES)
    tag = package_version(version)
    images = contract.get("images")
    if contract.get("schema_version") != 1 or contract.get("platform") != "linux/amd64":
        raise ValueError("images.yml must use schema_version 1 and platform linux/amd64")
    if not isinstance(images, list):
        raise ValueError("images.yml must declare an images list")
    names = {str(item.get("name", "")) for item in images if isinstance(item, dict)}
    if names != EXPECTED_IMAGES or len(images) != len(EXPECTED_IMAGES):
        raise ValueError(f"images.yml must declare exactly {sorted(EXPECTED_IMAGES)}")
    for item in images:
        context = ROOT / str(item["context"])
        dockerfile = ROOT / str(item["dockerfile"])
        if not context.exists() or not dockerfile.is_file():
            raise ValueError(f"invalid image build inputs for {item['name']}")
        item["tag"] = tag
        item["version"] = version or semantic_version()
        item["platform"] = contract["platform"]
    return contract


def _project_package() -> dict[str, Any]:
    project = _yaml(PROJECT)
    package = project.get("entities", {}).get("agent_bom_package")
    if not isinstance(package, dict):
        raise ValueError("snowflake.yml must declare agent_bom_package")
    return package


def package_files() -> dict[str, Path]:
    package = _project_package()
    files: dict[str, Path] = {}
    for artifact in package.get("artifacts", []):
        src_pattern = str(artifact["src"])
        dest = str(artifact["dest"])
        matches = sorted(APP.glob(src_pattern))
        if not matches:
            raise ValueError(f"snowflake.yml artifact has no matches: {src_pattern}")
        for source in matches:
            if not source.is_file():
                continue
            archive_name = f"{dest}{source.name}" if dest.endswith("/") else dest
            if archive_name in files:
                raise ValueError(f"duplicate package destination: {archive_name}")
            files[archive_name] = source
    return files


def validate(version: str | None = None) -> None:
    tag = package_version(version)
    contract = image_contract(version)
    manifest = _yaml(MANIFEST)
    marketplace = _yaml(APP / "marketplace.yml")
    listing = _yaml(LISTING)
    package = _project_package()

    if package.get("distribution") != "external" or package.get("enable_release_channels") is not True:
        raise ValueError("snowflake.yml must declare external distribution with release channels")
    if manifest.get("artifacts", {}).get("readme") != "README.md":
        raise ValueError("manifest.yml must package the consumer README")
    image_refs = manifest.get("artifacts", {}).get("container_services", {}).get("images", [])
    expected_prefix = "/" + str(contract["repository_path"]).strip("/") + "/"
    if len(image_refs) != len(EXPECTED_IMAGES):
        raise ValueError("manifest image count does not match images.yml")
    if any(not str(ref).startswith(expected_prefix) or not str(ref).endswith(f":{tag}") for ref in image_refs):
        raise ValueError("manifest image references must use the canonical repository and release tag")

    for spec in [APP / "service-spec.yaml", *sorted((APP / "service-specs").glob("*.yaml"))]:
        text = spec.read_text(encoding="utf-8")
        if ":latest" in text or f":{tag}" not in text:
            raise ValueError(f"{spec.relative_to(ROOT)} must use the immutable release tag {tag}")
        _yaml(spec)
        placeholders = set(re.findall(r"\{\{\s*([^} ]+)\s*\}\}", text))
        allowed_placeholders = {"mcp_bearer_token"} if spec.name == "mcp-runtime-service.yaml" else set()
        if placeholders != allowed_placeholders:
            raise ValueError(f"{spec.relative_to(ROOT)} has undeclared runtime placeholders: {sorted(placeholders)}")

    pools = marketplace.get("required_compute_pools", [])
    if len(pools) != 1 or "AGENT_BOM_CONSUMER_POOL" not in pools[0]:
        raise ValueError("marketplace.yml must disclose the AGENT_BOM_CONSUMER_POOL requirement")
    if not listing.get("usage_examples") or not listing.get("data_dictionary"):
        raise ValueError("listing template must include usage examples and a data dictionary")
    if "TBD" in LISTING.read_text(encoding="utf-8"):
        raise ValueError("listing template contains an unresolved TBD")

    files = package_files()
    required = {"README.md", "manifest.yml", "marketplace.yml", "scripts/setup.sql", "service-spec.yaml"}
    missing = required - files.keys()
    if missing:
        raise ValueError(f"application package is missing {sorted(missing)}")
    forbidden = {"snowflake.yml", "images.yml", "scripts/provider_bootstrap.sql"}
    leaked = forbidden & files.keys()
    if leaked:
        raise ValueError(f"provider-only files leaked into consumer package: {sorted(leaked)}")


def matrix(version: str | None = None) -> list[dict[str, str]]:
    validate(version)
    contract = image_contract(version)
    return [
        {
            "name": str(item["name"]),
            "context": str(item["context"]),
            "dockerfile": str(item["dockerfile"]),
            "platform": str(item["platform"]),
            "tag": str(item["tag"]),
            "version": str(item["version"]),
        }
        for item in contract["images"]
    ]


def build_package(output: Path, version: str | None = None) -> str:
    validate(version)
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for archive_name, source in sorted(package_files().items()):
            info = archive.gettarinfo(str(source), arcname=archive_name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            with source.open("rb") as handle:
                archive.addfile(info, handle)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            zipped.write(buffer.getvalue())
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "matrix", "package"))
    parser.add_argument("--version", default=None)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.command == "validate":
        validate(args.version)
        print(f"Snowflake Native App release assets valid for {package_version(args.version)}")
    elif args.command == "matrix":
        print(json.dumps(matrix(args.version), separators=(",", ":")))
    else:
        if args.output is None:
            parser.error("package requires --output")
        digest = build_package(args.output, args.version)
        print(f"{digest}  {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
