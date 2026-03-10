"""Tests for dataset card parser (HuggingFace, DVC)."""

import json

from agent_bom.parsers.dataset_cards import (
    DatasetScanResult,
    discover_dataset_files,
    parse_dataset_info_json,
    parse_dataset_readme,
    parse_dvc_file,
    scan_dataset_directory,
    scan_datasets,
)

# ─── parse_dataset_info_json ────────────────────────────────────────────────


def test_parse_dataset_info_complete(tmp_path):
    data = {
        "dataset_name": "squad",
        "description": "Stanford Question Answering Dataset",
        "license": "cc-by-4.0",
        "version": {"version_str": "1.1.0"},
        "features": {"context": {"dtype": "string"}, "question": {"dtype": "string"}, "answers": {"dtype": "string"}},
        "splits": {"train": {"num_examples": 87599}, "validation": {"num_examples": 10570}},
        "download_size": 35142551,
        "citation": "@article{rajpurkar2016squad}",
    }
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    info = parse_dataset_info_json(path)
    assert info is not None
    assert info.name == "squad"
    assert info.license == "cc-by-4.0"
    assert info.version == "1.1.0"
    assert "context" in info.features
    assert "question" in info.features
    assert info.splits["train"] == 87599
    assert info.size_bytes == 35142551
    assert info.citation.startswith("@article")
    assert info.security_flags == []  # has license


def test_parse_dataset_info_no_license(tmp_path):
    data = {"dataset_name": "unlicensed-data", "features": {"text": {"dtype": "string"}}}
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    info = parse_dataset_info_json(path)
    assert info is not None
    assert info.name == "unlicensed-data"
    assert len(info.security_flags) == 1
    assert info.security_flags[0]["type"] == "UNLICENSED_DATASET"
    assert info.security_flags[0]["severity"] == "MEDIUM"


def test_parse_dataset_info_license_as_list(tmp_path):
    data = {"dataset_name": "multi-lic", "license": ["apache-2.0", "mit"]}
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    info = parse_dataset_info_json(path)
    assert info is not None
    assert info.license == "apache-2.0"


def test_parse_dataset_info_invalid_json(tmp_path):
    path = tmp_path / "dataset_info.json"
    path.write_text("not valid json{{{")

    info = parse_dataset_info_json(path)
    assert info is None


def test_parse_dataset_info_missing_file(tmp_path):
    path = tmp_path / "nonexistent.json"
    info = parse_dataset_info_json(path)
    assert info is None


def test_parse_dataset_info_not_dict(tmp_path):
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps([1, 2, 3]))

    info = parse_dataset_info_json(path)
    assert info is None


# ─── parse_dataset_readme ───────────────────────────────────────────────────


def test_parse_dataset_readme_with_frontmatter(tmp_path):
    readme = """---
license: mit
task_categories:
  - text-classification
  - sentiment-analysis
language:
  - en
size_categories: 1K<n<10K
---

# My Dataset

Some description here.
"""
    d = tmp_path / "my-dataset"
    d.mkdir()
    path = d / "README.md"
    path.write_text(readme)

    info = parse_dataset_readme(path)
    assert info is not None
    assert info.license == "mit"
    assert "text-classification" in info.task_categories
    assert "en" in info.languages
    assert info.security_flags == []


def test_parse_dataset_readme_no_frontmatter(tmp_path):
    d = tmp_path / "bare-dataset"
    d.mkdir()
    path = d / "README.md"
    path.write_text("# Just a readme\n\nNo YAML frontmatter here.\n")

    info = parse_dataset_readme(path)
    assert info is not None
    assert info.name == "bare-dataset"
    assert len(info.security_flags) == 1
    assert info.security_flags[0]["type"] == "NO_DATASET_CARD"


def test_parse_dataset_readme_no_license(tmp_path):
    readme = """---
task_categories:
  - text-generation
---

# Unlicensed Dataset
"""
    d = tmp_path / "unlicensed"
    d.mkdir()
    path = d / "README.md"
    path.write_text(readme)

    info = parse_dataset_readme(path)
    assert info is not None
    assert len(info.security_flags) == 1
    assert info.security_flags[0]["type"] == "UNLICENSED_DATASET"


# ─── parse_dvc_file ────────────────────────────────────────────────────────


def test_parse_dvc_file_with_hash(tmp_path):
    dvc_content = """outs:
  - md5: d41d8cd98f00b204e9800998ecf8427e
    size: 1048576
    path: data.csv
"""
    path = tmp_path / "data.csv.dvc"
    path.write_text(dvc_content)

    info = parse_dvc_file(path)
    assert info is not None
    assert info.name == "data.csv"
    assert info.dvc_md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert info.size_bytes == 1048576
    assert info.security_flags == []


def test_parse_dvc_file_no_hash(tmp_path):
    dvc_content = """outs:
  - path: data.csv
    cache: false
"""
    path = tmp_path / "data.csv.dvc"
    path.write_text(dvc_content)

    info = parse_dvc_file(path)
    assert info is not None
    assert info.dvc_md5 == ""
    assert len(info.security_flags) == 1
    assert info.security_flags[0]["type"] == "UNVERSIONED_DATA"


def test_parse_dvc_file_with_remote(tmp_path):
    dvc_content = """outs:
  - md5: d41d8cd98f00b204e9800998ecf8427e
    size: 500000
    path: model.pkl
"""
    path = tmp_path / "model.pkl.dvc"
    path.write_text(dvc_content)

    # Create .dvc/config with remote
    dvc_dir = tmp_path / ".dvc"
    dvc_dir.mkdir()
    (dvc_dir / "config").write_text("[core]\n    remote = myremote\n['remote \"myremote\"']\n    url = s3://my-bucket/data\n")

    info = parse_dvc_file(path)
    assert info is not None
    assert info.dvc_remote == "s3://my-bucket/data"
    assert any(f["type"] == "REMOTE_DATA_SOURCE" for f in info.security_flags)


# ─── discover_dataset_files ────────────────────────────────────────────────


def test_discover_dataset_files(tmp_path):
    # Create dataset_info.json
    (tmp_path / "dataset_info.json").write_text("{}")

    # Create nested dataset_info.json
    d = tmp_path / "data" / "subdir"
    d.mkdir(parents=True)
    (d / "dataset_info.json").write_text("{}")

    # Create .dvc file
    (tmp_path / "train.csv.dvc").write_text("outs:\n  - path: train.csv\n")

    # Create README in a data-like directory
    data_dir = tmp_path / "dataset-v2"
    data_dir.mkdir()
    (data_dir / "README.md").write_text("---\nlicense: mit\n---\n")

    paths = discover_dataset_files(tmp_path)
    names = [p.name for p in paths]
    assert "dataset_info.json" in names
    assert "train.csv.dvc" in names
    assert "README.md" in names


def test_discover_skips_git_dirs(tmp_path):
    git_dir = tmp_path / ".git" / "data"
    git_dir.mkdir(parents=True)
    (git_dir / "dataset_info.json").write_text("{}")

    paths = discover_dataset_files(tmp_path)
    assert len(paths) == 0


# ─── scan_datasets ──────────────────────────────────────────────────────────


def test_scan_datasets_dedup(tmp_path):
    # Two dataset_info.json with same name
    d1 = tmp_path / "v1"
    d1.mkdir()
    (d1 / "dataset_info.json").write_text(json.dumps({"dataset_name": "squad"}))

    d2 = tmp_path / "v2"
    d2.mkdir()
    (d2 / "dataset_info.json").write_text(json.dumps({"dataset_name": "squad"}))

    result = scan_datasets([d1 / "dataset_info.json", d2 / "dataset_info.json"])
    assert len(result.datasets) == 1
    assert result.datasets[0].name == "squad"


# ─── scan_dataset_directory ─────────────────────────────────────────────────


def test_scan_dataset_directory_end_to_end(tmp_path):
    (tmp_path / "dataset_info.json").write_text(
        json.dumps({"dataset_name": "test-ds", "license": "apache-2.0", "features": {"text": {"dtype": "string"}}})
    )
    (tmp_path / "train.csv.dvc").write_text("outs:\n  - md5: abc123def456abc123def456abc123de\n    size: 1000\n    path: train.csv\n")

    result = scan_dataset_directory(str(tmp_path))
    assert len(result.datasets) >= 1
    assert result.source_files


def test_scan_dataset_directory_nonexistent(tmp_path):
    result = scan_dataset_directory(str(tmp_path / "nope"))
    assert len(result.warnings) == 1
    assert "Not a directory" in result.warnings[0]


def test_scan_dataset_directory_empty(tmp_path):
    result = scan_dataset_directory(str(tmp_path))
    assert len(result.warnings) == 1
    assert "No dataset card files" in result.warnings[0]


# ─── DatasetScanResult.to_dict ──────────────────────────────────────────────


def test_dataset_scan_result_to_dict():
    result = DatasetScanResult()
    d = result.to_dict()
    assert d["total_datasets"] == 0
    assert d["flagged_count"] == 0
    assert d["datasets"] == []


# ─── DatasetInfo.to_dict ────────────────────────────────────────────────────


def test_dataset_info_to_dict(tmp_path):
    data = {
        "dataset_name": "test",
        "license": "mit",
        "features": {"text": {"dtype": "string"}},
        "splits": {"train": {"num_examples": 100}},
    }
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    info = parse_dataset_info_json(path)
    d = info.to_dict()
    assert d["name"] == "test"
    assert d["license"] == "mit"
    assert "features" in d
    assert "splits" in d
