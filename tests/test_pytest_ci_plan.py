from __future__ import annotations

from pathlib import Path

from scripts.pytest_ci_plan import discover_test_files, plan_shards, select_targeted_tests


def _write(path: Path, lines: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n" * lines, encoding="utf-8")


def test_shard_plan_is_deterministic_disjoint_and_complete(tmp_path: Path) -> None:
    for index, lines in enumerate((200, 150, 120, 90, 70, 50, 30, 20, 10)):
        _write(tmp_path / f"group_{index % 3}" / f"test_{index}.py", lines)

    files = discover_test_files(tmp_path)
    first = plan_shards(files, total=4)
    second = plan_shards(files, total=4)

    assert first == second
    assert {path for shard in first for path in shard} == set(files)
    assert sum(len(shard) for shard in first) == len(files)

    loads = [sum(path.stat().st_size for path in shard) for shard in first]
    largest = max(path.stat().st_size for path in files)
    assert max(loads) - min(loads) <= largest


def test_targeted_tests_include_changed_tests_and_source_name_matches(tmp_path: Path) -> None:
    direct = tmp_path / "tests" / "test_direct.py"
    matching = tmp_path / "tests" / "db" / "test_local_analytics.py"
    unrelated = tmp_path / "tests" / "test_other.py"
    for path in (direct, matching, unrelated):
        _write(path, 1)

    selected = select_targeted_tests(
        changed_files=[Path("tests/test_direct.py"), Path("src/agent_bom/db/local_analytics.py")],
        root=tmp_path,
    )

    assert selected == [matching, direct]
