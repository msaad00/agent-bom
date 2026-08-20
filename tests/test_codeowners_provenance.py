from __future__ import annotations

from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json
from agent_bom.repo_auto_detect import load_codeowners


def test_load_codeowners_preserves_stable_prefixes_and_last_rule(tmp_path) -> None:
    owners_file = tmp_path / ".github" / "CODEOWNERS"
    owners_file.parent.mkdir()
    owners_file.write_text(
        "\n".join(
            [
                "* @platform",
                "/services/** @services",
                "/services/billing/** @payments @finops",
                "/services/billing/** @billing",
                "*.md @docs",
            ]
        ),
        encoding="utf-8",
    )

    assert load_codeowners(tmp_path) == {
        "": "@platform",
        "services": "@services",
        "services/billing": "@billing",
    }


def test_repo_tree_scan_and_json_retain_codeowners_provenance(tmp_path) -> None:
    (tmp_path / "CODEOWNERS").write_text("/services/api/** @api-team\n", encoding="utf-8")

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[], offline=True)
    assert result.codeowners == {"services/api": "@api-team"}

    report = AIBOMReport(codeowners=result.codeowners)
    assert to_json(report)["codeowners"] == {"services/api": "@api-team"}
