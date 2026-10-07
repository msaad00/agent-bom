from agent_bom.models import AIBOMReport
from agent_bom.output.html import to_html


def test_empty_html_is_not_a_clean_security_assessment():
    output = to_html(AIBOMReport())
    assert "CLEAN" not in output
    assert "NO ASSESSMENT EVIDENCE" in output


def test_missing_control_rows_do_not_count_as_assessment():
    from agent_bom.output.cis_posture import finding_free_posture

    assert finding_free_posture(AIBOMReport(cis_benchmark_data={"checks": None}))[1] == "NO ASSESSMENT EVIDENCE"
