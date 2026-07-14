"""Unit tests for the configurable executive risk-score engine (#3940)."""

from __future__ import annotations

from agent_bom.exec_score import (
    DEFAULT_EXEC_SCORE_WEIGHTS,
    DISPLAY_FORMATS,
    ExecScoreConfig,
    canonicalize_config,
    canonicalize_thresholds,
    canonicalize_weights,
    compute_exec_score,
    load_exec_score_config,
    score_to_grade,
)


def _sev(critical=0, high=0, medium=0, low=0, unrated=0) -> dict[str, int]:
    return {"critical": critical, "high": high, "medium": medium, "low": low, "unrated": unrated}


def test_no_evidence_is_na_not_a() -> None:
    """Empty estate grades N/A — never a clean A that reads as 'no vulns'."""
    result = compute_exec_score(severity=_sev())
    assert result["grade"] == "N/A"
    assert result["display"] is None
    assert "run a scan" in result["summary"].lower()


def test_score_derives_from_honest_counts() -> None:
    """2 critical + 1 high => penalty 30 => 70 => grade C (default weights)."""
    result = compute_exec_score(severity=_sev(critical=2, high=1))
    assert result["penalty_total"] == 30.0
    assert result["score"] == 70.0
    assert result["grade"] == "C"
    # Breakdown carries every driver's contribution for explainability.
    contrib = {row["driver"]: row["contribution"] for row in result["breakdown"]}
    assert contrib["critical"] == 24.0
    assert contrib["high"] == 6.0


def test_summary_never_claims_no_vulns_when_counted() -> None:
    result = compute_exec_score(severity=_sev(high=3))
    assert "no vulnerabilit" not in result["summary"].lower()
    assert "3 high" in result["summary"]


def test_large_estate_grades_f_without_flooring_at_zero() -> None:
    """A big critical estate is grade F with a very low — but non-zero — score.

    The diminishing-returns curve approaches 0 asymptotically; it must never
    round to a hard 0 for a finite estate (that is the saturation bug: 0 leaves
    no room to distinguish a bad estate from a catastrophic one)."""
    result = compute_exec_score(severity=_sev(critical=50))
    assert result["grade"] == "F"
    assert 0.0 < result["score"] < 15.0
    # score + penalty_total reconcile to a full 100 points.
    assert round(result["score"] + result["penalty_total"], 1) == 100.0


def test_score_discriminates_across_estate_scale() -> None:
    """The core #3967 fix: two estates with very different critical counts get
    *different* failing scores — both bad, but distinguishable, not both F/0."""
    small = compute_exec_score(severity=_sev(critical=20))
    mid = compute_exec_score(severity=_sev(critical=200))
    large = compute_exec_score(severity=_sev(critical=2000))
    # All fail, but each is strictly worse than the last — no saturation.
    assert small["grade"] == mid["grade"] == large["grade"] == "F"
    assert small["score"] > mid["score"] > large["score"] > 0.0
    # The 20-vs-2000 gap the audit called out is materially resolvable.
    assert small["score"] - large["score"] > 5.0


def test_more_criticals_never_raise_the_score() -> None:
    """Monotonic invariant (#3949): adding findings only lowers the score."""
    prev = compute_exec_score(severity=_sev(critical=1))["score"]
    for n in range(2, 40):
        cur = compute_exec_score(severity=_sev(critical=n))["score"]
        assert cur < prev, f"critical={n} did not lower the score"
        prev = cur


def test_clean_estate_still_scores_a() -> None:
    """A scanned estate with zero findings (floor present) still grades A."""
    result = compute_exec_score(severity=_sev(), floor_score=100.0)
    assert result["score"] == 100.0
    assert result["grade"] == "A"


def test_floor_never_launders_a_failing_scorecard_up() -> None:
    """A benign count cannot raise an authoritative failing scorecard."""
    result = compute_exec_score(severity=_sev(low=1), floor_score=30.0)
    assert result["score"] == 30.0  # min(99.5, 30.0)
    assert result["grade"] == "F"
    assert result["floored"] is True


def test_floor_does_not_raise_a_worse_count() -> None:
    """When counts are worse than the floor, the worse count wins."""
    result = compute_exec_score(severity=_sev(critical=10), floor_score=95.0)
    # Count-derived score (10 critical) is well below the benign 95 floor, so the
    # count wins and the floor is not applied.
    assert result["grade"] == "F"
    assert result["score"] < 60.0
    assert result["floored"] is False


def test_kev_and_exposure_amplify() -> None:
    base = compute_exec_score(severity=_sev(high=1))["score"]
    amplified = compute_exec_score(severity=_sev(high=1), kev=1, exposure=1)["score"]
    assert amplified < base


def test_display_format_variants() -> None:
    sev = _sev(high=1)
    assert compute_exec_score(severity=sev, config=_cfg("grade"))["display"].startswith("Grade ")
    assert compute_exec_score(severity=sev, config=_cfg("percent"))["display"].endswith("%")
    assert "/ 100" in compute_exec_score(severity=sev, config=_cfg("points"))["display"]


def _cfg(fmt: str) -> ExecScoreConfig:
    return load_exec_score_config({"display_format": fmt})


def test_canonicalize_weights_clamps_and_ignores_junk() -> None:
    weights = canonicalize_weights({"critical": -5, "high": "abc", "bogus": 99, "kev": 1000})
    assert weights["critical"] == 0.0  # negative clamped to 0
    assert weights["high"] == DEFAULT_EXEC_SCORE_WEIGHTS["high"]  # junk ignored
    assert weights["kev"] == 100.0  # clamped to max
    assert "bogus" not in weights


def test_canonicalize_thresholds_enforces_monotonic_order() -> None:
    # Deliberately inverted: A below C should be corrected to keep A>=B>=C>=D.
    thresholds = canonicalize_thresholds({"A": 50, "B": 80, "C": 70, "D": 60})
    assert thresholds["A"] >= thresholds["B"] >= thresholds["C"] >= thresholds["D"]


def test_canonicalize_config_never_raises_on_garbage() -> None:
    cfg = canonicalize_config({"weights": "not-a-dict", "display_format": 123, "grade_thresholds": None})
    assert set(cfg) == {"weights", "grade_thresholds", "display_format"}
    assert cfg["display_format"] in DISPLAY_FORMATS


def test_env_policy_applies(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_EXEC_SCORE_POLICY", '{"weights": {"critical": 20}, "display_format": "points"}')
    cfg = load_exec_score_config()
    assert cfg.weights["critical"] == 20.0
    assert cfg.display_format == "points"
    assert cfg.source.startswith("env:")


def test_tenant_override_wins_over_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_EXEC_SCORE_POLICY", '{"weights": {"critical": 20}}')
    cfg = load_exec_score_config({"weights": {"critical": 5}})
    assert cfg.weights["critical"] == 5.0
    assert "tenant_override" in cfg.source


def test_score_to_grade_uses_custom_thresholds() -> None:
    thresholds = {"A": 50.0, "B": 40.0, "C": 30.0, "D": 20.0}
    assert score_to_grade(55, thresholds) == "A"
    assert score_to_grade(10, thresholds) == "F"


def test_facade_merge_preserves_existing_and_clear() -> None:
    """Partial updates merge onto the persisted override; clear reverts."""
    from agent_bom.api.exec_score_config import (
        clear_exec_score_config,
        get_exec_score_overrides,
        resolve_exec_score_config,
        set_exec_score_config,
    )
    from agent_bom.api.stores import set_tenant_score_config_store
    from agent_bom.api.tenant_score_config_store import InMemoryTenantScoreConfigStore

    set_tenant_score_config_store(InMemoryTenantScoreConfigStore())
    tenant = "tenant-x"

    set_exec_score_config(tenant, {"display_format": "grade"})
    set_exec_score_config(tenant, {"weights": {"critical": 30}})
    resolved = resolve_exec_score_config(tenant)
    # Both fields survive across the two partial writes.
    assert resolved.display_format == "grade"
    assert resolved.weights["critical"] == 30.0
    assert get_exec_score_overrides(tenant)  # non-empty

    assert clear_exec_score_config(tenant) is True
    assert get_exec_score_overrides(tenant) == {}
    assert resolve_exec_score_config(tenant).display_format == "percent"

    set_tenant_score_config_store(InMemoryTenantScoreConfigStore())
