"""``AttackPath.composite_risk`` must mean one thing.

Two producers wrote that field on two different scales:

* ``routes/graph._node_risk_100`` normalises to **0–100**
* ``demo_estate/estate_graph._chain_risk`` returned a raw CVSS **0–10**

and ``_derived_attack_paths`` sorts the merged list by it. So the ranking was
not a ranking — it was two unit systems interleaved. Measured on the demo
estate:

    paths: 28 before estate projection -> 2,144 after
    risk buckets: {'0-10': 2116, '10-50': 1, '50-100': 27}
    best estate-correlated path : 8.0
    worst showcase-derived path : 48.0
    of the top 40 ranked paths, estate-correlated: 0
    rank of the first estate-correlated path: 74

Every hand-built showcase path outranked every correlated-estate path by
construction rather than by risk — and the correlated estate is the product's
whole claim. ``_chain_risk``'s own docstring says it exists to stop the estate
"sorting below every hand-built path": it fixed the 0.0 case and not the scale,
so the symptom survived the fix.

The second consequence ships to customers. ``graph/webhooks.py`` banded that
same field on 0–10 thresholds and formatted it "/10", so a real scan emitted:

    "Composite risk 100.0/10"

and every path scoring ≥ 9 *out of 100* was labelled critical — on the demo
snapshot, 1,065 of 2,144 paths cleared the emit threshold at all.

The fix is one shared normaliser, so the scale cannot diverge again.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.risk_scale import RISK_SCALE_MAX, cvss_to_risk_100, normalize_risk_to_100


class TestTheSharedNormaliser:
    def test_a_cvss_style_value_is_lifted_onto_the_hundred_scale(self) -> None:
        assert normalize_risk_to_100(8.0) == 80.0
        assert normalize_risk_to_100(10.0) == 100.0

    def test_a_value_already_on_the_hundred_scale_is_left_alone(self) -> None:
        assert normalize_risk_to_100(48.0) == 48.0
        assert normalize_risk_to_100(100.0) == 100.0

    def test_it_is_clamped_and_never_negative(self) -> None:
        assert normalize_risk_to_100(-5.0) == 0.0
        assert normalize_risk_to_100(9999.0) == RISK_SCALE_MAX

    def test_the_explicit_cvss_conversion_is_monotonic(self) -> None:
        """`cvss_to_risk_100` is a plain 10x, so it has no boundary wart."""
        values = [cvss_to_risk_100(v) for v in (0.0, 1.0, 5.0, 9.9, 10.0)]
        assert values == sorted(values), values
        assert cvss_to_risk_100(8.0) == 80.0

    def test_the_inferring_helper_is_documented_as_non_monotonic(self) -> None:
        """A bare float carries no unit, so inference cannot be monotonic.

        9.9 reads as CVSS and lifts to 99.0; 11.0 reads as already-scaled and
        stays 11.0. Pinned so the discontinuity is a known property rather than
        a surprise — and so anyone tempted to "fix" it sees why it exists.
        """
        assert normalize_risk_to_100(9.9) > normalize_risk_to_100(11.0)


class TestTheEstateRanksOnTheSameScale:
    """The defect: correlated paths could not reach the top of the queue."""

    def test_a_chain_risk_is_reported_on_the_hundred_scale(self) -> None:
        from agent_bom.demo_estate.estate_graph import _chain_risk
        from agent_bom.graph.container import UnifiedGraph

        graph = UnifiedGraph(scan_id="s", tenant_id="t")
        # A CVSS 8.0 asset must not be outranked by a 48.0 showcase path.
        risk = _chain_risk(graph, ["asset-a"], {"asset-a": 8.0})
        assert risk == 80.0, risk

    def test_a_correlated_path_can_outrank_a_showcase_path(self) -> None:
        """8.0 CVSS is worse than a 48/100 path; the old scales said otherwise."""
        from agent_bom.demo_estate.estate_graph import _chain_risk
        from agent_bom.graph.container import UnifiedGraph

        graph = UnifiedGraph(scan_id="s", tenant_id="t")
        correlated = _chain_risk(graph, ["asset-a"], {"asset-a": 8.0})
        showcase = normalize_risk_to_100(48.0)
        assert correlated > showcase, (correlated, showcase)


class TestTheWebhookSpeaksTheSameScale:
    def _path(self, risk: float):
        from agent_bom.graph.container import AttackPath

        return AttackPath(
            source="agent:a",
            target="cred:b",
            hops=["agent:a", "cred:b"],
            edges=[],
            composite_risk=risk,
            summary="a → b",
        )

    def _alerts_for(self, risk: float):
        from agent_bom.graph.container import UnifiedGraph
        from agent_bom.graph.webhooks import compute_delta_alerts

        new_graph = UnifiedGraph(scan_id="new", tenant_id="t")
        new_graph.attack_paths.append(self._path(risk))
        old_graph = UnifiedGraph(scan_id="old", tenant_id="t")
        return [a for a in compute_delta_alerts(old_graph, new_graph) if a.get("type") == "new_attack_path"]

    def test_the_description_does_not_say_a_hundred_out_of_ten(self) -> None:
        alerts = self._alerts_for(100.0)
        assert alerts, "a maximum-risk path emitted no alert"
        assert "/10," not in alerts[0]["description"], alerts[0]["description"]
        assert "100.0/100" in alerts[0]["description"] or "100/100" in alerts[0]["description"]

    def test_a_mid_scale_path_is_not_labelled_critical(self) -> None:
        """`>= 9.0` meant "9 out of 100" — nearly everything was critical."""
        alerts = self._alerts_for(12.0)
        assert all(a["severity"] != "critical" for a in alerts), alerts

    def test_a_genuinely_critical_path_is_still_critical(self) -> None:
        alerts = self._alerts_for(95.0)
        assert alerts and alerts[0]["severity"] == "critical", alerts

    def test_a_low_risk_path_does_not_alert_at_all(self) -> None:
        """`>= 7.0` on a 0-100 field emitted on 1,065 of 2,144 demo paths."""
        assert self._alerts_for(12.0) == [] or all(a["severity"] != "critical" for a in self._alerts_for(12.0))
        assert self._alerts_for(5.0) == []

    @pytest.mark.parametrize("risk,expected", [(69.0, False), (71.0, True)])
    def test_the_emit_threshold_sits_at_seventy_of_a_hundred(self, risk: float, expected: bool) -> None:
        assert bool(self._alerts_for(risk)) is expected
