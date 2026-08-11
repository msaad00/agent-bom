"""Ingest must not accept "reachable" from a row that names no path.

`safe_finding_response_payload` sanitises a finding row on two paths — the API
response, and persistence of compliance-hub findings via `_redact_finding`. It
copied `graph_reachable` through after a type check and nothing else::

    graph_reachable = row.get("graph_reachable")
    payload["graph_reachable"] = graph_reachable if isinstance(graph_reachable, bool) else None

`BlastRadius.calculate_risk_score` then turns that bool straight into
``RISK_REACHABLE_BOOST``. So any caller could post ``graph_reachable: true`` on
a finding with no supporting path and have it rank above findings the
reachability engine actually proved reachable — the one signal on the surface
that is supposed to mean "an agent can get here".

This is not a new policy. `dependency_reach.py` already defines the word::

    @property
    def reachable(self) -> bool:
        return bool(self.reachable_from)

Reachable *means* at least one agent reaches it. A row claiming
``graph_reachable: true`` with an empty ``graph_reachable_from_agents``
therefore contradicts the engine's own definition, and `blast_reach.py` shows
the engine never emits that combination — when it stamps ``reachable`` it also
stamps the agent list and the hop distance from the same report.

`_redact_finding` sharpens it: it *drops* ``graph_reachable_from_agents`` when
the list is empty, while keeping ``graph_reachable`` — so the stored row keeps
the claim and discards the evidence for it.

Unsupported claims become ``None``, which the model documents as "engine did not
run" and which leaves scoring unchanged. Fail closed, not fail quiet. Doing it
here covers both paths, and runs before the agent list is dropped.

**Known asymmetry, deliberately not fixed here.** ``graph_reachable: false``
lowers risk and is equally unverifiable, but a legitimately unreachable finding
carries no corroborating fields either — the engine emits ``distance=None`` and
``agents=[]`` for it, which is indistinguishable from a fabricated ``false``.
Rejecting it would break round-trip of our own export. Separating those two
needs a provenance field saying the engine ran, which this change does not add.
"""

from __future__ import annotations

import pytest

from agent_bom.finding_scope import safe_finding_response_payload


def ingest(**row: object) -> dict:
    base = {
        "cve_id": "CVE-2026-0001",
        "package": "left-pad",
        "version": "1.0.0",
        "ecosystem": "npm",
        "severity": "high",
    }
    base.update(row)
    return safe_finding_response_payload(base)


def test_reachable_with_named_agents_is_kept() -> None:
    """The engine's own shape: reachable, and it says by whom."""
    payload = ingest(
        graph_reachable=True,
        graph_reachable_from_agents=["agent:prod-copilot"],
        graph_min_hop_distance=2,
    )
    assert payload["graph_reachable"] is True
    assert payload["graph_reachable_from_agents"] == ["agent:prod-copilot"]


def test_reachable_from_nobody_is_not_reachable() -> None:
    """The defect: a boost with no path behind it."""
    payload = ingest(graph_reachable=True, graph_reachable_from_agents=[])
    assert payload["graph_reachable"] is None, "a claim with no reachable-from agent was accepted"


def test_reachable_with_the_field_absent_entirely_is_not_reachable() -> None:
    payload = ingest(graph_reachable=True)
    assert payload["graph_reachable"] is None


def test_a_hop_distance_alone_does_not_make_it_reachable() -> None:
    """Distance is not the definition; `bool(reachable_from)` is."""
    payload = ingest(graph_reachable=True, graph_min_hop_distance=3)
    assert payload["graph_reachable"] is None


def test_agents_that_are_not_usable_identifiers_do_not_count() -> None:
    """The agent list is already sanitised; the check must run on what survived."""
    payload = ingest(graph_reachable=True, graph_reachable_from_agents=[None, "", {}])
    assert payload["graph_reachable"] is None


def test_unreachable_is_still_accepted() -> None:
    """See the module docstring: the false direction needs a provenance field."""
    payload = ingest(graph_reachable=False)
    assert payload["graph_reachable"] is False


def test_absent_reachability_stays_unknown() -> None:
    payload = ingest()
    assert payload["graph_reachable"] is None


@pytest.mark.parametrize("bogus", ["true", 1, [], {}])
def test_non_boolean_reachability_is_unknown(bogus: object) -> None:
    assert ingest(graph_reachable=bogus)["graph_reachable"] is None


def test_the_unsupported_claim_does_not_reach_the_risk_boost() -> None:
    """End of the chain: the fabricated claim must not move the score."""
    from agent_bom.models import BlastRadius, Package, Vulnerability

    def blast(reachable: bool | None) -> BlastRadius:
        br = BlastRadius(
            vulnerability=Vulnerability(id="CVE-2026-0001", summary="test", severity="high", cvss_score=7.5),
            package=Package(name="left-pad", version="1.0.0", ecosystem="npm"),
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.graph_reachable = reachable
        br.calculate_risk_score()
        return br

    sanitised = ingest(graph_reachable=True, graph_reachable_from_agents=[])["graph_reachable"]
    assert blast(sanitised).risk_score == blast(None).risk_score
    # And the boost is real, so the comparison above is not vacuous.
    assert blast(True).risk_score > blast(None).risk_score
