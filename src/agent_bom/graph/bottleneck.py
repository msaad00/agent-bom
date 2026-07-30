"""Approximate betweenness ("what does everything have to go through?") with
the sample it was computed from declared alongside the answer.

Exact betweenness is a BFS from every node — O(V*(V+E)), unusable on an estate
graph. So this samples source nodes. Two rules make a sample honest:

* the sample must not be an artifact of how the graph was built. Taking the
  first N keys in insertion order made the answer depend on whether findings or
  topology were added first — the same estate ranked a scoreless CVE first in
  one order and the real choke point in the other. Sources are drawn by a fixed
  stride over the sorted node ids instead: deterministic, reproducible across
  runs and Python versions, and spread across the whole id space.
* the caller must be told it was a sample. :class:`BottleneckAnalysis` carries
  ``sampled_sources`` / ``total_nodes`` so no surface can present a partial
  traversal as the whole picture.

Nodes that no sampled path crossed are omitted rather than reported at 0.0 — a
zero is "not a bottleneck", not "the fifth biggest bottleneck", and normalising
an all-zero result used to render a full ranking of legitimate-looking zeros.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import isqrt
from typing import Any, Callable, Iterable, Sequence

# Source-sample bounds. The floor keeps small graphs meaningful; the ceiling
# keeps a 200k-node estate from turning a read into 200k breadth-first walks.
MIN_SAMPLE_SOURCES = 50
MAX_SAMPLE_SOURCES = 200


@dataclass(frozen=True, slots=True)
class BottleneckAnalysis:
    """Ranked bottlenecks plus the provenance of the traversal behind them."""

    nodes: list[tuple[str, float]] = field(default_factory=list)
    sampled_sources: int = 0
    total_nodes: int = 0

    @property
    def sampled(self) -> bool:
        """True when the ranking came from a subset of possible sources."""
        return self.sampled_sources < self.total_nodes

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": node_id, "score": score} for node_id, score in self.nodes],
            "sampled_sources": self.sampled_sources,
            "total_nodes": self.total_nodes,
            "sampled": self.sampled,
        }


def sample_sources(node_ids: Sequence[str]) -> list[str]:
    """Pick traversal sources deterministically and evenly across the estate.

    Sorted ids plus a fixed stride: no RNG to drift between releases, and the
    selection covers the whole id space instead of whichever nodes happened to
    be inserted first.
    """
    total = len(node_ids)
    if total == 0:
        return []
    target = min(MAX_SAMPLE_SOURCES, max(MIN_SAMPLE_SOURCES, isqrt(total)))
    ordered = sorted(node_ids)
    if total <= target:
        return ordered
    stride = total / target
    return [ordered[int(index * stride)] for index in range(target)]


def compute_bottlenecks(
    node_ids: Sequence[str],
    successors: Callable[[str], Iterable[str]],
    *,
    top_n: int = 5,
) -> BottleneckAnalysis:
    """Rank nodes by how many sampled shortest paths pass THROUGH them.

    *successors* yields the out-neighbours of a node; backends supply their own
    adjacency so the algorithm and its provenance contract stay in one place.
    """
    total = len(node_ids)
    if total == 0:
        return BottleneckAnalysis()

    sources = sample_sources(node_ids)
    scores: dict[str, float] = {}
    for source in sources:
        # Parent pointers instead of materialised path lists: same shortest-path
        # tree, without holding a copy of every path in memory at once.
        parents: dict[str, str | None] = {source: None}
        queue: deque[str] = deque([source])
        while queue:
            current = queue.popleft()
            for neighbour in successors(current):
                if neighbour not in parents:
                    parents[neighbour] = current
                    queue.append(neighbour)
        for target in parents:
            hop = parents[target]
            while hop is not None and hop != source:
                scores[hop] = scores.get(hop, 0.0) + 1.0
                hop = parents[hop]

    total_score = sum(scores.values())
    if total_score <= 0.0:
        # Nothing sits between anything. Say so rather than dividing by a
        # fabricated 1.0 and emitting a ranking of zeros.
        return BottleneckAnalysis(nodes=[], sampled_sources=len(sources), total_nodes=total)

    ranked = sorted(
        ((node_id, score / total_score) for node_id, score in scores.items() if score > 0.0),
        key=lambda item: (-item[1], item[0]),
    )
    return BottleneckAnalysis(nodes=ranked[:top_n], sampled_sources=len(sources), total_nodes=total)
