"""Graph neighbourhood read: the nodes and edges around one or more seeds.

Composed from parts that already exist -- ``neighbour_ids`` for the walk,
``get_many`` to hydrate it, ``edges_among`` for the edges internal to the
result -- and shaped exactly like the history reads: a permission-blind
walk, then a *separate* pass running ``permissions.evaluate`` per object,
then assembly. The assembler structurally cannot see an unchecked node.

**Denied nodes are dropped entirely, and only their count comes back.**

This is the one place where this read deliberately diverges from
``history.py``, which withholds a denied claim as an id-only placeholder.
That was right there: the caller named a claim and asked for its
supersession history, so the existence and the length of the chain were
already implied by the question, and dropping a step would have misreported
the record as a shorter one.

A neighbourhood is a different shape of disclosure. The caller supplies a
seed and a hop count, and the *structure* is the answer -- so a placeholder
is not a redaction, it is the finding. Id-shaped holes would let an agent
holding a grant that reads nothing walk the graph anyway and recover the
adjacency, the degree of each node and the density of each region: the map
of someone's memory, and where in it the interesting parts cluster, without
permission to read a single object. Worse, it is cheap and unbounded --
re-seed on a returned placeholder id and keep walking.

So: a denied node leaves the result, every edge with a denied endpoint
leaves with it (an edge is a fact about both of its endpoints), and what
remains is an aggregate -- how many objects were walked, how many are not
shown, and the distinct reasons. That keeps the property that matters: the
viewer is told the picture is partial and by how much, but not *where* the
holes are. The counts do leak a coarse magnitude, which is the deliberate
price of not letting a filtered subgraph pass itself off as the whole graph.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from ..permissions import Scope, evaluate
from ..schema import Claim, Entity, Event
from .runtime import Runtime

log = logging.getLogger(__name__)

_MODELS = {"Entity": Entity, "Event": Event, "Claim": Claim}


class NeighbourhoodState(TypedDict, total=False):
    seed_ids: list[str]
    grant_token: str
    scope: dict
    hops: int
    candidates: list[dict]
    verdicts: dict[str, str | None]
    denials: list[dict]
    edges: list[list[str]]
    hop_of: dict[str, int]
    result: dict


@dataclass(slots=True)
class Neighbourhood:
    seed_ids: list[str]
    answered: bool
    text: str
    hops: int = 2
    #: Visible nodes only, seeds first. Denied nodes are absent, not blanked.
    nodes: list[dict] = field(default_factory=list)
    #: ``{"from", "type", "to"}``, direction as stored. Both endpoints are
    #: always present in ``nodes``.
    edges: list[dict] = field(default_factory=list)
    #: Distinct connectors among the visible nodes.
    sources: list[str] = field(default_factory=list)
    #: How many walked objects are not shown, and why -- no ids, no
    #: positions. See the module docstring.
    withheld: int = 0
    withheld_reasons: list[str] = field(default_factory=list)
    #: Edges dropped because at least one endpoint was withheld.
    withheld_edges: int = 0
    #: Everything the blind walk reached, visible or not.
    considered: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_neighbourhood_graph(runtime: Runtime):
    def authorize(state: NeighbourhoodState) -> dict:
        if state.get("scope") and not state.get("grant_token"):
            raise ValueError("a grant_token is required; a caller-supplied scope is not trusted")
        scope = runtime.gateway.introspect_scope(state["grant_token"])
        return {"scope": scope.model_dump(mode="json")}

    def walk(state: NeighbourhoodState) -> dict:
        """Permission-blind traversal, owner-constrained at every node."""
        scope = Scope.model_validate(state["scope"])
        owner_id = scope.owner_id
        seeds = list(dict.fromkeys(state["seed_ids"]))
        present = {s.id for s in runtime.store.get_many(owner_id, seeds)}
        if not present:
            return {"candidates": [], "edges": [], "hop_of": {}}

        reached = runtime.store.neighbour_ids(owner_id, sorted(present), hops=state.get("hops", 2))
        hop_of = {sid: 0 for sid in seeds if sid in present}
        hop_of.update({k: v for k, v in reached.items() if k not in hop_of})
        found = runtime.store.get_many(owner_id, list(hop_of))
        edges = runtime.store.edges_among(owner_id, list(hop_of))
        log.info("neighbourhood.walk nodes=%d edges=%d", len(found), len(edges))
        return {
            "candidates": [
                {"id": s.id, "label": s.label, "payload": s.node.model_dump(mode="json")}
                for s in found
            ],
            "edges": [list(e) for e in edges],
            "hop_of": hop_of,
        }

    def check_permissions(state: NeighbourhoodState) -> dict:
        """One ``evaluate`` per walked object, before anything is assembled."""
        scope = Scope.model_validate(state["scope"])
        now_ms = int(time.time() * 1000)
        verdicts: dict[str, str | None] = {}
        denials: list[dict] = []
        for candidate in state.get("candidates", []):
            node = _node_of(candidate)
            decision = evaluate(scope, node.acl, now_ms)
            verdicts[candidate["id"]] = None if decision.allowed else decision.reason.value
            if not decision.allowed:
                denials.append({"id": candidate["id"], "reason": decision.reason.value})
        log.info(
            "neighbourhood.permissions allowed=%d denied=%d",
            len(verdicts) - len(denials),
            len(denials),
        )
        return {"verdicts": verdicts, "denials": denials}

    def assemble(state: NeighbourhoodState) -> dict:
        seeds = list(dict.fromkeys(state["seed_ids"]))
        hops = state.get("hops", 2)
        candidates = state.get("candidates", [])
        verdicts = state.get("verdicts", {})
        denials = state.get("denials", [])
        hop_of = state.get("hop_of", {})
        walked = {c["id"]: _node_of(c) for c in candidates}
        reasons = sorted({d["reason"] for d in denials})

        if not walked:
            return {
                "result": Neighbourhood(
                    seed_ids=seeds,
                    answered=False,
                    hops=hops,
                    text=f"No object among {', '.join(seeds)!r} is present in this memory.",
                ).as_dict()
            }

        visible = {nid: node for nid, node in walked.items() if verdicts.get(nid) is None}
        # Both ends checked, from the same verdict map the filter used -- an
        # edge is a fact about its two endpoints, so it cannot outlive either.
        edges = [
            {"from": a, "type": rel, "to": b}
            for a, rel, b in [tuple(e) for e in state.get("edges", [])]
            if a in visible and b in visible
        ]
        withheld_edges = len(state.get("edges", [])) - len(edges)

        if not visible:
            pretty = ", ".join(r.replace("_", " ") for r in reasons)
            return {
                "result": Neighbourhood(
                    seed_ids=seeds,
                    answered=False,
                    hops=hops,
                    text=(
                        f"Declining to answer: {len(walked)} object(s) are in this "
                        f"neighbourhood, but none are within the requesting agent's "
                        f"scope ({pretty})."
                    ),
                    withheld=len(walked),
                    withheld_reasons=reasons,
                    withheld_edges=withheld_edges,
                    considered=len(walked),
                ).as_dict()
            }

        ordered = sorted(visible.values(), key=lambda n: (hop_of.get(n.id, 0), n.id))
        nodes = [_node_view(n, hop_of.get(n.id, 0)) for n in ordered]
        sources = sorted({s for v in nodes for s in v["sources"]})
        return {
            "result": Neighbourhood(
                seed_ids=seeds,
                answered=True,
                hops=hops,
                text=_text(seeds, nodes, edges, len(denials), sources),
                nodes=nodes,
                edges=edges,
                sources=sources,
                withheld=len(denials),
                withheld_reasons=reasons,
                withheld_edges=withheld_edges,
                considered=len(walked),
            ).as_dict()
        }

    graph = StateGraph(NeighbourhoodState)
    graph.add_node("authorize", authorize)
    graph.add_node("walk", walk)
    graph.add_node("check_permissions", check_permissions)
    graph.add_node("assemble", assemble)
    graph.add_edge(START, "authorize")
    graph.add_edge("authorize", "walk")
    graph.add_edge("walk", "check_permissions")
    graph.add_edge("check_permissions", "assemble")
    graph.add_edge("assemble", END)
    return graph.compile(checkpointer=MemorySaver())


def _node_of(candidate: dict):
    return _MODELS[candidate["label"]].model_validate(candidate["payload"])


def _node_view(node, hops: int) -> dict:
    view = {
        "id": node.id,
        "label": type(node).__name__,
        "hops": hops,
        "sources": list(node.acl.sources),
        "occurred_at_ms": node.acl.occurred_at_ms,
        "status": None,
        "is_commitment": False,
    }
    if isinstance(node, Event):
        view["text"] = node.summary
        view["url"] = node.source.url
    elif isinstance(node, Claim):
        view["text"] = node.statement
        view["status"] = node.status.value
        view["is_commitment"] = node.commitment is not None
    else:
        view["text"] = f"{node.kind.value}: {node.name}"
    return view


def _text(
    seeds: list[str], nodes: list[dict], edges: list[dict], withheld: int, sources: list[str]
) -> str:
    head = (
        f"{len(nodes)} node(s) and {len(edges)} edge(s) around "
        f"{', '.join(seeds)} across {len(sources)} source(s) "
        f"({', '.join(sources) or 'none visible'})."
    )
    if withheld:
        head += (
            f" {withheld} further object(s) in this neighbourhood are outside "
            "the grant and are not shown -- neither they nor their edges are "
            "counted above, so this picture is partial."
        )
    return head


def neighbourhood(
    runtime: Runtime,
    seed_ids: list[str],
    grant_token: str,
    hops: int = 2,
    thread_id: str | None = None,
) -> Neighbourhood:
    """Nodes and edges within ``hops`` of ``seed_ids``, permission-filtered.

    Denied objects are dropped, not blanked; see the module docstring.
    """
    graph = build_neighbourhood_graph(runtime)
    config = {
        "configurable": {"thread_id": thread_id or f"neighbourhood:{','.join(seed_ids)}:{hops}"}
    }
    final = graph.invoke(
        {"seed_ids": list(seed_ids), "grant_token": grant_token, "hops": hops}, config=config
    )
    return Neighbourhood(**final["result"])
