"""History reads: why a decision shifted, and what context it hangs off.

Both are *reads over what ingestion already wrote*. A claim that supersedes
another, the ``SUPERSEDES``/``CONTRADICTS`` edges between them, and the
citation chain back to source events all exist in the graph the moment
ingestion finishes; what was missing is a read that makes them legible.
Neither of these adds a node type, and neither re-derives anything.

Both follow the query graph's shape exactly -- traverse blind, then a
separate node applies ``permissions.evaluate`` per object, so the assembler
structurally cannot see an unchecked claim. This matters more here than it
does for a plain query: a decision is often superseded *because* of evidence
from a source the asking agent has no grant for, which is both the
interesting case and the leak.

**A denied link is withheld, not dropped and not a truncation point.**
Dropping it would silently misreport the record -- a three-step history
would come back looking like a two-step one, which is worse than a refusal
because the agent cannot tell it happened. Truncating the walk at the first
denial would additionally hide permitted claims further along for no reason.
So the step stays, both ids stay (ids are opaque, and the query graph
already returns denied candidate ids with reasons), and everything that is
*content* goes: the statement, the timestamps, the elapsed interval and,
above all, the newly-appearing citations with their source refs -- that
citation is precisely the un-granted source's contribution.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from ..permissions import Scope, evaluate
from ..schema import Citation, Claim, Entity, Event
from .runtime import Runtime

log = logging.getLogger(__name__)

_MODELS = {"Entity": Entity, "Event": Event, "Claim": Claim}

_DAY_MS = 86_400_000


class HistoryState(TypedDict, total=False):
    object_id: str
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
class ShiftHistory:
    claim_id: str
    answered: bool
    text: str
    #: Every claim in the supersession run, oldest first; withheld ones are
    #: present as ``{"id": ..., "withheld": true, "reason": ...}``.
    chain: list[dict] = field(default_factory=list)
    #: One entry per ``SUPERSEDES`` link, oldest first.
    steps: list[dict] = field(default_factory=list)
    #: Unresolved ``CONTRADICTS`` links touching the chain.
    conflicts: list[dict] = field(default_factory=list)
    #: ``reconciled_into`` targets, where the resolver set one.
    reconciliations: list[dict] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    considered: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ContextChain:
    object_id: str
    answered: bool
    text: str
    hops: int = 0
    #: Objects reached over ``CITES``, nearest first; withheld ones carry an
    #: id and a reason only.
    nodes: list[dict] = field(default_factory=list)
    #: ``[from_id, to_id]`` pairs, direction as stored (citer -> cited).
    edges: list[list[str]] = field(default_factory=list)
    #: Distinct connectors among the objects this agent may see.
    sources: list[str] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    considered: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# -- shared nodes -------------------------------------------------------


def _authorize(runtime: Runtime):
    def authorize(state: HistoryState) -> dict:
        if state.get("scope") and not state.get("grant_token"):
            raise ValueError("a grant_token is required; a caller-supplied scope is not trusted")
        scope = runtime.gateway.introspect_scope(state["grant_token"])
        return {"scope": scope.model_dump(mode="json")}

    return authorize


def _check_permissions(state: HistoryState) -> dict:
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
        "history.permissions allowed=%d denied=%d",
        len(verdicts) - len(denials),
        len(denials),
    )
    return {"verdicts": verdicts, "denials": denials}


def _node_of(candidate: dict):
    return _MODELS[candidate["label"]].model_validate(candidate["payload"])


def _stored(candidates: list[dict]) -> dict[str, Any]:
    return {c["id"]: _node_of(c) for c in candidates}


# -- why did this shift -------------------------------------------------


def build_shift_graph(runtime: Runtime):
    def walk(state: HistoryState) -> dict:
        """Permission-blind traversal, exactly as retrieval is."""
        scope = Scope.model_validate(state["scope"])
        owner_id = scope.owner_id
        chain = runtime.store.supersession_chain(owner_id, state["object_id"])
        ids = [s.id for s in chain]

        extra: set[str] = set()
        for stored in chain:
            claim = stored.node
            if isinstance(claim, Claim) and claim.reconciled_into:
                extra.add(claim.reconciled_into)
        links = runtime.store.conflict_links(owner_id, ids) if ids else []
        for a, b in links:
            extra.update({a, b})
        extra.difference_update(ids)

        found = chain + (runtime.store.get_many(owner_id, sorted(extra)) if extra else [])
        log.info("history.shift chain=%d conflicts=%d", len(chain), len(links))
        return {
            "candidates": [
                {
                    "id": s.id,
                    "label": s.label,
                    "payload": s.node.model_dump(mode="json"),
                }
                for s in found
                if s.label == "Claim"
            ],
            "edges": [list(pair) for pair in links],
            "hop_of": {s.id: 0 for s in chain},
        }

    def assemble(state: HistoryState) -> dict:
        claim_id = state["object_id"]
        candidates = state.get("candidates", [])
        verdicts = state.get("verdicts", {})
        denials = state.get("denials", [])
        claims: dict[str, Claim] = _stored(candidates)
        in_chain = state.get("hop_of", {})

        if not claims:
            return {
                "result": ShiftHistory(
                    claim_id=claim_id,
                    answered=False,
                    text=f"No claim {claim_id!r} is present in this memory.",
                ).as_dict()
            }
        if all(verdicts.get(cid) is not None for cid in claims):
            reasons = sorted({d["reason"] for d in denials})
            pretty = ", ".join(r.replace("_", " ") for r in reasons)
            return {
                "result": ShiftHistory(
                    claim_id=claim_id,
                    answered=False,
                    text=(
                        f"Declining to answer: {len(claims)} claim(s) make up this "
                        f"decision's history, but none are within the requesting "
                        f"agent's scope ({pretty})."
                    ),
                    denied=denials,
                    considered=len(claims),
                ).as_dict()
            }

        ordered = sorted(
            (c for cid, c in claims.items() if cid in in_chain),
            key=lambda c: (c.asserted_at_ms, c.id),
        )
        chain = [_claim_view(c, verdicts.get(c.id)) for c in ordered]

        steps = []
        for claim in sorted(claims.values(), key=lambda c: (c.asserted_at_ms, c.id)):
            for superseded_id in claim.supersedes:
                earlier = claims.get(superseded_id)
                if earlier is None:
                    continue
                steps.append(_step(claim, earlier, verdicts))

        conflicts = [
            {
                "claim": _claim_view(claims[a], verdicts.get(a)),
                "contradicts": _claim_view(claims[b], verdicts.get(b)),
            }
            for a, b in [tuple(e) for e in state.get("edges", [])]
            if a in claims and b in claims
        ]
        reconciliations = [
            {
                "claim": _claim_view(c, verdicts.get(c.id)),
                "reconciled_into": (
                    _claim_view(claims[c.reconciled_into], verdicts.get(c.reconciled_into))
                    if c.reconciled_into in claims
                    else {"id": c.reconciled_into}
                ),
            }
            for c in ordered
            if c.reconciled_into
        ]

        return {
            "result": ShiftHistory(
                claim_id=claim_id,
                answered=True,
                text=_shift_text(claim_id, steps, conflicts),
                chain=chain,
                steps=steps,
                conflicts=conflicts,
                reconciliations=reconciliations,
                denied=denials,
                considered=len(claims),
            ).as_dict()
        }

    return _compile(runtime, walk, assemble)


def _step(superseding: Claim, superseded: Claim, verdicts: dict[str, str | None]) -> dict:
    """One ``SUPERSEDES`` link, with the evidence that is new in the superseder.

    The interesting part is not that B replaced A -- the caller can see that
    -- but *what appeared* that moved the decision: the citations present in
    B and absent from A.
    """
    both_visible = verdicts.get(superseding.id) is None and verdicts.get(superseded.id) is None
    known = {c.event_id for c in superseded.provenance.citations}
    new = [c for c in superseding.provenance.citations if c.event_id not in known]
    return {
        "superseding": _claim_view(superseding, verdicts.get(superseding.id)),
        "superseded": _claim_view(superseded, verdicts.get(superseded.id)),
        # Both of these are content of the two claims, so neither survives a
        # denial at either end: an interval leaks when a withheld claim was
        # asserted, and a new citation leaks the un-granted source itself.
        "elapsed_ms": (
            superseding.asserted_at_ms - superseded.asserted_at_ms if both_visible else None
        ),
        "new_citations": [_citation_view(c) for c in new] if both_visible else [],
        "withheld": not both_visible,
    }


def _claim_view(claim: Claim, denied_reason: str | None) -> dict:
    if denied_reason is not None:
        return {"id": claim.id, "withheld": True, "reason": denied_reason}
    return {
        "id": claim.id,
        "statement": claim.statement,
        "status": claim.status.value,
        "asserted_at_ms": claim.asserted_at_ms,
        "sources": list(claim.acl.sources),
        "is_commitment": claim.commitment is not None,
    }


def _citation_view(citation: Citation) -> dict:
    return {
        "event_id": citation.event_id,
        "connector": citation.source.connector,
        "external_id": citation.source.external_id,
        "url": citation.source.url,
        "occurred_at_ms": citation.source.occurred_at_ms,
        "ingested_at_ms": citation.source.ingested_at_ms,
        "quote": citation.quote,
    }


def _shift_text(claim_id: str, steps: list[dict], conflicts: list[dict]) -> str:
    if not steps and not conflicts:
        return f"{claim_id} has not been superseded or contradicted."
    lines = [f"{claim_id}: {len(steps)} supersession(s), {len(conflicts)} open conflict(s)."]
    for n, step in enumerate(steps, start=1):
        before, after = step["superseded"], step["superseding"]
        if step["withheld"]:
            lines.append(
                f"{n}. {_short(after)} superseded {_short(before)} "
                "-- details withheld (out of scope)."
            )
            continue
        gap = step["elapsed_ms"] / _DAY_MS
        evidence = ", ".join(
            f"{c['connector']}/{c['external_id']}" for c in step["new_citations"]
        )
        lines.append(
            f"{n}. after {gap:.1f}d, {_short(after)} superseded {_short(before)}"
            + (f" -- new evidence: {evidence}." if evidence else " -- no new citations.")
        )
    for conflict in conflicts:
        lines.append(
            f"! {_short(conflict['claim'])} still contradicts "
            f"{_short(conflict['contradicts'])}."
        )
    return "\n".join(lines)


def _short(view: dict) -> str:
    if view.get("withheld"):
        return f"[withheld {view['id']}]"
    return f'"{view["statement"]}" ({view["id"]})'


# -- context chains -----------------------------------------------------


def build_context_graph(runtime: Runtime):
    def walk(state: HistoryState) -> dict:
        scope = Scope.model_validate(state["scope"])
        owner_id = scope.owner_id
        seed_id = state["object_id"]
        hop_of, edges = runtime.store.cites_chain(
            owner_id, seed_id, hops=state.get("hops", 3)
        )
        hop_of = {seed_id: 0, **{k: v for k, v in hop_of.items() if k != seed_id}}
        found = runtime.store.get_many(owner_id, list(hop_of))
        log.info("history.context nodes=%d edges=%d", len(found), len(edges))
        return {
            "candidates": [
                {"id": s.id, "label": s.label, "payload": s.node.model_dump(mode="json")}
                for s in found
            ],
            "edges": [list(pair) for pair in edges],
            "hop_of": hop_of,
        }

    def assemble(state: HistoryState) -> dict:
        seed_id = state["object_id"]
        candidates = state.get("candidates", [])
        verdicts = state.get("verdicts", {})
        denials = state.get("denials", [])
        hop_of = state.get("hop_of", {})
        nodes = _stored(candidates)

        if not nodes:
            return {
                "result": ContextChain(
                    object_id=seed_id,
                    answered=False,
                    text=f"No object {seed_id!r} is present in this memory.",
                    hops=state.get("hops", 3),
                ).as_dict()
            }
        if all(verdicts.get(nid) is not None for nid in nodes):
            reasons = sorted({d["reason"] for d in denials})
            pretty = ", ".join(r.replace("_", " ") for r in reasons)
            return {
                "result": ContextChain(
                    object_id=seed_id,
                    answered=False,
                    text=(
                        f"Declining to answer: {len(nodes)} object(s) form this "
                        f"context chain, but none are within the requesting "
                        f"agent's scope ({pretty})."
                    ),
                    hops=state.get("hops", 3),
                    denied=denials,
                    considered=len(nodes),
                ).as_dict()
            }

        ordered = sorted(nodes.values(), key=lambda n: (hop_of.get(n.id, 0), n.id))
        views = [_node_view(n, hop_of.get(n.id, 0), verdicts.get(n.id)) for n in ordered]
        sources = sorted({s for v in views for s in v.get("sources", [])})
        return {
            "result": ContextChain(
                object_id=seed_id,
                answered=True,
                text=_context_text(seed_id, views, sources),
                hops=state.get("hops", 3),
                nodes=views,
                edges=[list(e) for e in state.get("edges", [])],
                sources=sources,
                denied=denials,
                considered=len(nodes),
            ).as_dict()
        }

    return _compile(runtime, walk, assemble)


def _node_view(node, hops: int, denied_reason: str | None) -> dict:
    if denied_reason is not None:
        return {"id": node.id, "hops": hops, "withheld": True, "reason": denied_reason}
    view = {
        "id": node.id,
        "label": type(node).__name__,
        "hops": hops,
        "sources": list(node.acl.sources),
    }
    if isinstance(node, Event):
        view["summary"] = node.summary
        view["source"] = _source_view(node)
    elif isinstance(node, Claim):
        view["statement"] = node.statement
        view["status"] = node.status.value
    else:
        view["name"] = node.name
    return view


def _source_view(event: Event) -> dict:
    """The stored event's own ``SourceRef``, not the citing object's.

    A cross-source citation records the id of the event it points at, but
    its timestamps are those of the reference; the cited event knows its own
    provenance, and that is what a chain should report.
    """
    return {
        "connector": event.source.connector,
        "external_id": event.source.external_id,
        "url": event.source.url,
        "occurred_at_ms": event.source.occurred_at_ms,
        "ingested_at_ms": event.source.ingested_at_ms,
    }


def _context_text(seed_id: str, views: list[dict], sources: list[str]) -> str:
    reach = [v for v in views if v["hops"] > 0]
    if not reach:
        return f"{seed_id} cites nothing and nothing cites it."
    head = (
        f"{seed_id}: {len(reach)} object(s) in the citation chain "
        f"across {len(sources)} source(s) ({', '.join(sources) or 'none visible'})."
    )
    lines = [head]
    for view in views:
        if view.get("withheld"):
            lines.append(f"- [{view['hops']} hop] withheld ({view['reason']}) {view['id']}")
            continue
        label = view.get("summary") or view.get("statement") or view.get("name") or ""
        source = view.get("source", {}).get("connector") or ",".join(view["sources"])
        lines.append(f"- [{view['hops']} hop] {source}: {label} ({view['id']})")
    return "\n".join(lines)


# -- wiring -------------------------------------------------------------


def _compile(runtime: Runtime, walk, assemble):
    graph = StateGraph(HistoryState)
    graph.add_node("authorize", _authorize(runtime))
    graph.add_node("walk", walk)
    graph.add_node("check_permissions", _check_permissions)
    graph.add_node("assemble", assemble)
    graph.add_edge(START, "authorize")
    graph.add_edge("authorize", "walk")
    graph.add_edge("walk", "check_permissions")
    graph.add_edge("check_permissions", "assemble")
    graph.add_edge("assemble", END)
    return graph.compile(checkpointer=MemorySaver())


def why_did_this_shift(
    runtime: Runtime,
    claim_id: str,
    grant_token: str,
    thread_id: str | None = None,
) -> ShiftHistory:
    """The ordered supersession history of one decision, with the evidence
    that moved it at each step."""
    graph = build_shift_graph(runtime)
    config = {"configurable": {"thread_id": thread_id or f"shift:{claim_id}"}}
    final = graph.invoke({"object_id": claim_id, "grant_token": grant_token}, config=config)
    return ShiftHistory(**final["result"])


def context_chain(
    runtime: Runtime,
    object_id: str,
    grant_token: str,
    hops: int = 3,
    thread_id: str | None = None,
) -> ContextChain:
    """What one object was derived from, and what was derived from it,
    walked over ``CITES`` and therefore across sources."""
    graph = build_context_graph(runtime)
    config = {"configurable": {"thread_id": thread_id or f"context:{object_id}:{hops}"}}
    final = graph.invoke(
        {"object_id": object_id, "grant_token": grant_token, "hops": hops}, config=config
    )
    return ContextChain(**final["result"])
