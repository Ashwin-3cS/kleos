"""Query graph: retrieve -> permission-check -> assemble (or decline).

The permission check is a node of its own, between retrieval and assembly,
so that it is structurally impossible for the assembler to see a candidate
that was not checked. A query that retrieves plenty but passes nothing
declines explicitly and says why -- it never falls back to answering from
what it happened to remember.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from ..permissions import Scope, evaluate
from ..retrieval.index import MemoryRetriever
from ..schema import Claim, Entity, Event
from .runtime import Runtime

log = logging.getLogger(__name__)


class QueryState(TypedDict, total=False):
    question: str
    grant_token: str
    scope: dict
    top_k: int
    candidates: list[dict]
    permitted: list[dict]
    denials: list[dict]
    answer: dict


@dataclass(slots=True)
class AnswerCitation:
    object_id: str
    label: str
    source: str
    url: str | None
    occurred_at_ms: int
    ingested_at_ms: int | None


@dataclass(slots=True)
class QueryAnswer:
    question: str
    answered: bool
    text: str
    citations: list[AnswerCitation] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    considered: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "answered": self.answered,
            "text": self.text,
            "citations": [asdict(c) for c in self.citations],
            "denied": self.denied,
            "considered": self.considered,
        }


def build_query_graph(runtime: Runtime):
    def authorize(state: QueryState) -> dict:
        """Resolves the grant token into the authoritative scope.

        The caller's own claim about its scope is never used: the gateway
        minted the grant against an owner session and is the only thing
        that can say what it covers.
        """
        if state.get("scope") and not state.get("grant_token"):
            raise ValueError("a grant_token is required; a caller-supplied scope is not trusted")
        scope = runtime.gateway.introspect_scope(state["grant_token"])
        return {"scope": scope.model_dump(mode="json")}

    def retrieve(state: QueryState) -> dict:
        scope = Scope.model_validate(state["scope"])
        retriever = MemoryRetriever(
            runtime.store,
            runtime.embedder,
            owner_id=scope.owner_id,
            top_k=state.get("top_k", 8),
        )
        ranked = retriever.retrieve_stored(state["question"])
        log.info("query.retrieve candidates=%d", len(ranked))
        return {
            "candidates": [
                {
                    "id": r.node.id,
                    "label": r.node.label,
                    "score": r.score,
                    "payload": r.node.node.model_dump(mode="json"),
                }
                for r in ranked
            ]
        }

    def check_permissions(state: QueryState) -> dict:
        scope = Scope.model_validate(state["scope"])
        now_ms = int(time.time() * 1000)
        permitted, denials = [], []
        for candidate in state.get("candidates", []):
            node = _node_of(candidate)
            decision = evaluate(scope, node.acl, now_ms)
            if decision.allowed:
                permitted.append(candidate)
            else:
                denials.append({"id": candidate["id"], "reason": decision.reason.value})
        log.info("query.permissions allowed=%d denied=%d", len(permitted), len(denials))
        return {"permitted": permitted, "denials": denials}

    def assemble(state: QueryState) -> dict:
        permitted = state.get("permitted", [])
        denials = state.get("denials", [])
        considered = len(state.get("candidates", []))

        if not permitted:
            reasons = sorted({d["reason"] for d in denials})
            text = _decline_text(considered, reasons)
            return {
                "answer": QueryAnswer(
                    question=state["question"],
                    answered=False,
                    text=text,
                    denied=denials,
                    considered=considered,
                ).as_dict()
            }

        citations = [_citation_of(c) for c in permitted]
        lines = [_line_of(c) for c in permitted]
        text = "\n".join(lines)
        return {
            "answer": QueryAnswer(
                question=state["question"],
                answered=True,
                text=text,
                citations=citations,
                denied=denials,
                considered=considered,
            ).as_dict()
        }

    graph = StateGraph(QueryState)
    graph.add_node("authorize", authorize)
    graph.add_node("retrieve", retrieve)
    graph.add_node("check_permissions", check_permissions)
    graph.add_node("assemble", assemble)
    graph.add_edge(START, "authorize")
    graph.add_edge("authorize", "retrieve")
    graph.add_edge("retrieve", "check_permissions")
    graph.add_edge("check_permissions", "assemble")
    graph.add_edge("assemble", END)
    return graph.compile(checkpointer=MemorySaver())


_MODELS = {"Entity": Entity, "Event": Event, "Claim": Claim}


def _node_of(candidate: dict):
    return _MODELS[candidate["label"]].model_validate(candidate["payload"])


def _decline_text(considered: int, reasons: list[str]) -> str:
    if considered == 0:
        return "No memory matches this question."
    pretty = ", ".join(r.replace("_", " ") for r in reasons)
    return (
        f"Declining to answer: {considered} candidate memory object(s) matched, "
        f"but none are within the requesting agent's scope ({pretty})."
    )


def _line_of(candidate: dict) -> str:
    node = _node_of(candidate)
    if isinstance(node, Claim):
        marker = "" if node.status.value == "active" else f" [{node.status.value}]"
        return f"- {node.statement}{marker} ({node.id})"
    if isinstance(node, Event):
        return f"- {node.summary} ({node.id})"
    return f"- {node.kind.value}: {node.name} ({node.id})"


def _citation_of(candidate: dict) -> AnswerCitation:
    node = _node_of(candidate)
    first = node.provenance.citations[0] if node.provenance.citations else None
    return AnswerCitation(
        object_id=node.id,
        label=candidate["label"],
        source=",".join(node.acl.sources),
        url=first.source.url if first else None,
        occurred_at_ms=node.acl.occurred_at_ms,
        ingested_at_ms=first.source.ingested_at_ms if first else None,
    )


def run_query(
    runtime: Runtime,
    question: str,
    grant_token: str,
    top_k: int = 8,
    thread_id: str | None = None,
) -> QueryAnswer:
    graph = build_query_graph(runtime)
    config = {"configurable": {"thread_id": thread_id or f"query:{abs(hash(question))}"}}
    final = graph.invoke(
        {"question": question, "grant_token": grant_token, "top_k": top_k},
        config=config,
    )
    answer = final["answer"]
    return QueryAnswer(
        question=answer["question"],
        answered=answer["answered"],
        text=answer["text"],
        citations=[AnswerCitation(**c) for c in answer["citations"]],
        denied=answer["denied"],
        considered=answer["considered"],
    )
