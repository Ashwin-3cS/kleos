"""Ingestion graph: fetch -> extract -> resolve -> encrypt -> write.

A StateGraph rather than a straight function because ingestion is bursty
and long-running: connecting a source means backfilling history in bursts,
each node is individually retryable, and the checkpointer lets a run resume
mid-pipeline after a restart instead of re-pulling and re-extracting
everything. Later phases add an approval gate before ``write``.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Annotated, Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from ..connectors import get_connector
from ..enums import ClaimStatus
from ..resolution.resolver import Resolver
from ..schema import Candidate, RawRecord
from .runtime import Runtime

log = logging.getLogger(__name__)


def _extend(left: list, right: list) -> list:
    return [*left, *right]


class IngestionState(TypedDict, total=False):
    owner_id: str
    source: str
    since_ms: int
    session_tokens: dict[str, str]
    records: list[dict]
    candidates: list[dict]
    sealed: dict[str, dict]
    written: Annotated[list[str], _extend]
    supersessions: list[list[str]]
    contradictions: list[list[str]]
    errors: Annotated[list[str], _extend]


@dataclass(slots=True)
class IngestionResult:
    owner_id: str
    records: int = 0
    entities: int = 0
    events: int = 0
    claims: int = 0
    sealed: int = 0
    supersessions: list[tuple[str, str]] = field(default_factory=list)
    contradictions: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner_id": self.owner_id,
            "records": self.records,
            "entities": self.entities,
            "events": self.events,
            "claims": self.claims,
            "sealed": self.sealed,
            "supersessions": [list(p) for p in self.supersessions],
            "contradictions": [list(p) for p in self.contradictions],
            "errors": self.errors,
        }


def build_ingestion_graph(runtime: Runtime):
    resolver = Resolver(runtime.store)

    def fetch(state: IngestionState) -> dict:
        connector = get_connector(state["source"], runtime.settings)
        records = list(connector.fetch(state.get("since_ms", 0)))
        log.info("ingestion.fetch source=%s records=%d", state["source"], len(records))
        return {"records": [r.model_dump(mode="json") for r in records]}

    def extract(state: IngestionState) -> dict:
        owner_id = state["owner_id"]
        candidates = []
        for raw in state.get("records", []):
            record = RawRecord.model_validate(raw)
            candidate = runtime.extractor.extract(owner_id, record)
            candidates.append(candidate.model_dump(mode="json"))
        log.info("ingestion.extract candidates=%d", len(candidates))
        return {"candidates": candidates}

    def resolve(state: IngestionState) -> dict:
        owner_id = state["owner_id"]
        merged: list[dict] = []
        supersessions: list[list[str]] = []
        contradictions: list[list[str]] = []
        candidates = [Candidate.model_validate(raw) for raw in state.get("candidates", [])]
        for candidate, resolution in zip(
            candidates, resolver.resolve_batch(owner_id, candidates), strict=True
        ):
            candidate.claims = resolution.new_claims
            merged.append(candidate.model_dump(mode="json"))
            supersessions += [list(p) for p in resolution.supersessions]
            contradictions += [list(p) for p in resolution.contradictions]
        log.info(
            "ingestion.resolve supersedes=%d contradicts=%d",
            len(supersessions),
            len(contradictions),
        )
        return {
            "candidates": merged,
            "supersessions": supersessions,
            "contradictions": contradictions,
        }

    def encrypt(state: IngestionState) -> dict:
        """Hands sensitive raw bodies to the enclave, via the gateway.

        This is the only point in the whole pipeline that touches the trust
        boundary. If the enclave is unreachable the record is not written in
        the clear as a fallback -- the error is recorded and the body stays
        out of the store.
        """
        sealed: dict[str, dict] = {}
        errors: list[str] = []
        sensitive = {
            r["external_id"]: r for r in state.get("records", []) if r.get("sensitive")
        }
        if not sensitive:
            return {"sealed": sealed}

        session = state.get("session_tokens", {}).get("session_token")
        if session:
            runtime.gateway.adopt_session(session)

        for external_id, record in sensitive.items():
            try:
                result = runtime.gateway.seal_encrypt(record["body"].encode())
            except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
                errors.append(f"seal failed for {external_id}: {exc}")
                continue
            sealed[external_id] = {
                "ref": result.ref.model_dump(mode="json"),
                "ciphertext_b64": base64.b64encode(result.ciphertext).decode(),
                "attestation": result.attestation,
            }
        log.info("ingestion.encrypt sealed=%d errors=%d", len(sealed), len(errors))
        return {"sealed": sealed, "errors": errors}

    def write(state: IngestionState) -> dict:
        sealed = state.get("sealed", {})
        written: list[str] = []
        errors: list[str] = []

        for raw in state.get("candidates", []):
            candidate = Candidate.model_validate(raw)

            for entity in candidate.entities:
                _upsert(runtime, entity, entity.name + " " + " ".join(entity.aliases))
                written.append(entity.id)

            for event in candidate.events:
                blob = sealed.get(event.source.external_id)
                if blob is not None:
                    event.encrypted_content = _ref_of(blob)
                    event.body = None
                elif _needs_seal(state, event.source.external_id):
                    errors.append(f"skipped {event.id}: sensitive body was not sealed")
                    continue
                _upsert(runtime, event, f"{event.summary} {event.body or ''}")
                written.append(event.id)
                for entity_id in event.entity_ids:
                    runtime.store.link(event.id, "MENTIONS", entity_id)
                for citation in event.provenance.citations:
                    if citation.event_id != event.id:
                        runtime.store.link(event.id, "CITES", citation.event_id)

            for claim in candidate.claims:
                _upsert(runtime, claim, claim.statement)
                written.append(claim.id)
                for entity_id in claim.subject_entity_ids:
                    runtime.store.link(claim.id, "ABOUT", entity_id)
                for citation in claim.provenance.citations:
                    runtime.store.link(claim.id, "CITES", citation.event_id)
                for superseded in claim.supersedes:
                    runtime.store.link(claim.id, "SUPERSEDES", superseded)
                    runtime.store.set_claim_status(superseded, ClaimStatus.SUPERSEDED.value)
                for conflicting in claim.contradicts:
                    runtime.store.link(claim.id, "CONTRADICTS", conflicting)

        log.info("ingestion.write nodes=%d", len(written))
        return {"written": written, "errors": errors}

    graph = StateGraph(IngestionState)
    graph.add_node("fetch", fetch)
    graph.add_node("extract", extract)
    graph.add_node("resolve", resolve)
    graph.add_node("encrypt", encrypt)
    graph.add_node("write", write)
    graph.add_edge(START, "fetch")
    graph.add_edge("fetch", "extract")
    graph.add_edge("extract", "resolve")
    graph.add_edge("resolve", "encrypt")
    graph.add_edge("encrypt", "write")
    graph.add_edge("write", END)
    return graph.compile(checkpointer=MemorySaver())


def _needs_seal(state: IngestionState, external_id: str) -> bool:
    return any(
        r["external_id"] == external_id and r.get("sensitive")
        for r in state.get("records", [])
    )


def _ref_of(blob: dict):
    from ..schema import EncryptedContentRef

    return EncryptedContentRef.model_validate(blob["ref"])


def _upsert(runtime: Runtime, node, text: str) -> None:
    runtime.store.upsert(node, runtime.embedder.embed(text))


def run_ingestion(
    runtime: Runtime,
    owner_id: str,
    source: str = "mock",
    since_ms: int = 0,
    session_token: str | None = None,
    thread_id: str | None = None,
) -> IngestionResult:
    graph = build_ingestion_graph(runtime)
    config = {"configurable": {"thread_id": thread_id or f"ingest:{owner_id}:{source}"}}
    final = graph.invoke(
        {
            "owner_id": owner_id,
            "source": source,
            "since_ms": since_ms,
            "session_tokens": {"session_token": session_token} if session_token else {},
        },
        config=config,
    )

    candidates = [Candidate.model_validate(c) for c in final.get("candidates", [])]
    return IngestionResult(
        owner_id=owner_id,
        records=len(final.get("records", [])),
        entities=sum(len(c.entities) for c in candidates),
        events=sum(len(c.events) for c in candidates),
        claims=sum(len(c.claims) for c in candidates),
        sealed=len(final.get("sealed", {})),
        supersessions=[tuple(p) for p in final.get("supersessions", [])],
        contradictions=[tuple(p) for p in final.get("contradictions", [])],
        errors=final.get("errors", []),
    )
