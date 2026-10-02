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

from ..enums import ClaimStatus
from ..resolution.resolver import Resolver
from ..schema import Candidate, RawRecord
from ..storage.content import text_for_index
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
    #: Counted in the ``write`` node, by label, as rows actually land.
    written_by_label: dict[str, int]
    skipped: int
    supersessions: list[list[str]]
    contradictions: list[list[str]]
    errors: Annotated[list[str], _extend]


@dataclass(slots=True)
class IngestionResult:
    """What ingestion *wrote*, not what it considered.

    The counts come from the ``write`` node as rows land, not from the
    candidate set. Those two numbers differ exactly when something went
    wrong -- an event whose sensitive body could not be sealed is skipped
    rather than stored in the clear -- and a report that counts candidates
    says "7 events" on a run that stored six, which is the one thing an
    ingestion report must not do.
    """

    owner_id: str
    records: int = 0
    entities: int = 0
    events: int = 0
    claims: int = 0
    sealed: int = 0
    #: Objects dropped before the write, each with a reason in ``errors``.
    skipped: int = 0
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
            "skipped": self.skipped,
            "supersessions": [list(p) for p in self.supersessions],
            "contradictions": [list(p) for p in self.contradictions],
            "errors": self.errors,
        }


def build_ingestion_graph(runtime: Runtime):
    # Stored claims are sealed at rest, so the resolver is handed the means to
    # read them back -- otherwise it would compare plaintext against ciphertext
    # and never notice a decision being superseded (ADR 0010).
    resolver = Resolver(runtime.store, unseal=runtime.content.unseal_node)

    def fetch(state: IngestionState) -> dict:
        source = state["source"]
        if not runtime.settings.source_enabled(source):
            raise ValueError(f"source {source!r} is not enabled in this deployment")
        connector = runtime.registry.connector(source, runtime.settings)
        records = list(connector.fetch(state["owner_id"], state.get("since_ms", 0)))
        log.info("ingestion.fetch source=%s records=%d", source, len(records))
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
        """Persists the resolved batch, and the sealed bytes it depends on.

        The counts returned here are what *landed*, label by label, because
        the alternative -- counting candidates -- reports a success number for
        a run that skipped something. An event whose sensitive body could not
        be sealed is skipped, never downgraded to a plaintext write.
        """
        owner_id = state["owner_id"]
        sealed = state.get("sealed", {})
        written: list[str] = []
        errors: list[str] = []
        # Distinct ids, not upsert calls. An entity mentioned in five records
        # is upserted five times and is one node; reporting five would be the
        # same overcount in the other direction from counting candidates.
        touched: dict[str, set[str]] = {"entities": set(), "events": set(), "claims": set()}
        skipped = 0

        def link(from_id: str, rel: str, to_id: str) -> None:
            # An unwritten endpoint is ordinary: a citation can name an event
            # from a record this batch skipped, or one a later batch brings in.
            # A *cross-owner* endpoint is not ordinary, and `link` refuses it
            # either way -- so a miss is logged at debug and not an error.
            if not runtime.store.link(owner_id, from_id, rel, to_id):
                log.debug("ingestion.write unlinked %s-[:%s]->%s", from_id, rel, to_id)

        # One batched write for every sealed body in this run, before anything
        # else. Batching is the point rather than an optimisation: a sealed
        # record body is a few kilobytes, per-blob encoding overhead dominates
        # at that size, and a Quilt removes it (ADR 0008). A run that seals 400
        # transcripts writes one container, not 400 blobs.
        refs_by_external_id, blob_errors = _persist_sealed(runtime, owner_id, sealed)
        errors += blob_errors

        for raw in state.get("candidates", []):
            candidate = Candidate.model_validate(raw)

            for entity in candidate.entities:
                _upsert(runtime, entity)
                written.append(entity.id)
                touched["entities"].add(entity.id)

            for event in candidate.events:
                if event.source.external_id in sealed:
                    ref = refs_by_external_id.get(event.source.external_id)
                    if ref is None:
                        # Same rule as a failed seal: no fallback that writes the
                        # plaintext body. A ref whose bytes were never stored is
                        # worse than a missing event -- it reads as recoverable.
                        errors.append(f"skipped {event.id}: sealed body not persisted")
                        skipped += 1
                        continue
                    event.encrypted_content = ref
                    event.body = None
                elif _needs_seal(state, event.source.external_id):
                    errors.append(f"skipped {event.id}: sensitive body was not sealed")
                    skipped += 1
                    continue
                _upsert(runtime, event)
                written.append(event.id)
                touched["events"].add(event.id)
                for entity_id in event.entity_ids:
                    link(event.id, "MENTIONS", entity_id)
                for citation in event.provenance.citations:
                    if citation.event_id != event.id:
                        link(event.id, "CITES", citation.event_id)

            for claim in candidate.claims:
                _upsert(runtime, claim)
                written.append(claim.id)
                touched["claims"].add(claim.id)
                for entity_id in claim.subject_entity_ids:
                    link(claim.id, "ABOUT", entity_id)
                if claim.commitment is not None:
                    link(claim.id, "OWED_BY", claim.commitment.owed_by_entity_id)
                    if claim.commitment.owed_to_entity_id:
                        link(claim.id, "OWED_TO", claim.commitment.owed_to_entity_id)
                for citation in claim.provenance.citations:
                    link(claim.id, "CITES", citation.event_id)
                for superseded in claim.supersedes:
                    link(claim.id, "SUPERSEDES", superseded)
                    runtime.store.set_claim_status(
                        owner_id, superseded, ClaimStatus.SUPERSEDED.value
                    )
                for conflicting in claim.contradicts:
                    link(claim.id, "CONTRADICTS", conflicting)

        log.info("ingestion.write nodes=%d skipped=%d", len(written), skipped)
        return {
            "written": written,
            "written_by_label": {k: len(v) for k, v in touched.items()},
            "skipped": skipped,
            "errors": errors,
        }

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


def _persist_sealed(
    runtime: Runtime, owner_id: str, sealed: dict[str, dict]
) -> tuple[dict[str, Any], list[str]]:
    """Writes every sealed body in this run as one batch of Quilt patches.

    Returns ``{external_id: EncryptedContentRef}`` and any errors. A caller that
    finds an external id missing from the mapping must skip that event: the half
    that was missing before ADR 0002 was storing the bytes at all, and the half
    that would be worse than missing is a ref pointing at bytes nobody wrote.

    The whole batch succeeds or the whole batch fails. A partial Quilt is not a
    thing worth building a recovery path for while the only writer is a backfill
    that can simply be re-run -- and re-running is cheap because patch ids are
    content addresses, so the second attempt rewrites nothing.
    """
    from ..schema import EncryptedContentRef

    if not sealed:
        return {}, []

    external_ids = list(sealed)
    ciphertexts = [base64.b64decode(sealed[eid]["ciphertext_b64"]) for eid in external_ids]
    try:
        refs = runtime.blobs.put_batch(owner_id, ciphertexts)
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
        return {}, [f"sealed bodies not persisted ({len(ciphertexts)} pending): {exc}"]

    out: dict[str, Any] = {}
    for external_id, blob_ref in zip(external_ids, refs, strict=True):
        ref = EncryptedContentRef.model_validate(sealed[external_id]["ref"])
        ref.blob_id = blob_ref.blob_id
        ref.patch_id = blob_ref.patch_id
        out[external_id] = ref
    log.info("ingestion.write persisted=%d patches", len(out))
    return out, []


def _upsert(runtime: Runtime, node) -> None:
    """Embeds from plaintext, then seals, then writes.

    The order is the whole correctness condition. An embedding computed after
    sealing would be an embedding of ciphertext -- noise -- and retrieval would go
    quietly useless while every test that checks structure kept passing. So the
    plaintext text is taken first, and the node that reaches the store has its
    content fields already sealed (ADR 0010).
    """
    embedding = runtime.embedder.embed(text_for_index(node))
    runtime.store.upsert(runtime.content.seal_node(node), embedding)


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

    # Counts come from the write node, not from the candidate set: see the
    # docstring on IngestionResult.
    counts = final.get("written_by_label", {})
    return IngestionResult(
        owner_id=owner_id,
        records=len(final.get("records", [])),
        entities=counts.get("entities", 0),
        events=counts.get("events", 0),
        claims=counts.get("claims", 0),
        sealed=len(final.get("sealed", {})),
        skipped=final.get("skipped", 0),
        supersessions=[tuple(p) for p in final.get("supersessions", [])],
        contradictions=[tuple(p) for p in final.get("contradictions", [])],
        errors=final.get("errors", []),
    )
