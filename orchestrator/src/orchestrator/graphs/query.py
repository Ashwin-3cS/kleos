"""Query graph: retrieve -> permission-check -> assemble (or decline).

The permission check is a node of its own, between retrieval and assembly,
so that it is structurally impossible for the assembler to see a candidate
that was not checked. A query that retrieves plenty but passes nothing
declines explicitly and says why -- it never falls back to answering from
what it happened to remember.

## Where the assembly happens, since ADR 0024

Two paths, and the condition is **whether the stored content is sealed at
all**, not a switch of its own:

- **Sealed content** -> the enclave assembles. This process posts the ranked
  candidates, still sealed, to ``POST /memory/assemble`` and relays what comes
  back: a blob encrypted to the device that signed the grant, plus the
  structural half the read log needs. It never unseals, never formats, and
  never holds the answer.
- **Unsealed content** -> this process assembles, exactly as it always did.

That is deliberately *not* a fallback, and the difference matters. A fallback
would mean a sealed store could be read in the clear out here when something
was misconfigured, which is the exposure returning silently -- the thing ADR
0024 warns about in as many words. These are two different states of the
store: in the second there is no ciphertext, so there is nothing for an
enclave to unseal and nothing being disclosed to the host that the host did
not already write. ``ENCRYPT_CONTENT_AT_REST`` is the one switch, it is loud,
and any deployment holding real memory has it on.

The permission check still runs here in the sealed case, and its verdict is
**not** sent. The enclave evaluates again, against the ACLs travelling with
the candidates, and its verdict is the one that governs disclosure -- a
decision made out here is a decision the operator makes. The host-side pass
survives only because retrieval and the read log are shaped around it; it
narrows what is posted and decides nothing. Step 4 removes it.
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
from .audit import record_read
from .runtime import Runtime

log = logging.getLogger(__name__)


class QueryState(TypedDict, total=False):
    question: str
    grant_token: str
    scope: dict
    #: Resolved alongside the scope, carried so the assembler can log it.
    device_id: str
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


#: What ``text`` says when the answer is somewhere this process cannot read.
#:
#: Self-labelling, in the spirit of ``KSEAL1:`` and ``MOCK_ATTESTATION_``: a
#: client that prints ``.text`` without noticing ``.sealed`` shows this instead
#: of the answer, which is wrong in a way somebody notices. An empty string
#: would have been wrong in a way nobody does.
SEALED_TEXT = (
    "KSEALED: this answer was assembled in the enclave and encrypted to the "
    "device that asked for it. Unseal it there; the host does not have it."
)


@dataclass(slots=True)
class QueryAnswer:
    question: str
    answered: bool
    text: str
    citations: list[AnswerCitation] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    considered: int = 0
    #: Which objects the answer discloses.
    #:
    #: The structural half, and the only one of these fields that means the same
    #: thing on both paths -- which is why callers that want "what did this
    #: read return" should use it rather than mining ``citations``.
    disclosed_ids: list[str] = field(default_factory=list)
    #: The sealed envelope, when the enclave assembled this. ``None`` when this
    #: process did, in which case ``text`` and ``citations`` are the answer.
    #:
    #: Exactly one of the two is ever populated. A field rather than a subclass
    #: because every caller has to serialise both shapes anyway, and a union
    #: here is a union a client can switch on.
    sealed: dict | None = None
    #: The attestation over the sealed assembly, and the enclave key needed to
    #: recompute what it commits to.
    #:
    #: Relayed rather than acted on: this process already verified them in
    #: `GatewayClient.assemble`, and it passes them on because its own verdict
    #: is a host-side verdict. The device checks for itself, which is the check
    #: that is not the operator's (ADR 0026).
    attestation: str | None = None
    enclave_public_key: str | None = None

    @property
    def is_sealed(self) -> bool:
        return self.sealed is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "answered": self.answered,
            "text": self.text,
            "citations": [asdict(c) for c in self.citations],
            "denied": self.denied,
            "considered": self.considered,
            "disclosed_ids": self.disclosed_ids,
            "sealed": self.sealed,
            "attestation": self.attestation,
            "enclave_public_key": self.enclave_public_key,
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
        # The grant, not just the scope: the signing device is what makes the
        # read log able to say *which* agent instance read this. ADR 0016.
        resolved = runtime.gateway.introspect_grant(state["grant_token"])
        scope = resolved.scope
        return {"scope": scope.model_dump(mode="json"), "device_id": resolved.device_id}

    def retrieve(state: QueryState) -> dict:
        scope = Scope.model_validate(state["scope"])
        retriever = MemoryRetriever(
            runtime.store,
            runtime.embedder,
            owner_id=scope.owner_id,
            top_k=state.get("top_k", 8),
            weights=runtime.weights,
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
        if runtime.content.seals_content:
            return _assemble_in_enclave(runtime, state)
        return _assemble_here(runtime, state)

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


def _assemble_in_enclave(runtime: Runtime, state: QueryState) -> dict:
    """Posts the sealed candidates and relays what comes back.

    The whole of this process's part in a sealed read. It does not unseal, does
    not format, and does not learn the answer -- `ContentCrypto.unseal_node` is
    not reachable from here, deliberately, because a path that could reach it
    is a path a configuration mistake can take.

    The candidates go up **as stored**: ranked, permission-narrowed, and with
    every content field still carrying its `KSEAL1:` marker. The ACLs travel
    with them, because the enclave evaluates again and its verdict is the one
    that governs disclosure.
    """
    permitted = state.get("permitted", [])
    denials = state.get("denials", [])
    considered = len(state.get("candidates", []))

    assembly = runtime.gateway.assemble(
        state["grant_token"],
        state["question"],
        [_candidate_for_enclave(c) for c in permitted],
    )

    # The *enclave's* denials, appended to the ones from out here rather than
    # replacing them. They are different facts: a candidate dropped here was
    # never offered, and a candidate dropped in there was offered and refused.
    # The second is the one that would catch the host narrowing a read it was
    # not entitled to narrow, so collapsing them would hide the interesting
    # half. Duplicates cannot arise -- only the permitted ones were posted.
    denied = [*denials, *assembly.denials]

    # Logged from what the enclave reported, not from what this process hoped.
    # Before the answer is returned, so there is no path that relays a blob
    # without a record of having relayed it.
    record_read(
        runtime,
        Scope.model_validate(state["scope"]),
        state["grant_token"],
        device_id=state.get("device_id"),
        kind="query",
        disclosed_ids=assembly.disclosed_ids,
        denied=denied,
        considered=considered,
        subject=state["question"],
    )

    return {
        "answer": QueryAnswer(
            question=state["question"],
            answered=bool(assembly.disclosed_ids),
            text=SEALED_TEXT,
            # Empty on purpose and not reconstructed from the ids this process
            # holds: a citation carries the source and the url, which come off
            # the object, and assembling half a citation out here would be a
            # second, lossier copy of something already inside the blob.
            citations=[],
            denied=denied,
            considered=considered,
            disclosed_ids=assembly.disclosed_ids,
            sealed=assembly.sealed,
            attestation=assembly.attestation,
            enclave_public_key=assembly.enclave_public_key,
        ).as_dict()
    }


def _assemble_here(runtime: Runtime, state: QueryState) -> dict:
    """The unsealed path: nothing is ciphertext, so this process formats.

    Kept because a store with no sealed content has nothing for an enclave to
    unseal -- not as a fallback for a sealed one. See the module docstring.
    """
    content = runtime.content.for_grant(state["grant_token"])
    permitted = state.get("permitted", [])
    denials = state.get("denials", [])
    considered = len(state.get("candidates", []))
    disclosed_ids = [c["id"] for c in permitted]

    # Logged before the answer is built, so there is no path that returns
    # content without a record of having returned it.
    record_read(
        runtime,
        Scope.model_validate(state["scope"]),
        state["grant_token"],
        device_id=state.get("device_id"),
        kind="query",
        disclosed_ids=disclosed_ids,
        denied=denials,
        considered=considered,
        subject=state["question"],
    )

    if not permitted:
        reasons = sorted({d["reason"] for d in denials})
        return {
            "answer": QueryAnswer(
                question=state["question"],
                answered=False,
                text=_decline_text(considered, reasons),
                denied=denials,
                considered=considered,
            ).as_dict()
        }

    nodes = [(c, content.unseal_node(_node_of(c))) for c in permitted]
    citations = [_citation_of(label=c["label"], node=n) for c, n in nodes]
    text = "\n".join(_line_of(n) for _, n in nodes)
    return {
        "answer": QueryAnswer(
            question=state["question"],
            answered=True,
            text=text,
            citations=citations,
            denied=denials,
            considered=considered,
            disclosed_ids=disclosed_ids,
        ).as_dict()
    }


def _candidate_for_enclave(candidate: dict) -> dict:
    """One ranked candidate in the shape `AssembleRequest` expects.

    The node payload plus `object_type`, which is the serde tag the Rust
    `MemoryNode` enum is deserialised through. Built from the label this
    process already carries rather than sniffed from the payload's fields,
    because a sniffed type is a type an attacker's payload chooses.
    """
    return {
        "node": {"object_type": candidate["label"].lower(), **candidate["payload"]},
        "score": float(candidate.get("score") or 0.0),
    }


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


def _line_of(node) -> str:
    if isinstance(node, Claim):
        marker = "" if node.status.value == "active" else f" [{node.status.value}]"
        return f"- {node.statement}{marker} ({node.id})"
    if isinstance(node, Event):
        return f"- {node.summary} ({node.id})"
    return f"- {node.kind.value}: {node.name} ({node.id})"


def _citation_of(label: str, node) -> AnswerCitation:
    first = node.provenance.citations[0] if node.provenance.citations else None
    return AnswerCitation(
        object_id=node.id,
        label=label,
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
        # `.get` on both, because LangGraph checkpoints these dicts: a thread
        # resumed from a checkpoint written before ADR 0024 has neither key,
        # and the safe reading of a missing `sealed` is "not sealed" only
        # because the other path cannot produce one.
        disclosed_ids=answer.get("disclosed_ids", []),
        sealed=answer.get("sealed"),
        attestation=answer.get("attestation"),
        enclave_public_key=answer.get("enclave_public_key"),
    )
