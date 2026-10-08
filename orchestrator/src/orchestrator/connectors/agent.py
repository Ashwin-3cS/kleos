"""What an agent decided, written into the same record the person's own sources go into.

Every source before this one carried something the *person* produced: a mailbox,
an export, their own typing. This one carries what an agent concluded while
working for them -- "I chose Postgres, and here is why" -- and that is a
different kind of thing in exactly one respect that matters: it has to be
weighable against the person's own account.

**One source id for the class, not one per agent.** The universe of agents is
open, so per-agent ids (`agent_claude_code`, `agent_chatgpt`, ...) would put
agent naming inside `SourceId` validation, make every grant scope need rewriting
when a new agent appears, and turn `ObjectAcl.sources` -- which the resolver's
precedence rule reads -- into a cardinality problem. Instance identity belongs on
provenance, where `actor_agent_id`, `actor_device_id` and `actor_session_id`
already carry it, and where the device half is actually authenticated.

**Separate from `text` and `voice` for the reason those are separate from each
other.** A grant scoped to `text` and not `agent` is a real thing someone would
want -- "read what I wrote down, not what my coding assistant concluded" -- and
`permits()` can express it for free only if the ids differ. It is also the write
side of the same rule: `Scope.write_sources` is distinct from `Scope.sources`
precisely so an agent permitted to *read* the person's notes cannot write a claim
that claims to be one.

Push-only, like `text` and `voice`, and for the same reason: there is nothing to
fetch. An agent does not have a mailbox to poll. Records arrive through
`record_decision` over MCP, which hands them to the ordinary ingestion graph --
the same extraction, resolution, sealing and write path, because a thing an agent
concluded is a record like any other once it exists, and a second graph would be
two paths that have to be kept resolving the same way.

No `mock_factory`, same as the push sources: a fixture here would make mock mode
invent decisions an agent never made, attributed to a device that does not exist.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from ..extraction.ids import stable_id
from ..schema import RawRecord
from .base import ConnectorSpec, pack_paragraphs

#: What an agent concluded while working for the owner.
AGENT = "agent"

#: Enough of the statement to recognise it in a list. The whole thing is the body.
_TITLE_CHARS = 90


class AgentConnector:
    """Declares the `agent` source. Cannot be pulled."""

    def __init__(self) -> None:
        self.name = AGENT

    def fetch(self, owner_id: str, since_ms: int) -> Iterable[RawRecord]:
        raise NotImplementedError(
            "'agent' is a push source: there is nothing to fetch. An agent records "
            "a decision through the record_decision MCP tool, which hands it to the "
            "ingestion graph directly."
        )


SPEC = ConnectorSpec(
    source_id=AGENT,
    display_name="Agent decisions",
    factory=lambda settings: AgentConnector(),
    # A decision plus its reasoning is one thought, and the reasoning is prose a
    # model wrote -- paragraphs, the same shape a typed note has.
    chunker=pack_paragraphs(900),
)


def build_record(
    owner_id: str,
    statement: str,
    reason: str,
    *,
    occurred_at_ms: int | None = None,
    sensitive: bool = False,
    agent_id: str = "",
    device_id: str = "",
    session_id: str = "",
) -> RawRecord:
    """Turns an agent's decision into a record the ingestion graph accepts.

    The body is the statement **and** the reason, in that order, because the
    extractor reads the body and the reason is what makes the claim worth
    anything to the next agent. Keeping the reason out of the body would store a
    decision with no basis and leave the rationale in metadata that nothing
    interprets.

    ``external_id`` is a content address over the owner, the statement, the
    reason and the timestamp, so a retried call writes nothing new -- the same
    idempotence every other id in this service has. The *session* is not part of
    it: the same decision reached twice in two sessions is one decision, and
    including the session would store it twice.

    ``url`` stays ``None``: a decision lives nowhere. The identity triple rides in
    ``metadata`` and is lifted onto `Provenance` at the write, never trusted from
    the extractor -- the same rule ADR 0014 applies to a fetched page's source.
    """
    stamp = occurred_at_ms if occurred_at_ms is not None else int(time.time() * 1000)
    external_id = stable_id("agd", owner_id, statement, reason, str(stamp))
    flat = " ".join(statement.split())
    title = flat if len(flat) <= _TITLE_CHARS else flat[:_TITLE_CHARS].rsplit(" ", 1)[0]
    statement, reason = statement.strip(), reason.strip()
    body = f"{statement}\n\nReason: {reason}" if reason else statement
    return RawRecord(
        external_id=external_id,
        connector=AGENT,
        occurred_at_ms=stamp,
        title=title,
        body=body,
        url=None,
        sensitive=sensitive,
        participants=[],
        metadata={
            "actor_agent_id": agent_id,
            "actor_device_id": device_id,
            "actor_session_id": session_id,
        },
    )
