"""Wire-level enums shared by the memory schema and the permission model.

These live in their own module only because Rust tolerates the
``memory.rs`` <-> ``permissions.rs`` import cycle and Python does not; the
values are exactly the ``snake_case`` serde representations used on the
Rust side.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator

_SOURCE_ID_RE = re.compile(r"^[a-z0-9_-]{1,64}$")


def _check_source_id(value: str) -> str:
    # Mirrors SourceId::parse in shared/src/memory.rs. Ids are compared as
    # opaque strings in the permission check, so a case or whitespace variant
    # would look identical in a grant UI while never matching.
    if not _SOURCE_ID_RE.match(value):
        raise ValueError(
            f"invalid source id {value!r}: expected 1-64 chars of [a-z0-9_-]"
        )
    return value


#: An open source identifier, not an enum: adding a connector must not require
#: rebuilding the enclave (which would change the measurement the attestation
#: commits to). The registry of *known* sources is a host-side product
#: concern; see connectors/registry.py.
SourceId = Annotated[str, AfterValidator(_check_source_id)]


class EntityKind(StrEnum):
    PERSON = "person"
    PROJECT = "project"
    ARTIFACT = "artifact"
    ORGANIZATION = "organization"
    TOPIC = "topic"


class ClaimStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    CONTRADICTED = "contradicted"
    RECONCILED = "reconciled"


class FulfillmentStatus(StrEnum):
    """Whether a commitment actually happened -- a separate axis from
    ``ClaimStatus``, which is about whether we still believe the claim.
    "Past due" is deliberately not a value here: it is ``OPEN`` plus a due
    timestamp in the past, so no writer has to keep it true."""

    OPEN = "open"
    FULFILLED = "fulfilled"
    DROPPED = "dropped"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PERSONAL = "personal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_RANK[self]


_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.PERSONAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}


class AffectTone(StrEnum):
    """The emotional register of a piece of content -- a **closed** vocabulary.

    Mirrors ``AffectTone`` in ``shared/src/memory.rs``, including the ordering.

    Closed on purpose, and that is the design rather than a limitation. The
    obvious shape for "what kind of content is this" is free-text tags, and free
    text is how an extractor eventually writes "anxious about the biopsy results"
    into a field built for filtering -- putting the most sensitive sentence in the
    record into the one place that gets indexed, logged and read without opening
    the body. A fixed vocabulary cannot carry content. See ADR 0009.
    """

    NEUTRAL = "neutral"
    JOY = "joy"
    RELIEF = "relief"
    AFFECTION = "affection"
    FRUSTRATION = "frustration"
    ANGER = "anger"
    ANXIETY = "anxiety"
    SADNESS = "sadness"
    SHAME = "shame"
    GRIEF = "grief"

    @property
    def sensitivity_floor(self) -> Sensitivity:
        """The lowest sensitivity a body in this register may be stored at.

        Affect **raises** the floor and never lowers it, which makes the label
        self-protecting: tagging a transcript as grief narrows who may read it
        rather than widening it. A connector declares sensitivity from the source
        it came from and cannot know that one conversation in an export was about
        a death; this is where that is corrected.
        """
        return _AFFECT_FLOOR[self]


_AFFECT_FLOOR = {
    # Ordinary register. Still PERSONAL -- nothing here is public.
    AffectTone.NEUTRAL: Sensitivity.PERSONAL,
    AffectTone.JOY: Sensitivity.PERSONAL,
    AffectTone.RELIEF: Sensitivity.PERSONAL,
    AffectTone.FRUSTRATION: Sensitivity.PERSONAL,
    AffectTone.ANGER: Sensitivity.PERSONAL,
    # Discloses something about a relationship or a state of mind.
    AffectTone.AFFECTION: Sensitivity.CONFIDENTIAL,
    AffectTone.ANXIETY: Sensitivity.CONFIDENTIAL,
    AffectTone.SADNESS: Sensitivity.CONFIDENTIAL,
    # The two registers a person is least likely to want an agent in.
    AffectTone.SHAME: Sensitivity.RESTRICTED,
    AffectTone.GRIEF: Sensitivity.RESTRICTED,
}


def raise_to_floor(declared: Sensitivity, tone: AffectTone | None) -> Sensitivity:
    """The stricter of a declared sensitivity and the tone's floor.

    One function so there is one place this rule lives. Called where an ACL is
    built, not where it is checked: ``permits`` stays pure over ``(scope, acl)``
    and must not grow a second notion of what an object's sensitivity is.
    """
    if tone is None:
        return declared
    floor = tone.sensitivity_floor
    return floor if floor.rank > declared.rank else declared


class Authority(StrEnum):
    """How much weight what asserted a thing carries against the person's own
    account -- a **closed** vocabulary.

    Mirrors ``Authority`` in ``shared/src/memory.rs``, including the ordering.

    The distinction ADR 0014 left implicit. A fetched page is a *stranger*: it
    may never supersede the person, because timestamps are the right tie-break
    between two things the person said and exactly the wrong one between
    something they said and something a stranger wrote. An agent the owner
    granted ``may_supersede_owner`` is a *delegate*, and a delegate's later
    decision replacing an earlier one is the record following what happened.

    So precedence is a property of the **grant**, not of the source -- which is
    why this is stamped at the one point where agent input becomes a candidate,
    and never read from an extractor.
    """

    OWNER = "owner"
    DELEGATE = "delegate"
    REFERENCE = "reference"


class MemoryKind(StrEnum):
    """What kind of long-term memory a claim is -- a **closed** vocabulary.

    Mirrors ``MemoryKind`` in ``shared/src/memory.rs``, including the ordering.

    A hierarchy rather than one pile, because the three answer different
    questions and an agent can reasonably be granted one and not another: "you
    may read how I do things, not what I did" is a sentence a person would say,
    and ``Scope`` can only express it if the kinds are named.

    Closed for the reason ``AffectTone`` is: this is promoted to an indexed
    column and read by a grant filter, and a free-text field built for filtering
    is where an extractor eventually writes a sentence.

    Short-term memory is deliberately **not** a member. It is a different
    *state* -- stored, and not searchable until consolidated -- and a fourth
    value here would put session scratchpads in the same vector index as
    consolidated facts. See ``storage/sessions.py``.
    """

    EPISODIC = "episodic"
    PROCEDURAL = "procedural"
    TACIT = "tacit"

    @property
    def sensitivity_floor(self) -> Sensitivity:
        """The lowest sensitivity a claim of this kind may carry.

        Same self-protecting property as ``AffectTone.sensitivity_floor``:
        labelling content can only ever narrow who may read it. A tacit claim is
        an inference *about* a person rather than something they said, so naming
        it has to cost reach.
        """
        return _MEMORY_KIND_FLOOR[self]


_MEMORY_KIND_FLOOR = {
    MemoryKind.EPISODIC: Sensitivity.PERSONAL,
    MemoryKind.PROCEDURAL: Sensitivity.PERSONAL,
    MemoryKind.TACIT: Sensitivity.CONFIDENTIAL,
}


class DenyReason(StrEnum):
    WRONG_OWNER = "wrong_owner"
    GRANT_EXPIRED = "grant_expired"
    AGENT_REVOKED = "agent_revoked"
    SOURCE_NOT_IN_SCOPE = "source_not_in_scope"
    ENTITY_KIND_NOT_IN_SCOPE = "entity_kind_not_in_scope"
    OUTSIDE_TIME_WINDOW = "outside_time_window"
    TOO_SENSITIVE = "too_sensitive"
    #: The grant does not permit writing at all.
    WRITE_NOT_PERMITTED = "write_not_permitted"
    #: It permits writing, but not as this source.
    WRITE_SOURCE_NOT_IN_SCOPE = "write_source_not_in_scope"
    MEMORY_KIND_NOT_IN_SCOPE = "memory_kind_not_in_scope"
    #: The object is readable; turning its sealed body back into plaintext is a
    #: second disclosure and a separate axis.
    UNSEAL_NOT_PERMITTED = "unseal_not_permitted"
    ACTION_NOT_PERMITTED = "action_not_permitted"
