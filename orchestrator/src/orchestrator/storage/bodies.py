"""Reading a sealed body back: the path that existed in two halves and no middle.

`LocalQuiltStore.get` was implemented, owner-partitioned and guarded against
path traversal. The gateway proxied the enclave's decrypt. Nothing joined them:
no code converted a stored `EncryptedContentRef` into a `BlobRef`, so `get` had
zero call sites and a sealed body was durable and unreadable. The documentation
said "the gateway does not expose decrypt", which was false, and the true
statement -- "nothing assembles the path" -- was nowhere.

This is the middle.

**It returns rather than raises.** A missing blob is an ordinary fact about an
old ingest, and must not fail a read that was otherwise permitted. The same shape
and the same argument as `ToolResult`: whatever drives this has to record the
attempt either way, and raising would make "no body stored" indistinguishable
from "this deployment cannot read the store it is pointed at".

Those two really are different, and keeping them apart is most of the point:

- ``not_stored`` -- the bytes are genuinely absent. An old ref, or a Quilt that
  was never written.
- ``backend_not_wired`` -- the body exists somewhere, and *this* deployment
  cannot reach it. A body sealed to local disk and later read with Walrus
  configured, which is the shape ADR 0002 and 0008 chose on purpose: no silent
  fall back to the orchestrator's disk, because a deployment that believes it
  writes to Walrus and actually writes locally has a confidentiality bug rather
  than a performance one. Reporting that as "no body" would make the
  confidentiality bug look like an empty record.
- ``not_permitted`` -- the grant may read the object and not its raw body.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..permissions import ObjectAcl, Scope, evaluate_unseal
from ..schema import Event
from .blobs import ref_from_encrypted_content

log = logging.getLogger(__name__)

NO_REF = "no_ref"
NOT_STORED = "not_stored"
BACKEND_NOT_WIRED = "backend_not_wired"
NOT_PERMITTED = "not_permitted"


@dataclass(frozen=True, slots=True)
class LoadedBody:
    """A body, or the reason there is not one."""

    text: str | None = None
    #: ``None`` when ``text`` is set. One of the constants above otherwise.
    unavailable: str | None = None
    #: What the grant said, when the answer was a refusal. Carried so a caller
    #: can render "you may see the claim, not its transcript" rather than a
    #: generic denial.
    reason: str | None = None

    @property
    def available(self) -> bool:
        return self.text is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "unavailable": self.unavailable,
            "reason": self.reason,
        }


def load_body(
    runtime,
    owner_id: str,
    event: Event,
    *,
    scope: Scope | None = None,
    grant_token: str | None = None,
    now_ms: int | None = None,
) -> LoadedBody:
    """The plaintext body of one event, if everything permits it and it is there.

    ``scope`` and ``grant_token`` are both required for an agent-initiated read
    and both omitted for an owner-initiated one. The split is deliberate: a
    caller holding a scope has to pass the token too, because unsealing goes
    through the gateway under that grant and there is no other credential the
    orchestrator could present.
    """
    if event.body is not None:
        # Never sealed. Nothing to unseal, and no permission question beyond the
        # one the caller already answered to be holding this event at all.
        return LoadedBody(text=event.body)

    ref = event.encrypted_content
    if ref is None:
        return LoadedBody(unavailable=NO_REF)

    if scope is not None:
        decision = evaluate_unseal(scope, event.acl, now_ms)
        if not decision.allowed:
            reason = decision.reason.value if decision.reason else "denied"
            return LoadedBody(unavailable=NOT_PERMITTED, reason=reason)
        if grant_token is None:
            raise ValueError(
                "a scope without its grant token cannot unseal: the gateway "
                "authorises the decrypt against the grant itself"
            )

    try:
        blob_ref = ref_from_encrypted_content(ref, runtime.blobs.backend)
    except ValueError as exc:
        log.debug("bodies.load unreadable ref for %s: %s", event.id, exc)
        return LoadedBody(unavailable=NOT_STORED, reason=str(exc))

    try:
        ciphertext = runtime.blobs.get(owner_id, blob_ref)
    except NotImplementedError as exc:
        # The Walrus stub, and the one case that must never be reported as an
        # absent body: the bytes exist, this deployment cannot reach them.
        log.warning("bodies.load backend not wired: %s", exc)
        return LoadedBody(unavailable=BACKEND_NOT_WIRED, reason=str(exc))

    if ciphertext is None:
        return LoadedBody(unavailable=NOT_STORED)

    if grant_token is not None:
        plaintext = runtime.gateway.unseal_for_grant(ciphertext, ref.key_id, grant_token)
    else:
        plaintext = runtime.gateway.seal_decrypt(ciphertext, ref.key_id)
    return LoadedBody(text=plaintext.decode())


def permits_unseal(scope: Scope, acl: ObjectAcl, now_ms: int | None = None) -> bool:
    """Convenience for a caller deciding whether to ask at all."""
    return evaluate_unseal(scope, acl, now_ms).allowed
