"""Who decides whether an agent may see an object (ADR 0028).

`permissions.evaluate` is pure, total and deny-by-default, which makes it the
easiest thing in this service to audit and also the easiest to replace with
`return Allow`. Running it here means an operator changes a verdict by editing
a file -- not by exploiting anything.

So with `EVALUATE_IN_ENCLAVE` on, the verdict is computed in the TEE and this
process applies a decision it did not make. Two things that buys, and one it
does not:

**The operator cannot compute the verdict.** The function that decides is
inside the measured image, where it was already compiled for `/assemble`.

**The clock stops being the host's.** `now_ms` was `int(time.time() * 1000)`
right here, and every time-window check and every grant expiry is measured
against it. A host that supplies the clock can rewind it -- resurrecting an
expired grant, reopening a closed window -- and nothing downstream looks wrong,
because the verdict is correct for the time it was given. The enclave reads its
own clock and there is no field to supply one.

**It does not make the scope trustworthy.** The scope is resolved from the grant
by the gateway, on the host, exactly as `/assemble` already has it. The operator
can no longer compute the verdict and can still choose the question. ADR 0011
has that half.

**No fallback.** If the enclave cannot be reached the read refuses.
`ENCRYPT_CONTENT_AT_REST` set the precedent -- ingestion fails rather than
quietly writing plaintext -- and it transfers: a permission check that falls
back to the host when the enclave is down is a permission check an operator
obtains by turning the enclave off.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from .permissions import ObjectAcl, Scope, WriteIntent, evaluate, evaluate_write

log = logging.getLogger(__name__)


class GatekeeperUnavailable(RuntimeError):
    """The enclave could not be asked, so nothing is disclosed.

    A distinct exception rather than a denial, because "denied" and "could not
    be decided" are different facts and only one of them is about the grant.
    Collapsing them would tell an agent its scope is too narrow when the truth
    is that the TEE is down.
    """


@dataclass(frozen=True, slots=True)
class Verdict:
    """One decision, with the reason when it is a denial."""

    allowed: bool
    reason: str | None = None


class Gatekeeper:
    """Evaluates, either in this process or in the enclave.

    One object rather than a flag at each call site: three call sites checking
    a setting is three places that can disagree about which one is authoritative,
    and the one that disagrees is the one nobody reads.
    """

    __slots__ = ("_gateway", "_in_enclave")

    def __init__(self, gateway: Any, in_enclave: bool) -> None:
        self._gateway = gateway
        self._in_enclave = in_enclave

    @property
    def in_enclave(self) -> bool:
        return self._in_enclave

    @property
    def where(self) -> str:
        """For the log lines, so a reader can tell which deployment they are in."""
        return "enclave" if self._in_enclave else "host"

    def evaluate_objects(
        self,
        scope: Scope,
        objects: list[tuple[str, ObjectAcl]],
        *,
        grant_token: str | None = None,
    ) -> dict[str, Verdict]:
        """One verdict per object, keyed by id.

        Keyed by id and not positional, matching what the enclave returns: a
        verdict list matched by position is one an intermediary can reorder or
        truncate, with the gap reading as "allowed".
        """
        if not objects:
            return {}
        if not self._in_enclave:
            now_ms = int(time.time() * 1000)
            return {
                object_id: _local(evaluate(scope, acl, now_ms)) for object_id, acl in objects
            }
        if not grant_token:
            # A caller that reaches here without the token has no way to ask,
            # and guessing is not available: the alternative would be deciding
            # on the host, which is what this exists to stop.
            raise GatekeeperUnavailable(
                "evaluating in the enclave needs the grant token the read was authorised "
                "with, and this call site did not pass one"
            )
        try:
            answer = self._gateway.evaluate(
                grant_token,
                [
                    {"id": object_id, "acl": acl.model_dump(mode="json")}
                    for object_id, acl in objects
                ],
            )
        except Exception as exc:  # noqa: BLE001 - every failure means the same thing
            raise GatekeeperUnavailable(
                f"the enclave could not be asked for a permission verdict, so nothing is "
                f"disclosed: {exc}"
            ) from exc

        verdicts = {
            v["id"]: Verdict(allowed=bool(v["allowed"]), reason=v.get("reason"))
            for v in answer.get("verdicts", [])
        }
        missing = [object_id for object_id, _ in objects if object_id not in verdicts]
        if missing:
            # Deny-by-default, applied to the transport. A truncated response is
            # the one failure a verdict map cannot represent, so it is refused
            # outright rather than read as "those ones were fine".
            raise GatekeeperUnavailable(
                f"the enclave returned no verdict for {len(missing)} of {len(objects)} "
                "objects, so the response is incomplete and nothing is disclosed"
            )
        return verdicts

    def evaluate_one_write(
        self, scope: Scope, intent: WriteIntent, *, grant_token: str | None = None
    ) -> Verdict:
        """The write gate.

        Separate from the read path for the reason `evaluate_write` is a sibling
        function rather than a flag: a mode parameter means every call site has
        to say which one it wants, and the one that forgets gets the default.
        """
        if not self._in_enclave:
            return _local(evaluate_write(scope, intent, None))
        if not grant_token:
            raise GatekeeperUnavailable(
                "evaluating a write in the enclave needs the grant token it is authorised with"
            )
        try:
            answer = self._gateway.evaluate_write(grant_token, intent.model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001
            raise GatekeeperUnavailable(
                f"the enclave could not be asked whether this write is permitted, so it is "
                f"not performed: {exc}"
            ) from exc
        return Verdict(allowed=bool(answer.get("allowed")), reason=answer.get("reason"))


def _local(decision: Any) -> Verdict:
    return Verdict(
        allowed=decision.allowed,
        reason=decision.reason.value if decision.reason else None,
    )
