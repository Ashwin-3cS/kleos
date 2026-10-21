---
title: "ADR 0028: The verdict is computed in the enclave"
description: "`evaluate` is the function that decides whether an agent may see an object, and on three of the four read paths it runs in host Python."
---

**Status:** accepted
**Date:** 2026-10-21

## Context

`evaluate` is the function that decides whether an agent may see an object, and
on three of the four paths it runs in host Python.

ADR 0024 moved it for the query path: `/assemble` evaluates every candidate in
Rust inside the enclave, against content the host cannot read. What was left
behind is `graphs/history.py:130` and `graphs/neighbourhood.py:139` — the
supersession chain and the graph neighbourhood — plus `graphs/decide.py:196`,
where `evaluate_write` gates every agent write.

So an operator who controls the host controls those decisions. Not by
exploiting anything: by editing a Python file. `evaluate` is pure, total and
deny-by-default, which makes it the easiest thing in the service to audit and
also the easiest to replace with `return Allow`.

The query path has the inverse problem. It evaluates in Python *and* the
enclave evaluates again, so the verdict is computed twice and only one of them
governs. `graphs/query.py:187`'s own comment says so. Two checks where one
decides is worse than one check, because the one a reader finds first is the one
that does not matter.

This is also the smallest remaining increase in the trusted computing base for
the largest gain. The functions are already pure and already mirrored in Rust;
nothing new enters the measured image.

## Decision

**Two enclave routes — `POST /permissions/evaluate` and
`POST /permissions/evaluate-write` — and the host asks rather than decides.**

```
history / neighbourhood / decide
   │
   ├─ gateway verifies the grant, derives the scope and the owner
   │
   └─ enclave evaluates, with its own clock
          │
          └─ verdicts, which the host applies and cannot compute
```

### The host sends ACLs, not nodes

`/assemble` has to send whole nodes because it assembles from their content.
These routes decide, and `evaluate` is decidable from `(scope, acl, now_ms)`
alone — that property was deliberate from the start and this is the thing it
buys. So the request carries an id and an `ObjectAcl` per object and nothing
else, which keeps sealed content out of a call that has no use for it.

### The clock is the enclave's

`now_ms` was `int(time.time() * 1000)` on the host, and every time-window check
and every grant expiry is measured against it. A host that supplies the clock
can rewind it, which resurrects an expired grant and reopens a closed time
window — and leaves no trace, because the verdict that comes back is
*correct* for the time it was given.

The enclave reads its own clock and **returns** the `now_ms` it used. There is
no field for the host to supply one. This is the part of the change that closes
an exposure rather than relocating one.

### The scope still comes from the gateway, and that is a separate gap

The enclave trusts the `Scope` the gateway resolved from the grant, exactly as
`/assemble` already does, and for the same reason: the gateway holds the device
key registry, so re-verifying the signature inside the enclave would need that
registry in the measured image for no gain — the host chooses what reaches the
route either way.

**So this closes "the operator computes the verdict" and not "the operator
supplies the scope."** Those are different, and the second needs a verification
root the operator cannot substitute, which ADR 0011 already flags. Saying it
here because a route named `/permissions/evaluate` inside a TEE invites the
stronger reading.

### No fallback when the enclave is unreachable

A read refuses. `ENCRYPT_CONTENT_AT_REST` set the precedent — ingestion fails
rather than quietly writing plaintext — and the reasoning transfers: a
permission check that falls back to the host when the enclave is down is a
permission check an operator can obtain by turning the enclave off.

Off by default (`EVALUATE_IN_ENCLAVE`) so the eval harness and the unit tests
keep running with no gateway, which is the same shape as every other setting
that needs the TEE.

### The duplicate on the query path goes, but only where it is duplicate

When content is sealed, the enclave evaluates and the host's pre-filter is
deleted: the host ships every ranked candidate and the enclave decides. When
content is **not** sealed the host assembles the answer itself, so it must
evaluate — there is no second check to defer to, and deleting it would be a
read with no permission check at all.

That asymmetry is uncomfortable and it is the honest state: the unsealed path
is a host-trusting deployment throughout, and a permission check is not the
place it stops being one.

### The write gate moves too

`evaluate_write` in `decide.py` is one call and the same shape, and leaving it
behind would mean the operator could no longer decide what an agent *reads*
while still deciding what it may *write* — the direction that modifies the
record rather than disclosing it. The plan's note that step 4 "delivers
brokered memory writes in the same move" is this: the enclave decides and the
host applies.

## Alternatives rejected

**Keep the Python check as a second opinion.** Evaluate in both and refuse
unless both allow. Tempting, and it is what the query path accidentally does
today. Rejected: two checks where one governs is the bug, not the mitigation.
An operator removing the host check loses nothing, and a reader finding it
first learns the wrong thing about where the decision is made. Deny-by-default
belongs in one place.

**Attest every verdict.** The response could carry an NSM document committing
to the scope, the ids and the verdicts, so a verdict could be proven later to
have been computed inside. Rejected for now because it has **no reader**: the
only consumer is the host, which already trusts the gateway for the scope, and
on real hardware it would be an NSM call per read. There is a plausible future
reader — an owner auditing the read log for whether denials were computed in
the TCB (ADR 0005's spirit) — and that is its own decision, with its own
reader, rather than a document nobody opens.

**Move the device key registry into the enclave too.** Then the enclave could
verify the grant itself and the scope would stop being host-supplied. That is
the right end state and it is not this change: the registry needs persistence
and sealing inside the measured image, and the gain is zero until it is
complete, because a partially-trusted scope is a fully-untrusted scope.

**Batch per read, or one call per object.** Per object is simpler and is one
round trip into the TEE per candidate — a neighbourhood of forty objects would
be forty. Batched, with the ids echoed back so a response cannot be silently
reordered or truncated: a verdict list the host matches by id is one the host
cannot quietly drop an entry from and have it read as "allowed".

## Consequences

- **A gateway round trip on the history and neighbourhood paths**, where there
  was none. They were pure CPU before. The batch keeps it at one per read.
- **The enclave's TCB grows by two routes** and no new dependency. `evaluate`
  and `evaluate_write` are already compiled into the image for `/assemble`.
- **Off by default means the default is the old behaviour**, and a deployment
  that forgets the setting is a deployment deciding on the host. Named in
  `docs/status.mdx` rather than left to be discovered.
- **The unsealed path still decides on the host, by necessity.** Anyone reading
  "the verdict is computed in the enclave" should read the paragraph above about
  which path.
- **It does not make the scope trustworthy.** The operator cannot compute the
  verdict and can still choose the question. That is ADR 0011's gap, still open.
