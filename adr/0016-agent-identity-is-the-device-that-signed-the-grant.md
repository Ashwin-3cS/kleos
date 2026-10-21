---
title: "ADR 0016: Agent identity is the device that signed the grant"
description: "Several agents now share one memory, and the record has to say which one did a thing."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

Several agents now share one memory, and the record has to say which one did a
thing. Until now it could not.

`Scope.agent_id` existed and looked like an answer. It is a string the owner
types into a scope file before running `kleos-device sign`, and nothing checks
it: two agents handed the same file are indistinguishable, one agent handed two
files looks like two agents, and `ObjectAcl.denied_agents` -- the only place the
field was load-bearing -- is a denylist keyed on an unauthenticated name.

Meanwhile the thing that *is* authenticated was being thrown away.
`scope_introspect` parsed `claims.key_id`, used it to look the device key up,
verified the signature against it, and then built a response carrying only
`{active, scope}`. The orchestrator never learned which device had asked.

## Decision

**Propagate the signing key id, and say in band how much any identity is worth.**

### The key id goes on the response, not in the scope

`ScopeIntrospectResponse` gains `key_id`. Deliberately not a field on `Scope`:

- The scope is what the device **signs**. A device id inside it would be
  self-asserted, and the verifier would then have to cross-check it against the
  token's own key id -- two sources of truth for one fact, with a forgery oracle
  in the gap.
- `Scope` is being kept in a shape that can become an on-chain grant object
  verbatim, and a signer's key is not part of a grant object's contents anywhere
  that signatures work.
- Mechanically it costs no schema-parity change, which is the proof it went to
  the right side rather than an argument that it did.

### Identity is a triple, and only the middle is authenticated

A decision is attributed to `(agent_id, device_id, session_id)`.

`session_id` is **minted by the orchestrator**, never supplied by the caller. An
agent-chosen id is an unauthenticated string two agents could collide on, by
accident or on purpose, and attribution is the entire point of having one.

### `identity_basis` says which kind of identity a reader is looking at

Everything Kleos renders about an agent carries `device_key` or `label`. A reader
who sees the first can rely on it; a reader who sees the second is told not to.
The same discipline as `MOCK_SEAL_V1:` and `MOCK_ATTESTATION_`: the weaker thing
says so in band rather than being indistinguishable from the stronger one.

## Alternatives

- **Trust `agent_id`.** It is already there and already carried everywhere. It is
  also unverified, so every attribution built on it would be a claim about who
  acted that anyone holding a grant could have written.
- **Put `device_id` in `Scope`.** Rejected above: self-asserted, duplicated, and
  it changes the shape being preserved for on-chain evaluation.
- **Issue one grant per agent instance and treat the grant as the identity.** The
  grant fingerprint is already recorded and does distinguish instances. It does
  not survive re-issuance, so an agent that rotates grants loses its history --
  and the fingerprint names a capability rather than a holder.

## Consequences

- "Device 1 decided this" is answerable with cryptographic force. "Claude Code
  decided this" is answerable only as well as the owner labels their own devices,
  and the output says which of the two a reader has.
- The read log, the mutation log, agent sessions and agent actions all record the
  device. Rows written before this existed read back with `None` rather than a
  backfilled guess: a fabricated device id would be indistinguishable from an
  authenticated one in every row that stores it.
- **MCP has no credential channel.** A tool call carries arguments and nothing
  else, so the grant token is an argument on every call and a `session_id` is
  never sufficient alone. A second agent on the same machine that learns a
  session id still needs a valid grant for every call, which is what makes the
  session id safe to be unauthenticated -- not any property of the id itself.
- Revocation granularity is unchanged and still coarse: revoking a device key
  invalidates every grant it ever signed, and there is nothing between that and
  per-object denial.
