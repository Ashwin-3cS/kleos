---
title: "ADR 0022: Sensitive actions are brokered in the TEE"
description: "An agent that can only read and write memory cannot do anything on the person's behalf."
---

**Status:** accepted
**Date:** 2026-10-13

## Context

An agent that can only read and write memory cannot do anything on the person's
behalf. The moment it can -- send mail, comment on an issue, call an API as them
-- it needs a credential, and that is the thing this whole system is built to keep
out of reach.

The README had already predicted an answer for the Google/GitHub connector gap:
the enclave unseals the refresh token, mints a short-lived access token, and
returns only that, so exposure is one token lifetime and the host still cannot
renew. Better than handing out a refresh token, and still a credential crossing
the boundary.

## Decision

**The agent submits an intent and receives an acknowledgement. The credential
never leaves the TEE, because the action does not either.**

This is not new machinery so much as a generalisation of the one thing the
enclave already does right. `/oauth/exchange` is in there precisely because a
refresh token is standing, renewable access to a person's mailbox and the host
must never hold one; the enclave holds the only copy of the client secret. The
broker says: so must every other sensitive action. If the *action* runs in there,
nothing outside holds even a short-lived token.

### A closed registry, compiled in

`action_id` resolves against a table in `enclave/src/services/actions.rs`, and an
unknown id is refused rather than forwarded -- with the refusal naming what *is*
known, so an operator learns the registry from an error rather than from the
source.

Same reason the upstream hostnames in `services/http.rs` are compile-time
constants: the enclave's environment is supplied by the host, so a host-settable
action is an **operator-repointable** one. Adding an action is a rebuild, a new
measurement and a new attestation -- the point rather than the cost, because the
measurement is what the attestation is worth.

### What keeps it small enough to belong in the TCB

The attestation is only meaningful if what it measures is small enough to audit,
and this is the change most likely to erode that. So an action is small and
auditable by construction: **no LLM, no ingestion, no retrieval, no pagination**
inside the enclave. Something that needs any of those is not an action -- it is
the orchestrator's job, operating on what an ack gave it.

A result too large to summarise comes back as a **sealed blob reference** rather
than as bytes, so the agent must then pass the `may_unseal` gate (ADR 0020) to
read any of it. Acknowledgement by default; disclosure as a second, separately
granted step.

### Two capability checks at the gateway, not one

`may_act` says this agent may ask for actions at all; `act_actions` says which. A
grant with only the first would be a grant to do anything the build knows how to
do, which is not a capability anybody would knowingly sign. The refusal is
identical either way, so an agent probing which actions a grant covers learns
nothing the owner did not tell it.

The gateway decides *who is asking*; the enclave decides *what may be done in
here*. The orchestrator checks neither, and that is deliberate: it cannot verify
a grant's signature, so a check there would pass on a forged token the gateway
would reject while reading in the code as though it were the gate.

### A refusal is still an acknowledgement

`200` with `ok: false`. An attempt made and failed is a different fact from one
never made, and collapsing them into an HTTP error would lose the distinction a
trace needs most -- the same reason every tool in the Python layer returns a
result instead of raising. A provider error never becomes ack text: it can carry
request URLs and token prefixes, so it propagates as an error and the attempt is
recorded without the provider's words in it.

### The record

`:AgentAction` is the fourth append-only record and the only one about something
that happened **outside** this system. A read discloses, a mutation changes the
record; an action sends mail, and cannot be undone by rewriting a row.

So it is written *after* the enclave answers and the write failing propagates: an
agent told "this may have happened and was not recorded" can go and check, while
one told "done" cannot.

**The arguments are not stored.** They are the content the action handled, and a
log keeping them would be a second uncontrolled copy of exactly what the enclave
exists to keep from the operator. A keyed digest over them is kept instead, which
answers the question an owner actually has: was that sent once, or forty times?

## Alternatives

- **Mint a short-lived access token and hand it to the orchestrator.** The
  README's own prediction. Strictly weaker: exposure is one token lifetime rather
  than none, and the host holds a usable credential for that window.
- **Perform actions in the orchestrator with an unsealed refresh token.** Breaks
  the invariant the entire connect flow is built around.
- **A host-configurable action list.** The enclave's environment comes from the
  host, so this is the operator choosing what the TEE will do.
- **Return the provider's response to the agent.** Makes the ack a disclosure
  channel with no permission check in front of it.

## Consequences

- An agent can ask for work to be done and never holds a credential.
- **Only `attest.digest` is wired**, and deliberately the one needing no provider
  credential: it proves the shape without pretending the credential path exists.
  `google.gmail.send` and `github.issue.comment` are declared with real metadata
  and refuse explicitly, naming what is missing -- the enclave has no path from a
  sealed refresh token to a short-lived access token. That is roadmap step 5 and
  gets its own ADR.
- The TCB grew by one route and one registry. The constraints above are what keep
  that from being the first step of growing it without limit, and they are stated
  rather than merely intended.
- **None of this has run on real Nitro hardware.** In mock mode the providers
  short-circuit exactly as the OAuth providers do, so "the agent never held the
  credential" is proven as a code path and not as a hardware property. Until an
  `.eif` runs on EC2 this is a correct design with no attestation behind it.
