# Architecture decision records

One decision per file. **An accepted record is immutable**: a decision that is
reversed gets a new record superseding it, rather than an edit. That is the same
shape as the memory layer's own `supersedes`, and for the same reason — the
earlier reasoning is part of the history, and overwriting it loses why anyone
thought otherwise.

Each file carries its own `Status` and `Date`.

## On the frontmatter

These files have a YAML `title` and `description` block, and the `# ADR NNNN:`
heading that used to sit below it is gone. That is a rendering change and not an
edit to any record: the title text is byte-identical to the heading it replaced,
the description is the record's own first sentence, and no sentence of any
decision was changed, added or removed.

It exists because these files were once served as documentation pages, where a
frontmatter title and a body heading saying the same thing render as the title
twice. They are no longer served -- see the note below -- and the frontmatter
stays anyway. Stripping it would mean touching twenty-five accepted records to
undo a formatting decision, which is a worse trade than a title line nothing
renders.

If a future record is added by hand, the frontmatter is the only part this
convention asks for:

```markdown
---
title: "ADR 00NN: What was decided"
description: "The first sentence of Context."
---

**Status:** accepted
**Date:** YYYY-MM-DD

## Context
...
```

Until these existed, this repository's reasoning lived in two READMEs and in
commit messages. That worked while there was one author and one running
argument, and it is why the READMEs are unusually long: every decision had to be
re-justified in prose next to the thing it governed.

**An accepted record is immutable.** A decision that is reversed gets a new
record that supersedes it, rather than an edit — which is the same shape as the
memory layer's own `supersedes`, and for the same reason: the earlier reasoning
is part of the history, and overwriting it loses why anyone thought otherwise.

## The records

| | Decision |
| --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions |
| [0002](0002-persist-sealed-ciphertext-in-a-blob-store.md) | Persist sealed ciphertext in a blob store |
| [0003](0003-recency-is-a-real-half-life-and-ranking-is-configurable.md) | Recency is a real half-life, and ranking is configurable |
| [0004](0004-derive-per-purpose-signing-keys-from-one-root.md) | Derive per-purpose signing keys from one root |
| [0005](0005-log-what-each-grant-disclosed.md) | Log what each grant disclosed |
| [0006](0006-measure-the-central-bet-before-building-on-it.md) | Measure the central bet before building on it |
| [0007](0007-measure-disclosure-not-only-recall.md) | Measure disclosure, not only recall |
| [0008](0008-store-sealed-bodies-as-quilt-patches.md) | Store sealed bodies as Quilt patches |
| [0009](0009-affect-as-a-closed-vocabulary-that-raises-the-floor.md) | Affect as a closed vocabulary that raises the floor |
| [0010](0010-encrypt-the-resolved-record-at-rest.md) | Encrypt the resolved record at rest |
| [0011](0011-the-owner-signs-grants-not-the-gateway.md) | The owner signs grants, not the gateway |
| [0012](0012-embed-locally-with-a-real-model.md) | Embed locally with a real model |
| [0013](0013-a-push-path-for-what-the-person-says.md) | A push path for what the person says |
| [0014](0014-following-what-the-person-referred-to.md) | Following what the person referred to |
| [0015](0015-two-names-for-one-thing.md) | Two names for one thing |
| [0016](0016-agent-identity-is-the-device-that-signed-the-grant.md) | Agent identity is the device that signed the grant |
| [0017](0017-an-agent-writes-under-a-grant-that-says-it-may.md) | An agent writes under a grant that says it may |
| [0018](0018-memory-kinds-and-short-term-as-a-state.md) | Memory kinds as a closed vocabulary, and short-term as a state |
| [0019](0019-every-state-change-is-a-record.md) | Every state change is a record, not an overwrite |
| [0020](0020-reading-a-sealed-body-under-a-grant.md) | Reading a sealed body under a grant |
| [0021](0021-the-briefing-and-why-reading-is-not-remembering.md) | The briefing, and why reading is not remembering |
| [0022](0022-sensitive-actions-are-brokered-in-the-tee.md) | Sensitive actions are brokered in the TEE |
| [0023](0023-the-owners-key-lives-in-the-browser.md) | The owner's key lives in the browser |
| [0024](0024-the-enclave-assembles-and-reseals-to-the-device.md) | The enclave assembles, and re-seals to the asking device |
| [0025](0025-reasoning-across-sessions-writes-claims-not-blocks.md) | Reasoning across sessions, and why its output is a claim |

The seven from 0016 are the agent harness, written after the fact: steps 1
through 11 landed with their reasoning in commit messages and code comments,
which is the situation ADR 0001 exists to end.

## Open decisions

Five are deliberately open, and each gets a record when it is made. Two were
closed by later records: *whether `assemble` synthesises or formats* is pinned to
formatting by [ADR 0024](0024-the-enclave-assembles-and-reseals-to-the-device.md),
and *what the harness does with accumulated context* by
[ADR 0025](0025-reasoning-across-sessions-writes-claims-not-blocks.md).

**Where extraction runs.** The tension is in [the confidentiality model](../docs/concepts/confidentiality.mdx):
extraction and resolution still handle plaintext on the host, and the resolver
unsealing *stored* claims is the sharper half.

**What triggers a reasoning pass.** [ADR 0025](0025-reasoning-across-sessions-writes-claims-not-blocks.md) rules
out per-block and timer-based passes; the threshold itself is unchosen.

**Whether the reasoning model may be hosted.** It decides the sentence the subscription rests on: the enclave's TLS tunnel hides
the prompt from the operator, not from the provider that answers it.

**Retention for transcripts and derived memory.** Tracked and unscheduled, which is overdue for anything that accumulates
somebody's memory by subscription.

**Whether to adopt on-chain components at all.** Only if beta users demonstrably need them. The blob store already has the shape
Walrus has, so it stays a second implementation rather than a migration.

## These are not published

They live here and not under `docs/` on purpose. `docs/` is a Mintlify site for
somebody using Kleos, and an architecture decision record is written for whoever
maintains it -- it argues with alternatives, names what is stubbed, and says
where the current build falls short of the claim. A reader who wants to know how
grants work is served by `docs/concepts/permissions`; a reader who wants to know
why the owner signs them rather than the gateway is reading this directory, and
is one of us.

ADR 0001 specified `docs/adr/NNNN-slug.md` as the location. The move to `adr/` is
a change of path, not of any decision: no record's text was edited, and 0001's
convention for numbering, immutability and supersession is untouched.
