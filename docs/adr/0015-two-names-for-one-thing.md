# ADR 0015: Two names for one thing

**Status:** accepted
**Date:** 2026-10-03

## Context

An entity id is `stable_id("ent", owner_id, kind, name.lower())`. So `RAG` and
`retrieval augmented generation` are two permanently separate nodes, and `Postgres`
and `PostgreSQL` are two databases.

This is not a cosmetic problem. The resolver finds claims to compare a new one
against by looking up `claims_about(owner_id, subject_entity_ids)`. A decision
recorded under the acronym is therefore **never weighed against** a decision
recorded under the expansion: no supersession is detected, no contradiction is
noticed, and both sit in the record as active, current and mutually invisible. The
duplicate entity is the visible symptom; the hole in the resolution is the actual
defect.

## Decision

A `canonicalise` node between extraction and resolution, matching names with
deterministic rules, with embeddings playing no part.

### Embeddings do not work here, and the measurement is the reason

The obvious design — and what this was planned as — is cosine similarity above a
threshold. Measured under `bge-small-en-v1.5`, the model this service already uses:

| should merge | | should **not** merge | |
|---|---|---|---|
| `RAG` ~ `retrieval augmented generation` | **0.531** | `Postgres` vs `Redis` | **0.652** |
| `K8s` ~ `Kubernetes` | 0.674 | `Mina` vs `Rafi` | 0.542 |
| `Mina` ~ `Mina Patel` | 0.794 | `Lantern` vs `Harbour` | 0.528 |
| `Kleos` ~ `project Kleos` | 0.897 | `Kleos` vs `Harbour` | 0.525 |
| `Postgres` ~ `PostgreSQL` | 0.934 | `RAG` vs `sourdough bread` | 0.519 |

The lowest true positive (0.531) sits **below** the highest true negative (0.652).
The classes overlap, so no threshold separates them. Any cutoff low enough to catch
the acronym also merges two unrelated databases into one entity.

The fallback position was to keep embeddings as a **veto** — never causing a merge,
only blocking a lexical one. That does not survive the same measurement: a veto
floor must sit below 0.531 to avoid killing the acronym case and above 0.542 to
reject anything at all. No such number exists. So the veto was dropped too, and
embeddings are absent from this module entirely.

Two things worth stating plainly, because the instinct is to reach for the model:

- **Every pair embeddings score highly (0.794–0.934) is one a cheap lexical rule
  also catches.** Containment or a shared prefix handles all of them. The embedder
  adds nothing on the easy cases.
- **The one case needing real help is exactly where it fails.** The acronym is the
  pair a person would most want joined, and it scores lowest of the five.

This is not a surprising result once stated: a sentence embedder was trained on
sentences, and a two-word proper noun gives it almost nothing to work with. It is
recorded here because "use embeddings for entity resolution" will be proposed again,
and the answer should be a number rather than an opinion.

### The rules, and what each one is guarded against

Strongest first; the scores exist only to order them and to detect a tie, and
nothing thresholds on a score.

- **`same_normalised`** — equal after lowercasing and dropping punctuation, or equal
  once separators are removed entirely. `Node.js` ~ `nodejs`.
- **`acronym`** — a 2–6 character name equals the initials of a multi-word name.
  `RAG` ~ `retrieval augmented generation`, and `R.A.G.` too, because the compact
  form throws the separators away.
- **`suffix_fold`** — one name is the other plus at most three more characters, with
  the shorter at least five. `Postgres` → `PostgreSQL` folds; `Redis` →
  `Redisearch` does not, because a five-character tail is a different word and this
  rule cannot tell a suffix from the start of another name.
- **`containment`** — one name's words appear in the other as a **contiguous** run,
  with the shorter at least four characters. `Mina` ⊂ `Mina Patel`. Contiguous
  because `Lantern review` should not match `Lantern design review` — a design
  review of Lantern is not the Lantern review. Four characters because `AI` is
  inside a hundred unrelated names.
- **Kind must agree.** Without it, a project named after the person running it
  collapses the two, and "what does Mina owe me" starts answering about a project.
- **Containment does not apply to topics**, and this one was measured rather than
  reasoned. See below.

**A known miss, recorded rather than forced:** `K8s` ~ `Kubernetes` does not match.
It is a numeronym — the digit stands for elided letters — and the pattern that would
catch it (letter, digits, letter) also matches version and model names, so it would
merge `Llama 3` into `Llama 31`. One duplicate is cheaper than that.

### Containment means two different things, and only one of them is identity

The first measured run merged `storage` into `durable storage`. Lexically correct, and
wrong: for a *proper noun*, a longer name containing a shorter one is the same referent
named more fully — `Mina` and `Mina Patel` are one person. For a *common noun phrase* it
is a hyponym — `storage` and `durable storage` are a topic and a sub-topic — and folding
them asserts an identity that does not hold while building a high-degree node that every
project's storage claims hang off.

**The eval caught it and a single metric would not have.** With topics merged, the
Harbour question began returning the *Lantern* storage decision — cross-project
contamination straight through that shared node — while recall and precision stayed
exactly flat at 0.900 and 0.417. The entity count went down, which is what this phase
was supposed to achieve. Reported alone, it would have read as a clean win.

Measured over the eval corpus, `EMBEDDER=real EXTRACTOR=llm`:

| | off | containment on topics | topics excluded |
|---|---|---|---|
| distinct entities | 56 | 52 | 49 |
| resolved recall | 0.900 | 0.900 | **0.933** |
| resolved precision | 0.417 | 0.417 | **0.433** |
| forbidden returned | 0.000 | **0.167** | 0.000 |

**What these numbers do and do not support.** The extractor is an LLM, so the entity
counts carry run-to-run variance and the gap between 56 and 49 is not wholly
attributable to canonicalisation; neither is the recall move from 0.900 to 0.933, which
is one question out of six. The firm finding is the middle column, because its cause was
identified by reading the graph rather than inferred from the metric: the merged
`storage` node was there in the alias list, and the contaminated answer reached the
Harbour question through it.

So containment is forbidden for `TOPIC`, the one kind whose names are common noun
phrases. Only containment: an acronym or a shared spelling asserts identity, which is as
true of a topic as of a person, and `RAG` ~ `retrieval augmented generation` are both
topics — a blanket exclusion would have defeated the phase's whole purpose.

### Ambiguity resolves to leaving a duplicate

If two targets match equally well, the answer is to merge with neither, and the
refusal is reported rather than silent.

The asymmetry is the whole reason the rules above are so narrow. A duplicate is
visible and recoverable — a later merge fixes it. A wrong merge is neither: two
people's histories are now one person's, nothing records that they were ever
separate, and **this system has no per-object deletion to undo it with**. Until it
does, every uncertain case has to fail towards the duplicate.

### A stored id always survives, even when it is the shorter name

Within a batch the longer name wins, so two new names give
`retrieval augmented generation` with `RAG` as an alias — the more specific label is
the better one to show. But an id already in the graph always survives regardless of
length, because rewriting references on *stored* nodes would need a migration this
has no way to perform. The consequence is an inconsistency worth naming: whether the
acronym or the expansion ends up canonical depends on which arrived first.

### Before `resolve`, not after

`canonicalise` sits between extract/enrich and resolve. Both paths into resolution
go through it, and a test asserts that against the compiled graph.

If it ran after resolution, the graph would end up tidy and the record wrong: the
resolver would still have compared the new `RAG` claim against nothing, the
supersession would still be missed, and **nothing would fail**. Ordering that only
matters silently is ordering to pin down in a test.

Unconditional, unlike `enrich`: every batch has entities, so there is no cheap test
that would let it be skipped. Switched off wholesale by `CANONICALISE_ENTITIES`
instead — and **on by default**, unlike enrichment, because this reaches nothing
outward and a record that silently keeps two of every entity is the behaviour worth
needing a flag to get back.

### Reference rewriting is where a bug would hide

Merging ids means rewriting every field that holds one: `Event.entity_ids`,
`Claim.subject_entity_ids`, and a commitment's `owed_by_entity_id` and
`owed_to_entity_id`. A merge that updates the entity and misses the commitment
leaves an obligation pointing at an id no node has, so "what does Mina owe me"
returns nothing and reports no error. Each field is covered by a test that asserts
on it by name.

Rewriting is safe because a claim id is derived from `(owner, event_id, statement)`
and not from its subjects, so changing a subject does not invalidate the id the
resolver de-duplicates on.

## Alternatives

- **Embedding similarity above a threshold.** The measurement above. Rejected on
  evidence rather than taste.
- **Embeddings as a veto over lexical proposals.** The same measurement; no floor
  exists.
- **Ask the LLM whether two names are the same thing.** Plausible, and it would
  catch `K8s`. Rejected for now on three counts: it is a network call per candidate
  pair against an *O(n²)* comparison, the answer is not reproducible so the same
  corpus could canonicalise differently on re-ingest, and the input is attacker-
  influenced — a fetched page naming an entity would get a say in which of the
  person's entities it merges with, which is ADR 0014's rule 1 one layer down.
- **Merge at read time instead of write time.** Keeps every name the person used and
  loses nothing. But it leaves the resolver reading the unmerged graph, which is the
  actual defect, so it would fix the symptom and not the cause.
- **A user-facing merge review.** The right eventual answer for the uncertain cases,
  and what `ambiguous` is the data for. Not yet, because there is no interface to
  review them in.
- **An alias dictionary the person maintains.** No guessing at all, and no adoption
  either; a feature that requires setup before it does anything mostly does nothing.

## Consequences

- **Canonicalisation found a duplicate the system was already creating.** The mock
  extractor's artifact pattern swallows the sentence's full stop, so it emitted
  `Postgres` and `Postgres.` as two entities with two ids. That had been happening
  on every ingest and nothing noticed. The node collapses them, and the extractor
  pattern is still wrong.
- **The merge target set is bounded** at `CANONICALISE_MAX_ENTITIES` (2,000), most
  recently seen first. Past it, an entity nobody has mentioned lately stops being a
  merge target and a duplicate is created instead. That is the correct direction to
  fail in, but it does mean canonicalisation is best-effort on a large graph, and
  the comparison is *O(candidates × pool)* with no index behind it.
- **A re-mention no longer wipes out an alias.** `upsert` replaces the payload
  wholesale, so an entity mentioned again arrived with an empty alias list and
  overwrote whatever a merge had added — silently re-opening the duplicate. Found
  while writing this and fixed in the same node, which is where the stored entity is
  already in hand. It was a pre-existing defect, not one this change introduced.
- **Sealed names do not match.** With `ENCRYPT_CONTENT_AT_REST=true` the node is
  handed `unseal_node` exactly as the resolver is. If unsealing is unavailable the
  rules see ciphertext, match nothing, and cost a duplicate — the safe direction,
  but it compounds the open defect that reads cannot decrypt at all.
- **Containment on a project carries the same hyponym risk as on a topic.** The eval
  corpus merged `Harbour API` into `Harbour`, which is the general/specific shape that
  the topic rule exists to prevent. It is not punished by the current questions, so
  there is no evidence to act on and `PROJECT` is left allowed — but it is the next
  place this rule is likely to be found wrong, and it would be found the same way.
- **Nothing undoes a merge.** The alias records what the name was, which is enough
  to find the entity again but not enough to split it back into two. The missing
  primitive is per-object deletion, which this system still does not have anywhere.
