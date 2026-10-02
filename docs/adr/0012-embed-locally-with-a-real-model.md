# ADR 0012: Embed locally, with a real model

**Status:** accepted
**Date:** 2026-10-02

## Context

Every retrieval number this project has ever reported came from
`HashedTokenEmbedder` — a bag-of-tokens projection into a fixed-width unit vector.
Stable, keyless, reproducible, and not semantic: it matches on shared vocabulary
and nothing else. ADR 0006 said so, and the eval report has printed a warning on
every run since: *the delta is meaningful and the absolute numbers are not.*

Two things made that stop being tolerable at the same time.

**Live extraction made the corpus bigger.** With the LLM extractor the eval corpus
resolves to 118 objects where the rule-based one produced 54 — a richer, more
correct graph. Recall on the "what changed and why" question went from 100% to
**0%**. Not an extraction regression: a retrieval one. Lexical hashing cannot rank
over a pool that size, and the question it fails on is the one whose evidence
records never mention what they caused, so there is no shared vocabulary to match.

**The numbers were being used.** ADR 0006's findings — "the query graph alone
retrieves less than plain cosine" and "graph proximity returns a wrong-answer
record on both cross-project questions" — were reported as findings about the
*design*. They were artifacts of the embedder. Both disappear below. Continuing to
reason about architecture from numbers produced by a toy embedder was the real
risk.

## Decision

`fastembed` with `BAAI/bge-small-en-v1.5`: 384 dimensions, ~67MB of ONNX weights,
CPU, no API key, no torch. `EMBEDDING_DIM` moves 256 → 384.

**Local rather than hosted, for reasons that are not cost.**

- Embedding text means sending it somewhere, and the text here is the resolved
  record — precisely what ADR 0010 encrypts at rest. Encrypting a database and then
  streaming the same sentences to a third party to be vectorised would be theatre.
- `test_content_at_rest` asserts a stored vector equals a freshly computed one.
  That holds for a pinned local model and not for a versioned endpoint; a hosted
  embedder would have made a correctness test flaky and the fix would have been to
  weaken the test.
- Embeddings are on the ingest path for every object, so a network round trip per
  object would set the backfill rate.
- No key to provision, which matters because the one provider key this project has
  serves no embedding model.

Weights download once and cache, putting the network dependency at install time
rather than query time.

### The silent failure that had to be fixed first

`apply_migrations` created the vector index with `CREATE VECTOR INDEX ... IF NOT
EXISTS`. Against an existing database, changing the dimension therefore did
**nothing**: the 256-dim index survived, the function logged `embedding_dim=384` as
though it had taken effect, 384-wide writes landed as list properties the index
declined to cover, and reads then failed inside `vector_search` with an arity error
far from the cause. Configuration and reality disagreeing, with the log siding with
configuration.

Three changes make a mismatch loud instead:

1. **`apply_migrations` reads the live dimension** from `SHOW INDEXES` and drops and
   recreates the index when it differs — warning that every stored embedding is now
   unusable and a re-ingest is required. It does not re-embed automatically:
   re-embedding a corpus is expensive and owner-scoped, and silently starting one on
   boot would be worse than saying so.
2. **`Neo4jStore.upsert` refuses a vector of the wrong width.** Neo4j accepts a
   mis-sized vector as an ordinary list property, so without this the write
   succeeds and the node is permanently invisible to retrieval — a write that
   succeeds and loses the data.
3. **`verify_dim` runs at `Runtime.build`**, before the migration, comparing the
   model's actual output width against configuration. The model is the authority;
   configuration is what the index is built from; those two disagreeing is the whole
   bug class.

## Result

Eval with the local embedder and live extraction, 34 records, 6 questions, `top_k=5`:

| metric | resolved | resolved+history | plain-rag |
|---|---|---|---|
| recall | 93% | **100%** | 93% |
| precision | **46%** | 42% | 27% |
| cited | 100% | 100% | 0% |
| unmarked stale | 0% | 0% | 50% |
| forbidden returned | **0%** | **0%** | 17% |

Compared against the hashed-token run, three things changed and two of them are
corrections to ADR 0006:

- **The history question recovered**, 0% → 60% on the query graph alone → **100%**
  with the supersession read. The local embedder ranks the throughput-evidence
  record above the cross-project distractor (0.679 vs 0.619 cosine) where the hashed
  embedder could not, because the evidence shares almost no vocabulary with the
  question.
- **"The query graph alone retrieves less than the baseline" is withdrawn.** It was
  87% vs 93%; it is now 93% vs 93%. The ranking was not the problem.
- **"Graph proximity costs precision across projects" is withdrawn.** Forbidden
  records went 33% → **0%**. Proximity was pulling in neighbours because the
  semantic term was too weak to dominate it, not because proximity is wrong.

Precision nearly doubled against the baseline (46% vs 27%), and the report's
"absolute numbers are not meaningful" warning no longer prints.

## Alternatives

- **A hosted embedder (Voyage, OpenAI).** Better quality per dimension, and it
  sends the resolved record to a third party, needs a key this project does not
  have, makes a correctness test flaky, and puts a network hop on the ingest path.
- **`sentence-transformers` locally.** The same models, through torch — roughly 2GB
  of dependencies against 67MB, for an identical vector.
- **A larger local model (`bge-base`, `bge-large`).** Available and a drop-in via
  `EMBEDDING_MODEL`. Not yet justified: `bge-small` already moved every metric the
  right way, and the eval is the thing that should decide, not taste.
- **bge's recommended query instruction prefix.** The model card suggests prefixing
  *queries* (not documents) for retrieval. It would mean the `Embedder` protocol
  growing asymmetric query/document methods. Deferred as tuning, to be decided by
  the eval rather than by the model card.
- **Keep hashed embeddings and tune ranking weights.** What ADR 0006's findings
  implied. It would have been tuning against noise, and ADR 0003 made the weights
  configurable specifically so the eval could settle them — the eval first needed to
  measure something real.

## Consequences

- **Every stored embedding is invalid.** 256-wide vectors from a different model;
  the index is recreated and a re-ingest is required. Fine now, and after a beta
  this needs a re-embed job rather than a warning in a log line.
- A test that asserted recall direction on hashed embeddings had to stop doing so.
  It moved from 100% to 83% when the vector width changed, with no change to
  retrieval, resolution or the corpus — a number that moves when an unrelated
  constant moves was never evidence. The structural assertions (staleness marking,
  citations) stay, because they do not depend on ranking, and the recall comparison
  now belongs to a reported run against the real embedder.
- First load is ~20s while weights are fetched and the ONNX session starts, then
  ~1ms per embedding. Acceptable for a background job; `embed_many` exists for the
  batched case and ingestion should move to it when a backfill makes it matter.
- The eval now takes ~165s end to end, most of it LLM extraction rather than
  embedding.
- `fastembed` adds onnxruntime to the dependency set. Deliberately not torch.
