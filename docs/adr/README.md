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
decision was changed, added or removed. It exists because these files are served
as documentation pages, where a frontmatter title and a body heading saying the
same thing render as the title twice.

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

## Index

The rendered index, with the open decisions listed alongside, is
`docs/decisions/index.mdx`.
