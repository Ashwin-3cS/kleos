/**
 * The warnings, which are the composer's actual job.
 *
 * A grant that verifies and reads nothing is the hardest mistake to diagnose
 * from the agent's side, because it is indistinguishable from an empty memory.
 * Every case below produces exactly that, and every one of them is invisible in
 * a hand-written `scope.json` -- which is what this screen replaces.
 */

import { describe, expect, it } from "vitest";

import { collectWarnings } from "./ScopeComposer";
import { emptyScope, type Scope } from "../lib/grants";

/** A scope that reads something, so each test varies one thing. */
function workable(overrides: Partial<Scope> = {}): Scope {
  return {
    ...emptyScope("owner-x", "agent-x"),
    sources: ["mock"],
    entity_kinds: ["person", "project"],
    memory_kinds: ["episodic"],
    ...overrides,
  };
}

const texts = (scope: Scope) => collectWarnings(scope).map((w) => w.text).join(" ");
const fatal = (scope: Scope) => collectWarnings(scope).filter((w) => w.fatal);

describe("collectWarnings", () => {
  it("says nothing about a scope that works", () => {
    expect(collectWarnings(workable())).toEqual([]);
  });

  it("treats an empty source list as fatal, because it grants nothing", () => {
    // Deny-by-default, which reads backwards to anyone expecting a filter: an
    // empty list is not "no restriction".
    expect(fatal(workable({ sources: [] }))).toHaveLength(1);
    expect(texts(workable({ sources: [] }))).toContain("deny-everything");
  });

  it("treats an empty entity-kind list as fatal too", () => {
    expect(fatal(workable({ entity_kinds: [] }))).toHaveLength(1);
  });

  it("warns without blocking when no memory kind is named", () => {
    // Not fatal: unkinded claims still come back, and in an older graph that is
    // most of them. So this grant works and degrades, which is a warning.
    const warnings = collectWarnings(workable({ memory_kinds: [] }));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]!.fatal).toBe(false);
  });

  it("catches tacit memory below its own floor", () => {
    // The trap: the grant verifies, names the kind, and reads none of it,
    // because `MemoryKind::Tacit` floors at confidential.
    const warned = texts(workable({ memory_kinds: ["tacit"], max_sensitivity: "personal" }));
    expect(warned).toContain("floored at confidential");

    expect(
      collectWarnings(workable({ memory_kinds: ["tacit"], max_sensitivity: "confidential" })),
    ).toEqual([]);
  });

  it("catches writing with nowhere to write as", () => {
    // `write_sources` is separate from `sources` so that "read my notes" can
    // never mean "write something that claims to be my note" -- which means
    // turning writing on is not enough by itself.
    expect(fatal(workable({ may_write: true }))).toHaveLength(1);
    expect(
      collectWarnings(workable({ may_write: true, write_sources: ["agent"] })),
    ).toEqual([]);
  });

  it("catches acting with no action named", () => {
    expect(fatal(workable({ may_act: true }))).toHaveLength(1);
    expect(
      collectWarnings(workable({ may_act: true, act_actions: ["attest.digest"] })),
    ).toEqual([]);
  });

  it("notes superseding the owner without blocking it", () => {
    const warnings = collectWarnings(
      workable({ may_write: true, write_sources: ["agent"], may_supersede_owner: true }),
    );
    expect(warnings).toHaveLength(1);
    expect(warnings[0]!.fatal).toBe(false);
    expect(warnings[0]!.text).toContain("overwrite decisions you recorded yourself");
  });

  it("reports every problem at once rather than the first", () => {
    // An owner fixing one thing at a time, with a form that re-blocks on the
    // next, learns nothing about what the scope needs.
    const warnings = collectWarnings(
      emptyScope("owner-x", "agent-x"),
    );
    expect(warnings.length).toBeGreaterThanOrEqual(2);
  });
});
