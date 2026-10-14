/**
 * Composing a scope, and teaching the three things the CLI silently hides.
 *
 * Writing `scope.json` by hand produces grants that verify, look reasonable, and
 * read nothing. All three ways that happens are invisible in a JSON file and
 * obvious in a form, so surfacing them is most of this component's job:
 *
 * 1. **Sources and entity kinds are `all`, not `any`.** `evaluate` requires every
 *    source an object was derived from to be in scope (`permissions.rs:176`), so
 *    a record built from a page *and* a note needs both. A picker that reads as
 *    "choose a source" ships grants that miss exactly the objects with the most
 *    provenance.
 * 2. **An empty list grants nothing**, not everything. Deny-by-default.
 * 3. **`tacit` floors at `confidential`** (`memory.rs:302`), so a grant naming
 *    tacit memory at `personal` reads none of it.
 *
 * It also states what nothing in the JSON says: `agent_id` is a label the owner
 * typed and nothing authenticates it. The authenticated identity is the device
 * key that signs.
 */

import { useEffect, useMemo, useState } from "react";

import {
  type EntityKind,
  type MemoryKind,
  type Scope,
  type Sensitivity,
} from "../lib/grants";
import type { StoredKey } from "../lib/keys";
import { describe } from "./SignIn";

const ENTITY_KINDS: EntityKind[] = [
  "person",
  "project",
  "artifact",
  "organization",
  "topic",
];
const MEMORY_KINDS: MemoryKind[] = ["episodic", "procedural", "tacit"];
const SENSITIVITIES: Sensitivity[] = ["public", "personal", "confidential", "restricted"];

/** Known at build time; replaced by whatever `/sources` reports. */
const FALLBACK_SOURCES = ["mock", "text", "chatgpt", "agent", "google", "github", "web"];

/**
 * TTLs the UI will compose. **Client-side policy only** -- nothing clamps a
 * grant's TTL server-side (`sign_grant` honours whatever it is given), so another
 * client can sign a grant lasting a decade. Offering a bounded set here is the
 * dashboard declining to make that easy, not an enforcement.
 */
const TTLS: { label: string; secs: number }[] = [
  { label: "1 hour", secs: 3600 },
  { label: "8 hours", secs: 8 * 3600 },
  { label: "7 days", secs: 7 * 86400 },
  { label: "30 days", secs: 30 * 86400 },
];

export function ScopeComposer(props: {
  ownerId: string;
  keys: StoredKey[];
  baseScope: Scope;
  onIssue: (
    scope: Scope,
    keyId: string,
    ttlSecs: number,
  ) => Promise<{ token: string; verified: { scope: Scope; key_id: string } }>;
}) {
  const [scope, setScope] = useState<Scope>(props.baseScope);
  const [keyId, setKeyId] = useState<string>("");
  const [ttl, setTtl] = useState<number>(3600);
  const [sources, setSources] = useState<string[]>(FALLBACK_SOURCES);
  const [result, setResult] = useState<{ token: string; verified: Scope } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // The authoritative source vocabulary, so a connector added to the service
    // shows up here without an edit. Falls back silently: a list of source names
    // is not worth an error banner.
    fetch("/sources")
      .then((r) => (r.ok ? r.json() : null))
      .then((body: { sources?: { id?: string }[] } | null) => {
        const ids = (body?.sources ?? []).map((s) => s.id).filter((s): s is string => !!s);
        if (ids.length) setSources([...new Set([...ids, "agent"])].sort());
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!keyId && props.keys[0]) setKeyId(props.keys[0].keyId);
  }, [props.keys, keyId]);

  const patch = (next: Partial<Scope>) => {
    setScope((current) => ({ ...current, ...next }));
    setResult(null);
  };

  const toggle = <T extends string>(list: T[], value: T): T[] =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

  const warnings = useMemo(() => collectWarnings(scope), [scope]);
  const fatal = warnings.filter((w) => w.fatal);

  async function issue() {
    setBusy(true);
    setError(null);
    try {
      const { token, verified } = await props.onIssue(
        { ...scope, owner_id: props.ownerId },
        keyId,
        ttl,
      );
      setResult({ token, verified: verified.scope });
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>Issue a grant</h2>
      <p className="why">
        A grant is a signed capability, not a database row. It is signed here, by
        a key in this browser, and the gateway can only verify it &mdash; which is
        why nobody running the server can issue one.
      </p>

      <div className="grid2">
        <div>
          <label className="field">
            <span className="name">Signed by</span>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
              {props.keys.map((k) => (
                <option key={k.keyId} value={k.keyId}>
                  {k.label || "(unlabelled)"} &mdash; {k.keyId.slice(0, 12)}
                </option>
              ))}
            </select>
            <span className="hint">
              {props.keys.length === 0
                ? "No usable key. Generate and register one above."
                : "Revoking this key later invalidates every grant it signed."}
            </span>
          </label>

          <label className="field">
            <span className="name">Agent label</span>
            <input
              type="text"
              value={scope.agent_id}
              placeholder="chatgpt"
              onChange={(e) => patch({ agent_id: e.target.value })}
            />
            <span className="hint">
              A name for your own benefit. <strong>Nothing authenticates it</strong>
              &nbsp;&mdash; any holder of the token presents this label. The
              identity that is checked is the key above.
            </span>
          </label>

          <label className="field">
            <span className="name">Valid for</span>
            <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              {TTLS.map((t) => (
                <option key={t.secs} value={t.secs}>
                  {t.label}
                </option>
              ))}
            </select>
            <span className="hint">
              Short is the real control: there is no way to revoke one grant, only
              the key that signed it.
            </span>
          </label>

          <label className="field">
            <span className="name">Up to sensitivity</span>
            <select
              value={scope.max_sensitivity}
              onChange={(e) => patch({ max_sensitivity: e.target.value as Sensitivity })}
            >
              {SENSITIVITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="hint">Inclusive: everything at this level and below.</span>
          </label>
        </div>

        <div>
          <Picker
            name="Sources it may read"
            hint="Every source an object came from must be here. An object built from a page and a note needs both — so a narrow list quietly skips the best-attested records."
            options={sources}
            selected={scope.sources}
            onToggle={(v) => patch({ sources: toggle(scope.sources, v) })}
          />
          <Picker
            name="Entity kinds"
            hint="Also all, not any, and also empty means nothing."
            options={ENTITY_KINDS}
            selected={scope.entity_kinds}
            onToggle={(v) =>
              patch({ entity_kinds: toggle(scope.entity_kinds, v as EntityKind) })
            }
          />
          <Picker
            name="Memory kinds"
            hint="Episodic is what was decided, procedural is how something is done, tacit is an inference about the person they never stated."
            options={MEMORY_KINDS}
            selected={scope.memory_kinds}
            onToggle={(v) =>
              patch({ memory_kinds: toggle(scope.memory_kinds, v as MemoryKind) })
            }
          />
        </div>
      </div>

      <h2 style={{ fontSize: 13, marginTop: 10 }}>What it may do</h2>
      <div className="toggles">
        <label>
          <input
            type="checkbox"
            checked={scope.may_write}
            onChange={(e) => patch({ may_write: e.target.checked })}
          />
          <span>
            <strong>Write memory</strong>
            <span className="hint">
              Record what it decided, and why. The reason is what the next agent
              is briefed with.
            </span>
          </span>
        </label>
        {scope.may_write ? (
          <>
            <Picker
              name="Write as source"
              hint="Separate from reading on purpose: 'read my notes' must never be able to mean 'write something that claims to be my note'. Agents write as `agent`."
              options={sources}
              selected={scope.write_sources}
              onToggle={(v) => patch({ write_sources: toggle(scope.write_sources, v) })}
            />
            <label>
              <input
                type="checkbox"
                checked={scope.may_supersede_owner}
                onChange={(e) => patch({ may_supersede_owner: e.target.checked })}
              />
              <span>
                <strong>May supersede what you recorded yourself</strong>
                <span className="hint">
                  Off, an agent&rsquo;s conflicting claim is recorded as a
                  contradiction and yours stands. On, it is treated as a delegate
                  acting for you and can replace yours.
                </span>
              </span>
            </label>
          </>
        ) : null}
        <label>
          <input
            type="checkbox"
            checked={scope.may_unseal}
            onChange={(e) => patch({ may_unseal: e.target.checked })}
          />
          <span>
            <strong>Unseal original bodies</strong>
            <span className="hint">
              Seeing a claim is not permission to pull the transcript it came
              from. This grants the second one.
            </span>
          </span>
        </label>
        <label>
          <input
            type="checkbox"
            checked={scope.may_act}
            onChange={(e) => patch({ may_act: e.target.checked })}
          />
          <span>
            <strong>Ask the enclave to act</strong>
            <span className="hint">
              The agent submits an intent and gets back an acknowledgement. It
              never receives the credential, or what the credential unlocked.
            </span>
          </span>
        </label>
        {scope.may_act ? (
          <Picker
            name="Actions"
            hint="Compiled into the enclave, so this list is what that build knows. attest.digest is the one that is wired."
            options={["attest.digest", "google.gmail.send", "github.issue.comment"]}
            selected={scope.act_actions}
            onToggle={(v) => patch({ act_actions: toggle(scope.act_actions, v) })}
          />
        ) : null}
      </div>

      {warnings.map((w) => (
        <p key={w.text} className={w.fatal ? "bad" : "warn"}>
          {w.text}
        </p>
      ))}

      {error ? <p className="bad">{error}</p> : null}

      <div className="row" style={{ marginTop: 12 }}>
        <button
          className="go"
          onClick={issue}
          disabled={busy || !keyId || fatal.length > 0 || !scope.agent_id.trim()}
        >
          Sign the grant
        </button>
        {fatal.length > 0 ? (
          <span className="sub">Fix what is in red first &mdash; it would grant nothing.</span>
        ) : null}
      </div>

      {result ? <Issued token={result.token} verified={result.verified} /> : null}
    </section>
  );
}

function Picker(props: {
  name: string;
  hint: string;
  options: readonly string[];
  selected: readonly string[];
  onToggle: (value: string) => void;
}) {
  return (
    <div className="field">
      <span className="name" style={{ display: "block", fontWeight: 550, marginBottom: 4 }}>
        {props.name}
      </span>
      <div className="chips">
        {props.options.map((option) => (
          <label key={option} className={props.selected.includes(option) ? "on" : ""}>
            <input
              type="checkbox"
              checked={props.selected.includes(option)}
              onChange={() => props.onToggle(option)}
            />
            {option}
          </label>
        ))}
      </div>
      <span className="hint" style={{ display: "block", color: "var(--dim)", marginTop: 4 }}>
        {props.hint}
      </span>
    </div>
  );
}

function Issued({ token, verified }: { token: string; verified: Scope }) {
  return (
    <div className="ok" style={{ marginTop: 14 }}>
      <strong>Signed, and checked by the gateway.</strong>
      <p style={{ margin: "6px 0" }}>
        What follows is the scope <em>the gateway read back</em> after verifying
        the signature and applying its own expiry clamp &mdash; not what this page
        composed. The two agreeing is the thing worth seeing.
      </p>
      <dl className="kv">
        <dt>permits</dt>
        <dd>
          read
          {verified.may_write ? " · write" : ""}
          {verified.may_unseal ? " · unseal" : ""}
          {verified.may_act ? " · act" : ""}
        </dd>
        <dt>sources</dt>
        <dd className="mono">{verified.sources.join(", ") || "(none)"}</dd>
        <dt>kinds</dt>
        <dd className="mono">{verified.memory_kinds.join(", ") || "(none)"}</dd>
        <dt>expires</dt>
        <dd>
          {verified.expires_at_ms
            ? new Date(verified.expires_at_ms).toLocaleString()
            : "(unbounded)"}
        </dd>
      </dl>
      <p style={{ margin: "10px 0 4px" }}>
        Give this to the agent. It is the whole capability, so treat it like a
        password &mdash; and this is the only time it is shown.
      </p>
      <textarea readOnly value={token} onFocus={(e) => e.currentTarget.select()} />
    </div>
  );
}

interface Warning {
  text: string;
  fatal: boolean;
}

/**
 * The warnings, as one function so they can be tested without a browser.
 *
 * `fatal` means "this grant would read nothing", which is worth blocking rather
 * than warning about: a grant that verifies and returns nothing is the hardest
 * kind of mistake to diagnose from the agent's side, because it looks exactly
 * like an empty memory.
 */
export function collectWarnings(scope: Scope): Warning[] {
  const warnings: Warning[] = [];

  if (scope.sources.length === 0) {
    warnings.push({
      text:
        "No sources selected, so this grant reads nothing. An empty list is " +
        "deny-everything, not allow-everything.",
      fatal: true,
    });
  }
  if (scope.entity_kinds.length === 0) {
    warnings.push({
      text: "No entity kinds selected, so this grant reads nothing.",
      fatal: true,
    });
  }
  if (scope.memory_kinds.length === 0) {
    warnings.push({
      text:
        "No memory kinds selected. Claims that carry a kind will all be hidden; " +
        "only unkinded ones come back, which in an established graph is most of " +
        "the older records and none of the newer ones.",
      fatal: false,
    });
  }
  if (
    scope.memory_kinds.includes("tacit") &&
    (scope.max_sensitivity === "public" || scope.max_sensitivity === "personal")
  ) {
    warnings.push({
      text:
        "Tacit memory is floored at confidential — an unwritten heuristic about " +
        `you is an inference about you — so at "${scope.max_sensitivity}" this ` +
        "grant reads none of it. Raise the sensitivity or drop the kind.",
      fatal: false,
    });
  }
  if (scope.may_write && scope.write_sources.length === 0) {
    warnings.push({
      text:
        "Writing is on but no write source is selected, so every write will be " +
        "refused. Agents write as `agent`.",
      fatal: true,
    });
  }
  if (scope.may_act && scope.act_actions.length === 0) {
    warnings.push({
      text: "Acting is on but no action is named, so every action will be refused.",
      fatal: true,
    });
  }
  if (scope.may_supersede_owner) {
    warnings.push({
      text:
        "This agent may overwrite decisions you recorded yourself. Its reason " +
        "is kept and shown in the history, but yours stops being the current one.",
      fatal: false,
    });
  }
  if (scope.max_sensitivity === "restricted") {
    warnings.push({
      text: "Restricted is everything you have. There is no level above it.",
      fatal: false,
    });
  }
  return warnings;
}
