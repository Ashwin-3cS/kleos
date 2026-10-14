/**
 * What the agents have been working on, and the one transition that is manual.
 *
 * The thing people expect here is a Sync button, and it is worth saying why
 * there isn't one: there is nothing to pull. Kleos has no per-device memory
 * store. An agent that decides something writes it straight into the one graph
 * at the moment it decides, under its grant, so a second device is already
 * current before it asks.
 *
 * What genuinely is not automatic is narrower and more interesting. A session's
 * blocks -- the agent's working notes, file contents, tool output -- are
 * **stored** and deliberately not **searchable**: sealed as blobs, with no
 * embedding and no `:Memory` label, so no retrieval can reach them.
 * Consolidation is the only path across, and it stays manual because an
 * automatic one would be the system inventing claims about a person out of
 * scratch work nobody asked it to read.
 *
 * So this screen renders the three states and gives the owner that one button.
 */

import { useCallback, useEffect, useState } from "react";

import type { Owner } from "../App";
import { consolidate, listSessions, type SessionEntry } from "../lib/api";
import { emptyScope, signGrant } from "../lib/grants";
import { listKeys, type StoredKey } from "../lib/keys";
import { describe } from "./SignIn";

/**
 * How long the consolidation grant lives. Seconds, because of what it has to
 * carry: writing *and* unsealing, across every memory kind, at the top
 * sensitivity. That is the price of using the same gate as every agent instead
 * of adding an owner-authority back door, and the mitigation is that it exists
 * for one request.
 */
const CONSOLIDATE_TTL_SECS = 45;

interface Outcome {
  sessionId: string;
  text: string;
  kind: "ok" | "warn" | "bad";
}

export function Memory({ owner, onExpired }: { owner: Owner; onExpired: () => void }) {
  const [sessions, setSessions] = useState<SessionEntry[]>([]);
  const [undistilled, setUndistilled] = useState(0);
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [keyId, setKeyId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [body, mine] = await Promise.all([listSessions(owner.sessionToken), listKeys()]);
      setSessions(body.entries);
      setUndistilled(body.undistilled);
      setKeys(mine);
      if (mine[0] && !keyId) setKeyId(mine[0].keyId);
    } catch (e) {
      setError(describe(e));
      if ((e as { status?: number }).status === 401) onExpired();
    }
  }, [owner.sessionToken, onExpired, keyId]);

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [owner.sessionToken]);

  async function distil(session: SessionEntry) {
    const key = keys.find((k) => k.keyId === keyId);
    if (!key) {
      setError("No key in this browser to authorise this with. Register one on Access.");
      return;
    }
    setBusy(session.id);
    setError(null);
    setOutcome(null);
    try {
      // Signed per click, and never cached. The dashboard holds no standing
      // write capability: between clicks there is no token in existence that
      // could be used to write to this owner's memory.
      const token = await signGrant({
        scope: {
          ...emptyScope(owner.ownerId, "owner-dashboard"),
          sources: ["agent"],
          entity_kinds: ["person", "project", "artifact", "organization", "topic"],
          // Confidential rather than personal because tacit conclusions floor
          // there; a narrower ceiling would refuse them one at a time and look
          // like a partial success.
          max_sensitivity: "confidential",
          may_write: true,
          // The source is hardcoded `agent` on the write path, deliberately: an
          // agent that could name its own source could write a claim that
          // claims to be a typed note from the person.
          write_sources: ["agent"],
          memory_kinds: ["episodic", "procedural", "tacit"],
          // The blocks are sealed. Reading them back goes through the enclave,
          // and the gateway refuses that without this flag.
          may_unseal: true,
        },
        keyId: key.keyId,
        privateKey: key.privateKey,
        ttlSecs: CONSOLIDATE_TTL_SECS,
      });

      const result = await consolidate(token, session.id);
      const kept = result.claims?.length ?? 0;
      if (result.refused) {
        // A backstop. Consolidation declines per conclusion, so a refusal
        // normally arrives in `errors` below and never reaches here.
        setOutcome({
          sessionId: session.id,
          text: `Refused outright: ${result.reason}. The key signing this must be registered and not revoked.`,
          kind: "bad",
        });
      } else if (result.errors?.length) {
        // **Where a refusal actually lands**, and never folded away. Kept none
        // of one is a failed run that would otherwise read as a clean one.
        setOutcome({
          sessionId: session.id,
          text:
            `Kept ${kept} of ${kept + result.errors.length}. ` +
            (kept === 0
              ? `Nothing was written — ${result.errors.join("; ")}. The grant this ` +
                `was signed with does not cover what the session concluded.`
              : `Refused: ${result.errors.join("; ")}`),
          kind: kept === 0 ? "bad" : "warn",
        });
      } else if (kept === 0) {
        setOutcome({
          sessionId: session.id,
          text: `Read ${result.blocks ?? 0} block(s) and concluded nothing. That is the usual outcome — working notes are mostly not decisions.`,
          kind: "ok",
        });
      } else {
        setOutcome({
          sessionId: session.id,
          text: `Kept ${kept} conclusion(s): ${(result.conclusions ?? [])
            .map((c) => `${c.kind} — ${c.statement}`)
            .join(" | ")}`,
          kind: "ok",
        });
      }
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(null);
    }
  }

  const byDevice = new Map<string, SessionEntry[]>();
  for (const session of sessions) {
    const list = byDevice.get(session.device_id) ?? [];
    list.push(session);
    byDevice.set(session.device_id, list);
  }

  return (
    <>
      <section className="panel">
        <h2>Already shared, by construction</h2>
        <p className="why">
          There is no per-device memory to sync. An agent that decides something
          writes it into the one graph as it decides, so every other agent is
          current before it asks &mdash; and what it is told includes which
          device decided and why.
        </p>
        <p className="why">
          What <em>is</em> manual is narrower. An agent&rsquo;s working notes are
          stored and deliberately not searchable; turning them into memory other
          agents can retrieve is the button below. It stays manual because an
          automatic one would mean inventing claims about you out of scratch work
          nobody asked it to read.
        </p>
        <div className="row">
          <a href="/explorer" target="_blank" rel="noreferrer">
            Open the graph explorer
          </a>
          <span className="sub">
            &mdash; shows what one grant can and cannot see, including what it withheld
          </span>
        </div>
      </section>

      {error ? <p className="bad">{error}</p> : null}

      <section className="panel">
        <h2>Working sessions</h2>
        <p className="why">
          {undistilled === 0
            ? "Nothing is waiting to be distilled."
            : `${undistilled} session${undistilled === 1 ? "" : "s"} with notes that have never been distilled.`}{" "}
          A session that has been distilled and concluded nothing is the common
          case, and reads as done rather than pending.
        </p>

        {keys.length > 1 ? (
          <label className="field" style={{ maxWidth: 360 }}>
            <span className="name">Authorise distilling with</span>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
              {keys.map((k) => (
                <option key={k.keyId} value={k.keyId}>
                  {k.label || "(unlabelled)"} &mdash; {k.keyId.slice(0, 12)}
                </option>
              ))}
            </select>
            <span className="hint">
              A grant is signed per click and expires in {CONSOLIDATE_TTL_SECS}s. It
              carries write and unseal, so it exists for one request and is never
              kept.
            </span>
          </label>
        ) : null}

        {[...byDevice.entries()].map(([deviceId, entries]) => (
          <div key={deviceId} style={{ marginBottom: 18 }}>
            <h2 className="mono" style={{ fontSize: 13 }}>
              {deviceId}{" "}
              <span className="tag ok" title="verified by the gateway at grant time">
                device-authenticated
              </span>{" "}
              <span className="sub" style={{ fontWeight: 400 }}>
                labelled &lsquo;{entries[0]?.agent_id}&rsquo;
              </span>
            </h2>
            <table>
              <thead>
                <tr>
                  <th>Opened</th>
                  <th>Blocks</th>
                  <th>State</th>
                  <th>Produced</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {entries.map((session) => (
                  <tr key={session.id}>
                    <td>{new Date(session.opened_at_ms).toLocaleString()}</td>
                    <td>
                      {session.block_count}{" "}
                      <span className="sub">({Math.ceil(session.byte_len / 1024)}k)</span>
                    </td>
                    <td>
                      {session.consolidated_at_ms !== null ? (
                        <span className="tag ok">distilled</span>
                      ) : session.block_count === 0 ? (
                        <span className="tag">empty</span>
                      ) : (
                        <span className="tag warn">stored only</span>
                      )}
                    </td>
                    <td>
                      {session.consolidated_into.length > 0 ? (
                        `${session.consolidated_into.length} claim(s)`
                      ) : session.consolidated_at_ms !== null ? (
                        <span className="sub">nothing</span>
                      ) : (
                        <span className="sub">&mdash;</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="quiet"
                        disabled={busy !== null || session.block_count === 0 || keys.length === 0}
                        onClick={() => distil(session)}
                      >
                        {busy === session.id ? "distilling..." : "Distil into memory"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {outcome && entries.some((s) => s.id === outcome.sessionId) ? (
              <p className={outcome.kind === "ok" ? "ok" : outcome.kind}>{outcome.text}</p>
            ) : null}
          </div>
        ))}

        {sessions.length === 0 ? (
          <p className="note">
            No sessions yet. An agent opens one when it connects over MCP and
            starts appending what it is working from.
          </p>
        ) : null}
      </section>
    </>
  );
}
