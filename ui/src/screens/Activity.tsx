/**
 * The record: what each grant read, what changed and why, and what was done.
 *
 * The cheapest screen to build and the one that makes the other two worth
 * trusting. Issuing a capability is only meaningful if the owner can see what it
 * was used for afterwards, and all three logs are append-only and carry no
 * `:Memory` label -- the system's record of its own activity can never be
 * retrieved as memory, which is what stops an agent's reads becoming another
 * agent's briefing.
 *
 * All three are owner-authenticated and have no grant path and no MCP tool, for
 * the reason in `api.py`: a cross-agent log tells agent B what agent C has been
 * doing, which is a disclosure channel around the permission check rather than a
 * record of it.
 *
 * The three answer different questions, which is why they are not one table:
 * a read disclosed something, a mutation changed the record, and an action
 * happened **in the world** and cannot be undone by rewriting a row.
 */

import { useCallback, useEffect, useState } from "react";

import type { Owner } from "../App";
import {
  type ActionEntry,
  listActions,
  listMutations,
  type MutationEntry,
  readLog,
} from "../lib/api";
import { describe } from "./SignIn";

interface ReadGroup {
  grant_fp?: string;
  agent_id?: string;
  device_id?: string | null;
  reads?: number;
  disclosed?: number;
  last_at_ms?: number;
  subjects?: string[];
}

export function Activity({ owner, onExpired }: { owner: Owner; onExpired: () => void }) {
  const [reads, setReads] = useState<ReadGroup[]>([]);
  const [mutations, setMutations] = useState<MutationEntry[]>([]);
  const [actions, setActions] = useState<ActionEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [r, m, a] = await Promise.all([
        readLog(owner.sessionToken),
        listMutations(owner.sessionToken),
        listActions(owner.sessionToken),
      ]);
      const groups = (r as { grants?: ReadGroup[]; entries?: ReadGroup[] }).grants ??
        (r as { entries?: ReadGroup[] }).entries ?? [];
      setReads(groups);
      setMutations(m.entries);
      setActions(a.entries);
    } catch (e) {
      setError(describe(e));
      if ((e as { status?: number }).status === 401) onExpired();
    }
  }, [owner.sessionToken, onExpired]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <>
      {error ? <p className="bad">{error}</p> : null}

      <section className="panel">
        <h2>What was read</h2>
        <p className="why">
          Grouped by grant rather than by agent, because the grant is the
          capability: the same agent holding two grants is two authorisations,
          and an owner deciding whether to stop issuing one needs them apart.
        </p>
        <table>
          <thead>
            <tr>
              <th>Agent</th>
              <th className="mono">Device</th>
              <th className="mono">Grant</th>
              <th>Reads</th>
              <th>Disclosed</th>
              <th>Last</th>
            </tr>
          </thead>
          <tbody>
            {reads.map((group, i) => (
              <tr key={group.grant_fp ?? i}>
                <td>{group.agent_id ?? "—"}</td>
                <td className="mono">
                  {group.device_id ? (
                    group.device_id.slice(0, 12)
                  ) : (
                    <span className="sub">none</span>
                  )}
                </td>
                <td className="mono">{group.grant_fp?.slice(0, 12) ?? "—"}</td>
                <td>{group.reads ?? 0}</td>
                <td>{group.disclosed ?? 0}</td>
                <td>
                  {group.last_at_ms ? new Date(group.last_at_ms).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
            {reads.length === 0 ? (
              <tr>
                <td colSpan={6} className="sub">
                  Nothing has been read yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>What changed, and why</h2>
        <p className="why">
          Append-only: a superseded claim is not overwritten, so the prior value
          and the rule that decided are both still here. <code>rule</code> is what
          makes &ldquo;every change and why&rdquo; true rather than aspirational
          &mdash; it names the branch that fired, not a summary written afterwards.
        </p>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th className="mono">Object</th>
              <th>Change</th>
              <th>Rule</th>
              <th>Reason</th>
              <th className="mono">By</th>
            </tr>
          </thead>
          <tbody>
            {mutations.map((m) => (
              <tr key={m.id}>
                <td>{new Date(m.at_ms).toLocaleString()}</td>
                <td className="mono">{m.object_id.slice(0, 14)}</td>
                <td>
                  {m.field_name}: <span className="sub">{m.before ?? "—"}</span> →{" "}
                  <strong>{m.after ?? "—"}</strong>
                </td>
                <td className="mono">{m.rule ?? "—"}</td>
                <td>{m.reason ?? <span className="sub">—</span>}</td>
                <td className="mono">
                  {m.actor_device_id ? (
                    <>
                      {m.actor_device_id.slice(0, 12)}
                      <br />
                      <span className="sub">{m.actor_agent_id}</span>
                    </>
                  ) : (
                    <span className="sub" title="the owner's own ingestion, which has no device">
                      your own ingestion
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {mutations.length === 0 ? (
              <tr>
                <td colSpan={6} className="sub">
                  Nothing has changed yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>What was done</h2>
        <p className="why">
          Actions the enclave performed on your behalf. The agent submitted an
          intent and received an acknowledgement &mdash; never the credential, and
          never what the credential unlocked. The arguments are not here either:
          an action&rsquo;s arguments are the content it acted on, so what is kept
          is a digest, which makes a repeat recognisable without being readable.
        </p>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Action</th>
              <th>Outcome</th>
              <th>Summary</th>
              <th className="mono">Arguments</th>
              <th className="mono">By</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((a) => (
              <tr key={a.id}>
                <td>{new Date(a.at_ms).toLocaleString()}</td>
                <td className="mono">{a.action_id}</td>
                <td>
                  {a.ok ? (
                    <span className="tag ok">done</span>
                  ) : (
                    <span className="tag bad" title={a.error ?? ""}>
                      attempted
                    </span>
                  )}
                </td>
                <td>{a.ok ? a.summary : (a.error ?? a.summary)}</td>
                <td className="mono" title="a digest, so a repeat is recognisable">
                  {a.args_fp.slice(0, 10)}
                </td>
                <td className="mono">
                  {a.device_id?.slice(0, 12) ?? <span className="sub">—</span>}
                </td>
              </tr>
            ))}
            {actions.length === 0 ? (
              <tr>
                <td colSpan={6} className="sub">
                  Nothing has been done in the world yet. Only{" "}
                  <code>attest.digest</code> is wired in this build.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>
    </>
  );
}
