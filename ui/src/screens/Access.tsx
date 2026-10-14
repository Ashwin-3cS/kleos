/**
 * Access policy: the agent keys this owner holds, and the grants they sign.
 *
 * The screen the whole dashboard exists for, and the one with a real constraint
 * behind it. A grant is signed by a key the **owner** holds and the gateway
 * cannot mint one (ADR 0011). So this page composes a scope, asks a key in this
 * browser to sign it, and hands the token over. The server is never asked to
 * sign, which is why an operator running the host still cannot grant themselves
 * read access to someone's memory.
 */

import { useCallback, useEffect, useState } from "react";

import type { Owner } from "../App";
import { describe } from "./SignIn";
import {
  type DeviceKeyView,
  introspectScope,
  listDeviceKeys,
  registerDeviceKey,
  revokeDeviceKey,
} from "../lib/api";
import {
  b64Encode,
  emptyScope,
  type EntityKind,
  type MemoryKind,
  type Scope,
  type Sensitivity,
  signGrant,
} from "../lib/grants";
import {
  createKey,
  forgetKey,
  isSupported,
  listKeys,
  type StoredKey,
} from "../lib/keys";
import { ScopeComposer } from "./ScopeComposer";

/** Issued grants, remembered locally. See the caveat rendered beside them. */
const ISSUED_STORAGE = "kleos.issued-grants.v1";

interface IssuedGrant {
  keyId: string;
  label: string;
  agentId: string;
  issuedAtMs: number;
  expiresAtMs: number;
  token: string;
  scope: Scope;
}

function loadIssued(): IssuedGrant[] {
  try {
    return JSON.parse(localStorage.getItem(ISSUED_STORAGE) ?? "[]") as IssuedGrant[];
  } catch {
    // A per-viewer convenience that can come back empty in a private window or
    // with site data blocked, so every read tolerates it and the screen says
    // what the authoritative source is instead.
    return [];
  }
}

function saveIssued(grants: IssuedGrant[]): void {
  try {
    localStorage.setItem(ISSUED_STORAGE, JSON.stringify(grants.slice(0, 50)));
  } catch {
    /* ignore: the list is a convenience, not the record */
  }
}

export function Access({ owner, onExpired }: { owner: Owner; onExpired: () => void }) {
  const [supported, setSupported] = useState<boolean | null>(null);
  const [local, setLocal] = useState<StoredKey[]>([]);
  const [registered, setRegistered] = useState<DeviceKeyView[]>([]);
  const [issued, setIssued] = useState<IssuedGrant[]>(loadIssued);
  const [error, setError] = useState<string | null>(null);
  const [newLabel, setNewLabel] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void isSupported().then(setSupported);
  }, []);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [mine, theirs] = await Promise.all([listKeys(), listDeviceKeys(owner.sessionToken)]);
      setLocal(mine);
      setRegistered(theirs);
    } catch (e) {
      setError(describe(e));
      if ((e as { status?: number }).status === 401) onExpired();
    }
  }, [owner.sessionToken, onExpired]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function addKey() {
    setBusy(true);
    setError(null);
    try {
      const key = await createKey(newLabel.trim());
      // Registration is a separate step that fails for unrelated reasons, so
      // the key exists locally first and a failed registration is retryable.
      const view = await registerDeviceKey(
        owner.sessionToken,
        b64Encode(key.publicKey),
        key.label,
      );
      if (view.key_id !== key.keyId) {
        // The whole reason this UI derives the key id itself. The gateway
        // disagreeing about the id of a key we just generated means the key it
        // stored is not the key we hold.
        setError(
          `The gateway registered key ${view.key_id} but this browser generated ` +
            `${key.keyId}. Those must match. Do not use this key: revoke it and ` +
            `tell someone, because it means the key the server holds is not the ` +
            `one this browser does.`,
        );
      }
      setNewLabel("");
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(keyId: string) {
    setBusy(true);
    setError(null);
    try {
      await revokeDeviceKey(owner.sessionToken, keyId);
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  }

  async function issue(scope: Scope, keyId: string, ttlSecs: number) {
    const key = local.find((k) => k.keyId === keyId);
    if (!key) throw new Error("that key is not in this browser");
    const token = await signGrant({
      scope,
      keyId: key.keyId,
      privateKey: key.privateKey,
      ttlSecs,
    });

    // Previewed through the gateway rather than rendered from the scope we just
    // composed: this checks the signature, the registration, the revocation and
    // the expiry, and applies the TTL clamp. A locally rendered preview would be
    // the UI agreeing with itself.
    const verified = await introspectScope(token);

    const entry: IssuedGrant = {
      keyId: key.keyId,
      label: key.label,
      agentId: scope.agent_id,
      issuedAtMs: Date.now(),
      expiresAtMs: verified.scope.expires_at_ms ?? Date.now() + ttlSecs * 1000,
      token,
      scope: verified.scope,
    };
    const next = [entry, ...issued];
    setIssued(next);
    saveIssued(next);
    return { token, verified };
  }

  if (supported === false) {
    return (
      <section className="panel">
        <h2>This browser cannot hold a device key</h2>
        <p className="why">
          Kleos grants are signed with Ed25519, and this browser has no Ed25519 in
          WebCrypto. Chrome&nbsp;137+, Safari&nbsp;17+ and Firefox&nbsp;130+ do.
        </p>
        <p className="why">
          There is deliberately no JavaScript fallback. One would work everywhere
          and would put your private key in ordinary readable memory, weakening
          the one property this screen exists to uphold &mdash; quietly, on the
          browsers least likely to be current. Until then,{" "}
          <code>kleos-device</code> on the command line does the same job.
        </p>
      </section>
    );
  }

  return (
    <>
      {error ? <p className="bad">{error}</p> : null}

      <KeyList
        local={local}
        registered={registered}
        newLabel={newLabel}
        setNewLabel={setNewLabel}
        onAdd={addKey}
        onRevoke={revoke}
        onForget={async (keyId) => {
          await forgetKey(keyId);
          await refresh();
        }}
        busy={busy || supported === null}
      />

      <ScopeComposer
        ownerId={owner.ownerId}
        keys={local.filter((k) => {
          const row = registered.find((r) => r.key_id === k.keyId);
          return row !== undefined && row.revoked_at_ms === null;
        })}
        baseScope={emptyScope(owner.ownerId)}
        onIssue={issue}
      />

      <IssuedList grants={issued} />
    </>
  );
}

function KeyList(props: {
  local: StoredKey[];
  registered: DeviceKeyView[];
  newLabel: string;
  setNewLabel: (value: string) => void;
  onAdd: () => void;
  onRevoke: (keyId: string) => void;
  onForget: (keyId: string) => void;
  busy: boolean;
}) {
  const { local, registered } = props;
  const localIds = new Set(local.map((k) => k.keyId));
  const unknown = registered.filter((r) => !localIds.has(r.key_id));

  return (
    <section className="panel">
      <h2>Agent keys</h2>
      <p className="why">
        One key per agent, because there is no per-grant revocation anywhere in
        Kleos: revoking a key invalidates every grant it ever signed, immediately
        and server-side. A key per agent is what makes &ldquo;revoke this
        agent&rdquo; mean something. Private keys stay in this browser and cannot
        be read by this page &mdash; only signed with.
      </p>

      <table>
        <thead>
          <tr>
            <th>Agent</th>
            <th className="mono">Key id</th>
            <th>State</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {local.map((key) => {
            const row = registered.find((r) => r.key_id === key.keyId);
            return (
              <tr key={key.keyId}>
                <td>{key.label || <span className="sub">(unlabelled)</span>}</td>
                <td className="mono">{key.keyId}</td>
                <td>
                  {row === undefined ? (
                    <span className="tag warn" title="generated here, not registered">
                      not registered
                    </span>
                  ) : row.revoked_at_ms !== null ? (
                    <span className="tag bad">revoked</span>
                  ) : (
                    <span className="tag ok" title="derived locally and matches the gateway">
                      verified
                    </span>
                  )}
                </td>
                <td>
                  <div className="row">
                    {row !== undefined && row.revoked_at_ms === null ? (
                      <button
                        className="danger"
                        disabled={props.busy}
                        onClick={() => props.onRevoke(key.keyId)}
                      >
                        Revoke
                      </button>
                    ) : null}
                    <button
                      className="quiet"
                      disabled={props.busy}
                      onClick={() => props.onForget(key.keyId)}
                      title="Removes it from this browser only. Not revocation."
                    >
                      Forget here
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
          {local.length === 0 ? (
            <tr>
              <td colSpan={4} className="sub">
                No keys in this browser yet.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>

      {unknown.length > 0 ? (
        <div className="warn">
          <strong>
            {unknown.length} registered {unknown.length === 1 ? "key is" : "keys are"} not
            in this browser.
          </strong>{" "}
          Two innocent explanations and one that is not. Innocent: you registered
          them from another browser or with <code>kleos-device</code>; or the
          gateway is running without <code>SEALED_TOKEN_STORE_URL</code>, whose
          in-memory key store is rebuilt on restart. Not innocent: registration is
          authorised by a session the host signs, so a host that forged one could
          register a key of its own &mdash; which would look exactly like this.
          Nothing prevents that; noticing it is the defence.
          <ul className="mono" style={{ margin: "8px 0 0" }}>
            {unknown.map((r) => (
              <li key={r.key_id}>
                {r.key_id} &mdash; {r.label || "(no label)"}{" "}
                {r.revoked_at_ms !== null ? "(revoked)" : ""}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="row" style={{ marginTop: 12 }}>
        <input
          type="text"
          placeholder="what this agent is called, e.g. chatgpt"
          value={props.newLabel}
          onChange={(e) => props.setNewLabel(e.target.value)}
          style={{ maxWidth: 320 }}
          aria-label="agent label"
        />
        <button className="go" onClick={props.onAdd} disabled={props.busy || !props.newLabel.trim()}>
          Generate and register a key
        </button>
      </div>
      <p className="note">
        Losing this browser is recoverable: registering and revoking are
        authorised by your owner session, not by a key. Clearing site data costs
        the ability to sign <em>new</em> grants with these keys &mdash; you
        register a fresh one and revoke the stranded ones.
      </p>
    </section>
  );
}

function IssuedList({ grants }: { grants: IssuedGrant[] }) {
  const now = Date.now();
  return (
    <section className="panel">
      <h2>Grants issued from this browser</h2>
      <p className="why">
        <strong>A local note, not the record.</strong> Kleos stores no grant
        table &mdash; a grant is a signed token, and the server knows only the
        keys that can sign and what each grant has read. So a grant issued from
        another browser will not be here, and nothing here proves a grant is
        still live. The authoritative answers are the key list above and the
        Activity screen.
      </p>
      <table>
        <thead>
          <tr>
            <th>Agent</th>
            <th>Signed by</th>
            <th>Permits</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          {grants.map((g) => (
            <tr key={g.token.slice(-24)}>
              <td>{g.agentId}</td>
              <td className="mono">{g.keyId.slice(0, 12)}</td>
              <td>
                <Capabilities scope={g.scope} />
              </td>
              <td>
                {g.expiresAtMs < now ? (
                  <span className="tag">expired</span>
                ) : (
                  new Date(g.expiresAtMs).toLocaleString()
                )}
              </td>
            </tr>
          ))}
          {grants.length === 0 ? (
            <tr>
              <td colSpan={4} className="sub">
                Nothing issued from this browser yet.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </section>
  );
}

export function Capabilities({ scope }: { scope: Scope }) {
  const on: string[] = ["read"];
  if (scope.may_write) on.push(scope.may_supersede_owner ? "write (may supersede)" : "write");
  if (scope.may_unseal) on.push("unseal");
  if (scope.may_act) on.push(`act (${scope.act_actions.join(", ") || "nothing"})`);
  return (
    <span className="stack">
      <span>{on.join(" · ")}</span>
      <span className="sub mono">
        {scope.sources.length} source{scope.sources.length === 1 ? "" : "s"} ·{" "}
        {scope.max_sensitivity} ·{" "}
        {scope.memory_kinds.length ? scope.memory_kinds.join("/") : "no kinds"}
      </span>
    </span>
  );
}

export type { IssuedGrant };
export type { Sensitivity, EntityKind, MemoryKind };
