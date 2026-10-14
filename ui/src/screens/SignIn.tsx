/**
 * Getting an owner session, which everything owner-facing needs.
 *
 * Two routes in, and the mock one is not a shortcut: in `ORCHESTRATOR_MODE=mock`
 * the enclave derives an identity from a `mock_google_<subject>` prefix, and
 * that is the only way to use this dashboard without a real OAuth app. It is
 * labelled as development rather than hidden, because a sign-in button that
 * silently did something different in mock mode would be worse.
 */

import { useState } from "react";

import type { Owner } from "../App";
import { ApiError, authorizeUrl, openSession } from "../lib/api";

export function SignIn({ onSignedIn }: { onSignedIn: (owner: Owner) => void }) {
  const [mockSubject, setMockSubject] = useState("alice");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function withGoogle() {
    setBusy(true);
    setError(null);
    try {
      const { authorize_url } = await authorizeUrl("google");
      // The gateway returns the URL as JSON rather than a 302 precisely so a UI
      // can navigate to it unchanged.
      window.location.assign(authorize_url);
    } catch (e) {
      setError(describe(e));
      setBusy(false);
    }
  }

  async function withMock() {
    setBusy(true);
    setError(null);
    try {
      const result = await openSession(`mock_google_${mockSubject}`);
      onSignedIn({
        ownerId: result.identity.owner_id,
        sessionToken: result.session_token,
      });
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>Sign in</h2>
      <p className="why">
        An owner session is what authorises registering a device key, revoking
        one, and reading what your agents have done. It is held in this tab only
        and expires in an hour &mdash; it can register a signing key, so it is
        not worth persisting.
      </p>

      {error ? <p className="bad">{error}</p> : null}

      <div className="row" style={{ marginBottom: 18 }}>
        <button className="go" onClick={withGoogle} disabled={busy}>
          Sign in with Google
        </button>
      </div>

      <h2 style={{ fontSize: 13 }}>Development</h2>
      <p className="why">
        With the stack in mock mode the enclave accepts a{" "}
        <code>mock_google_&lt;subject&gt;</code> token and attests the identity it
        implies. No real OAuth app needed, and no real mailbox reached.
      </p>
      <div className="row">
        <input
          type="text"
          value={mockSubject}
          onChange={(e) => setMockSubject(e.target.value)}
          style={{ maxWidth: 200 }}
          aria-label="mock subject"
        />
        <button className="quiet" onClick={withMock} disabled={busy || !mockSubject}>
          Sign in as mock_google_{mockSubject}
        </button>
      </div>
    </section>
  );
}

export function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return `${error.detail} (the session may have expired)`;
    return `${error.detail} (HTTP ${error.status})`;
  }
  if (error instanceof Error) {
    // A bare "Failed to fetch" is the most common thing to see here and the
    // least informative, so it gets named.
    if (error.message === "Failed to fetch") {
      return "could not reach the service; is the stack running? (scripts/run_local.sh)";
    }
    return error.message;
  }
  return String(error);
}
