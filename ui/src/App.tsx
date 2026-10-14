/**
 * The owner's dashboard.
 *
 * Three screens, and the split between them is the permission model rather than
 * a navigation convenience:
 *
 * - **Access** composes and signs grants. The only screen that touches a private
 *   key, and the only one that can hand out a capability.
 * - **Memory** shows what the agents have been working on and exposes the one
 *   transition that is not automatic: session blocks becoming searchable claims.
 * - **Activity** is the record -- what each grant read, what changed and why,
 *   and what was done in the world.
 *
 * The owner session is held in React state and **never** in `localStorage`. It
 * is the credential that registers a signing key, so persisting it would make a
 * stolen browser profile enough to add a key to the owner's account; a 1-hour
 * expiry and re-signing in is the cheaper trade. See ADR 0023.
 */

import { useCallback, useEffect, useState } from "react";

import { Access } from "./screens/Access";
import { Activity } from "./screens/Activity";
import { Memory } from "./screens/Memory";
import { completeCallback } from "./lib/api";
import { SignIn } from "./screens/SignIn";

export interface Owner {
  ownerId: string;
  sessionToken: string;
}

type Tab = "access" | "memory" | "activity";

const TABS: { id: Tab; label: string }[] = [
  { id: "access", label: "Access" },
  { id: "memory", label: "Memory" },
  { id: "activity", label: "Activity" },
];

export function App() {
  const [owner, setOwner] = useState<Owner | null>(null);
  const [tab, setTab] = useState<Tab>("access");
  const [landing, setLanding] = useState<string | null>(null);

  // The OAuth landing. `GOOGLE_REDIRECT_URI` points at /ui/oauth/land, which is
  // *this* origin, so the code and state arrive on our own query string and the
  // session can be read from the gateway's JSON response. Were the redirect to
  // land on the gateway itself, the browser would sit on a JSON page that runs no
  // script and this page would never see the token.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) return;

    // Before anything else, and before any await: the code and state are
    // single-use credentials sitting in a URL that would otherwise reach the
    // history stack and the Referer of every subresource.
    window.history.replaceState({}, "", "/ui");
    setLanding("completing sign-in...");
    completeCallback(code, state)
      .then((result) => {
        setOwner({
          ownerId: result.identity.owner_id,
          sessionToken: result.session_token,
        });
        setLanding(null);
      })
      .catch((error: Error) => {
        // The state is consumed by the attempt, so this is terminal: a retry
        // needs a fresh authorize rather than a reload.
        setLanding(`sign-in did not complete: ${error.message}. Start again below.`);
      });
  }, []);

  const signOut = useCallback(() => setOwner(null), []);

  return (
    <div className="shell">
      <header className="top">
        <h1>Kleos</h1>
        <span className="sub">memory several agents share</span>
        <span className="spacer" />
        {owner ? (
          <span className="row">
            <span className="sub mono">{owner.ownerId}</span>
            <button className="quiet" onClick={signOut}>
              Sign out
            </button>
          </span>
        ) : null}
      </header>

      {landing ? <p className="note">{landing}</p> : null}

      {owner === null ? (
        <SignIn onSignedIn={setOwner} />
      ) : (
        <>
          <nav className="tabs">
            {TABS.map(({ id, label }) => (
              <button
                key={id}
                aria-current={tab === id ? "page" : undefined}
                onClick={() => setTab(id)}
              >
                {label}
              </button>
            ))}
          </nav>
          {tab === "access" ? <Access owner={owner} onExpired={signOut} /> : null}
          {tab === "memory" ? <Memory owner={owner} onExpired={signOut} /> : null}
          {tab === "activity" ? <Activity owner={owner} onExpired={signOut} /> : null}
        </>
      )}
    </div>
  );
}
