---
title: "ADR 0023: The owner's key lives in the browser"
description: "A dashboard where the server signs grants would collapse the whole confidentiality story to trust-the-host."
---

**Status:** accepted
**Date:** 2026-10-14

## Context

Everything the harness does was reachable only over MCP, HTTP and two CLI
binaries, which left the owner's own box the one that was still entirely
technical. Issuing a grant was five steps: `kleos-device keygen`, `pubkey`, a
curl with a bearer token, a hand-written `scope.json` over fifteen fields, then
`kleos-device sign`. An owner could not see which agents held access, what each
could read, what they had read, or what they had changed, without curl.

So the dashboard is not a convenience feature. A capability system whose
capabilities can only be issued by someone who can write canonical JSON is a
capability system with one user.

The constraint arrives immediately. [ADR 0011](/adr/0011-the-owner-signs-grants-not-the-gateway)
says a grant is signed by a key the **owner** holds and that the gateway cannot
mint one, which is the reason an operator who runs the host still cannot grant
themselves read access to someone's memory. A dashboard where the owner clicks
"give ChatGPT read access" and the *server* signs destroys that property
completely: every confidentiality claim in the project would reduce to "trust the
host".

## Decision

**The owner's signing key lives in their browser, as a non-extractable WebCrypto
key, and the dashboard composes a scope and asks that key to sign it.** The
server is never asked to sign anything.

That makes this a local-crypto application that happens to have forms, rather
than an admin panel, and the decisions below follow from it.

### Non-extractable, and what that actually buys

Keys are generated with `extractable: false` and stored as `CryptoKey` objects in
IndexedDB, which structured-clones them with the flag intact. The page can sign
with a key it can never read.

This is not a hardware guarantee and should not be described as one. Anyone with
the page's origin can obtain signatures for as long as they are there. What it
removes is the *exfiltration* step: there is no serialised private key to steal,
log, or sync to a backup.

### No JavaScript crypto fallback

`crypto.subtle` Ed25519 is Chrome/Edge 137+, Safari 17+, Firefox 130+. Elsewhere
the dashboard refuses and points at `kleos-device`.

A `@noble/ed25519` fallback would work everywhere, and would put the private key
in ordinary readable JavaScript memory — weakening precisely the property this
screen exists to uphold, silently, on the browsers least likely to be current. A
UI that quietly downgrades the owner's key custody is worse than one that says it
cannot help.

### Deriving the key id locally is the security feature

`key_id` is `hex(blake2b256("kleos/device-key/v1" || pubkey)[0..16])`, and
WebCrypto has no BLAKE2b, so this costs a dependency (`blakejs`).

`POST /auth/device/register` returns the key id, so the UI could simply believe
it. It must not. Both `gateway/src/routes/memory.rs` and
`store/device_keys/mod.rs` name the same residual weakness: registration is
authorised by an owner session, owner sessions are signed by the host, so **a
host that forges one can register a key of its own.** Nothing prevents that. What
detects it is a client that derives the id from the public key it holds and
compares — against the register response, and against every row from
`GET /auth/device/keys`. Revoked keys are listed too, deliberately, so a
substitution cannot hide behind a filter.

That check is the main thing the dashboard adds over the CLI, and it is why the
hash is computed rather than trusted.

### One key per agent, because revocation is per key

There is no per-grant revocation anywhere in Kleos. `POST /auth/device/revoke`
revokes a *key* and with it every grant that key ever signed; `grants.rs` calls it
"the only revocation lever that exists today".

Rather than build a revocation list, the dashboard adopts the convention that
makes the existing lever sufficient: **one key per agent.** "Give ChatGPT access"
mints a key labelled for ChatGPT; "revoke ChatGPT" revokes that key. Nothing
limits how many keys an owner registers, so this costs a registration call and is
strictly better than what the CLI encourages, where one key signs everything and
revocation is all-or-nothing.

It is **UI policy and not an invariant.** Another client can sign many agents'
grants with one key and the gateway will accept it. Said here rather than implied
by a screen.

The same shape applies to TTLs: nothing clamps a grant's lifetime server-side, so
the dashboard offers a bounded set and declines to compose anything longer. Also
policy, also not enforcement.

### Login lands on the orchestrator's origin, not the gateway's

The dashboard needs a real sign-in, and the obvious design was unsafe. Carrying a
`redirect_to` inside the signed OAuth state and 302-ing back with the session in
the URL fragment does not work: `GET /auth/authorize` is unauthenticated, so an
attacker mints their own validly-signed state pointing anywhere. The signature
buys nothing against the party who asked for it, and single-use `state_id` stops
replay rather than first use. Delivered in a fragment, that is owner-account
takeover, because the session token is the credential that registers a signing
key.

What works instead needs no Rust change at all, because **the redirect URI is
configuration, not a route**. Point `GOOGLE_REDIRECT_URI` at
`/ui/oauth/land` — the orchestrator's origin, where the dashboard is served — and
the page reads `code` and `state` off its own query string, then fetches
`/auth/callback` on the gateway cross-origin. The gateway already serves
`Access-Control-Allow-Origin: *`, so the JSON response, session token included, is
readable by script. The exchange still succeeds because `callback` forwards the
*configured* `redirect_uri`, which is what the provider saw, and nothing compares
it against the request's `Host`.

The landing page calls `history.replaceState` before anything else, since the code
and state are single-use credentials that would otherwise reach the history stack
and the `Referer` of every subresource. The PKCE verifier never leaves the
gateway, so a leaked code is not independently redeemable.

The session is held in memory and **never** in `localStorage`: it can register a
signing key, so a 1-hour expiry and signing in again is the cheaper trade.

### The owner's own "consolidate" is grant-authorised

The Memory screen turns a session's stored blocks into searchable claims. The
owner presses the button, so an owner-session route and an owner-authority path
inside `decide.py` looked natural. Rejected.

Instead the dashboard **signs a short-lived grant with the owner's own key** and
calls a grant-authenticated `POST /memory/consolidate`, leaving
`consolidate_session` unchanged. Three reasons:

- One gate decides every claim-producing write. A second entry point would be a
  second place where the gate, the source and the precedence class are chosen,
  which is exactly what `decide.py`'s module docstring argues against.
- Every such write keeps a `grant_fp`. Design B would have created the first
  remote-triggered write with no grant fingerprint and no actor device — a new row
  shape in the mutation log whose authorisation left no trace in the log at all.
- It does not regress onto the host-signed session. Under B, a host that forged a
  session could trigger a write directly; under this, it would also have to
  register a key, which is a stored, timestamped row the owner can see.

The honest costs. The grant needs `may_write`, `write_sources: ["agent"]`,
non-empty `entity_kinds`, every memory kind, `max_sensitivity: confidential`
(because tacit floors there) and `may_unseal` (the blocks are sealed) — so it is
powerful, and is minted per click with a 45-second expiry and never cached.
Between clicks no token exists that could write to this owner's memory.

Two things found by driving the HTTP route against a real session rather than a
stubbed `consolidate_session`:

**A refusal arrives in `errors`, not in `refused`.** Consolidation declines *per
conclusion* so that a grant covering episodes but not procedures keeps the
episodes — so nothing escapes to the handler and `refused` stays false even when
every conclusion was turned away. A client reading `refused` alone reports a
wholly refused run as a success, which is what the first version of the screen
did.

**A run that refused everything is no longer stamped as distilled.** The
timestamp was unconditional, on the argument that consolidation had *run*. That
is wrong in the direction that matters: the owner would see a distilled session
holding nothing, indistinguishable from one that genuinely concluded nothing, and
would never retry under a grant that permits the write. It is now stamped when
something was kept or when nothing was refused — a partial run counts, a wholly
refused one does not.

And the attribution is the dashboard's, not the originating agent's. `Authority`
comes out `Delegate` or `Reference` and **never `Owner`**, which is correct: the
conclusions are a consolidator's summary of an agent's notes, not the person's own
typing. The route back to the agent whose session it was is the session id and the
`CONSOLIDATED_FROM` edge. The dashboard's key is labelled `owner-dashboard` so the
audit trail reads as what it is.

## Consequences

- An owner can issue, inspect and revoke access from a screen, and see what every
  grant read, changed and did.
- **The three semantics that produce a silently empty grant are now visible**, and
  two of them block issuing: `sources` and `entity_kinds` are `all` not `any`; an
  empty list grants nothing; `tacit` below `confidential` reads nothing. All three
  are invisible in a hand-written `scope.json`.
- The wire format now has two implementations, so it is pinned the way the
  Python/Rust schema mirror is — by making the other side check.
  `ui/scripts/sign-fixture.mjs` is an independent reading of the format,
  `shared/tests/browser_grant_parity.rs` verifies its token with the real
  `verify_grant`, and `grants.test.ts` asserts the module the browser *actually
  runs* produces that same token byte for byte. The third is the one that matters:
  without it the Rust test only proves the fixture script is right, and the
  fixture script is not what runs in anyone's browser.
- Built assets are committed, so running Kleos still needs Python and nothing
  else. Node is a development dependency of `ui/`.
- **The orchestrator still has no CORS middleware, and that is the design.** The
  dashboard is same-origin with the routes it calls, so none is needed; an
  `allow_origins` entry would be the single change most likely to make the
  owner-authenticated routes reachable from somewhere else. `npm run dev` proxies
  instead of asking the service to relax.
- Losing the browser is recoverable, which is what makes this choice safe:
  registering and revoking are authorised by the owner *session*, not by a key. The
  cost of clearing site data is the ability to sign *new* grants with the stranded
  keys, and the fix is to register a fresh one and revoke them.
- **The session is still a host-signed JWT.** Everything owner-facing rests on it,
  so a host that forges one can register a key. The dashboard makes that visible
  and cannot prevent it. The gateway change that would help — the callback putting
  the session in a one-time slot keyed by a nonce and 302-ing to an exact-origin
  allowlisted UI, so the credential never appears in a URL — is recorded here and
  not built.
- Still no per-grant revocation, still no server-side TTL ceiling. Both are
  conventions this client follows and another need not.
