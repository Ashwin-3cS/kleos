/**
 * The browser's signing path, against the running stack.
 *
 * `grants.test.ts` proves this module produces the bytes the Rust test verifies.
 * That is the format pinned, and it is not the same as the thing working: it
 * says nothing about whether a key generated in a browser can be registered,
 * whether the gateway agrees about its id, whether a grant that key signs is
 * accepted by a service that has never seen it, or whether revoking the key
 * actually stops it.
 *
 * So this is the same code path the dashboard runs, end to end, with no browser:
 * generate, register, sign, introspect, read, revoke, fail. **Step 7 is the
 * point** -- a capability nobody can withdraw is not a capability, it is a
 * password you have given away.
 *
 * Skipped, not failed, when the stack is not up: a developer without
 * `scripts/run_local.sh` running should not see red. The format tests above have
 * no such escape and always run.
 *
 *     ./scripts/run_local.sh          # enclave + gateway
 *     cd orchestrator && .venv/bin/python -m orchestrator.api
 *     cd ui && npm test
 */

import { beforeAll, describe, expect, it } from "vitest";

import { b64Encode, emptyScope, keyIdFor, signGrant } from "./grants";

const GATEWAY = process.env.KLEOS_GATEWAY ?? "http://127.0.0.1:8080";
const ORCHESTRATOR = process.env.KLEOS_ORCHESTRATOR ?? "http://127.0.0.1:8090";

let up = false;

beforeAll(async () => {
  try {
    const [gateway, orchestrator] = await Promise.all([
      fetch(`${GATEWAY}/health`, { signal: AbortSignal.timeout(2000) }),
      fetch(`${ORCHESTRATOR}/health`, { signal: AbortSignal.timeout(2000) }),
    ]);
    up = gateway.ok && orchestrator.ok;
  } catch {
    up = false;
  }
});

async function json<T>(response: Response): Promise<T> {
  const text = await response.text();
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${text}`);
  return JSON.parse(text) as T;
}

/** What `keys.ts::createKey` does, minus IndexedDB, which node has no business with. */
async function generate() {
  const [signing, sealing] = (await Promise.all([
    crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]),
    crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]),
  ])) as [CryptoKeyPair, CryptoKeyPair];
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", signing.publicKey));
  const encryptionPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", sealing.publicKey),
  );
  return {
    publicKey,
    privateKey: signing.privateKey,
    encryptionPublicKey,
    keyId: keyIdFor(publicKey),
  };
}

describe("the dashboard's signing path, live", () => {
  it("registers a browser key, signs a grant with it, and revokes it", async () => {
    if (!up) {
      console.log("skipped: the stack is not reachable (see this file's docstring)");
      return;
    }

    // 1. An owner session. In mock mode the enclave derives and attests the
    //    identity from the token's prefix.
    const session = await json<{ session_token: string; identity: { owner_id: string } }>(
      await fetch(`${GATEWAY}/auth/session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ google_token: "mock_google_alice" }),
      }),
    );
    const ownerId = session.identity.owner_id;
    expect(ownerId).toBeTruthy();

    // 2. A key, generated here and never leaving.
    const key = await generate();

    // 3. Registered. The public key crosses; nothing else can.
    const registered = await json<{
      key_id: string;
      label: string;
      can_receive_sealed: boolean;
    }>(
      await fetch(`${GATEWAY}/auth/device/register`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.session_token}`,
        },
        body: JSON.stringify({
          public_key_b64: b64Encode(key.publicKey),
          encryption_key_b64: b64Encode(key.encryptionPublicKey),
          label: "live-test",
        }),
      }),
    );

    // Both halves landed. Ed25519 signs grants; X25519 is where the enclave will
    // seal an assembly back to. Asserted at registration because a device missing
    // the second half registers fine, signs fine and reads fine, and fails only
    // when something first tries to send it sealed content.
    expect(registered.can_receive_sealed).toBe(true);

    // 4. **The check the dashboard adds over the CLI.** Registration is
    //    authorised by a session the host signs, so a host that forged one could
    //    register a key of its own; nothing prevents that, and a client that
    //    believed the server's arithmetic about its own key would never notice.
    expect(registered.key_id).toBe(key.keyId);

    // 5. A grant, signed in this process by a key the gateway has only ever seen
    //    the public half of.
    const token = await signGrant({
      scope: {
        ...emptyScope(ownerId, "live-test-agent"),
        sources: ["mock"],
        entity_kinds: ["person", "project", "artifact", "organization", "topic"],
        max_sensitivity: "personal",
        memory_kinds: ["episodic", "procedural"],
      },
      keyId: key.keyId,
      privateKey: key.privateKey,
      ttlSecs: 300,
    });

    // 6. The gateway's own reading of it -- signature, registration, revocation,
    //    expiry, and the TTL clamp.
    const introspected = await json<{
      active: boolean;
      key_id: string;
      scope: { owner_id: string; agent_id: string; expires_at_ms: number | null };
    }>(
      await fetch(`${GATEWAY}/memory/scope/introspect`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grant_token: token }),
      }),
    );
    expect(introspected.active).toBe(true);
    expect(introspected.key_id).toBe(key.keyId);
    expect(introspected.scope.owner_id).toBe(ownerId);
    expect(introspected.scope.expires_at_ms).not.toBeNull();

    // 7. And a service that has never seen this key accepts it, which is the
    //    whole point of a signed capability: the orchestrator asks the gateway
    //    and needs no shared state with this process.
    const answered = await json<{ answer?: string; citations?: unknown[] }>(
      await fetch(`${ORCHESTRATOR}/query`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grant_token: token, question: "what do we use for storage" }),
      }),
    );
    expect(answered).toHaveProperty("citations");

    // 8. Revoked. There is no per-grant revocation, so this is the lever: it
    //    invalidates every grant the key ever signed, immediately.
    const revoked = await json<{ revoked: boolean }>(
      await fetch(`${GATEWAY}/auth/device/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${session.session_token}`,
        },
        body: JSON.stringify({ key_id: key.keyId }),
      }),
    );
    expect(revoked.revoked).toBe(true);

    // 9. The same token, which was valid four lines ago, is now refused. Nothing
    //    about the token changed -- which is exactly why a key per agent is how
    //    the dashboard expresses "revoke this agent".
    const after = await fetch(`${GATEWAY}/memory/scope/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_token: token }),
    });
    expect(after.ok).toBe(false);
    expect(await after.text()).toContain("revoked");
  }, 30_000);
});
