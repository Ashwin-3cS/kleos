/**
 * The browser signer, checked against the fixture Rust verifies.
 *
 * There are three pieces and they close a loop on purpose:
 *
 *   `scripts/sign-fixture.mjs`  an independent reading of the format -> a token
 *   `browser_grant_parity.rs`   the real `verify_grant` accepts that token
 *   this file                   `grants.ts` produces *that same token*
 *
 * Without the third, the Rust test only proves the fixture script is right, and
 * the fixture script is not what runs in anyone's browser. Without the first,
 * this would be a module agreeing with itself. The loop is what makes any of it
 * evidence.
 */

import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  b64Encode,
  b64urlDecode,
  b64urlEncode,
  emptyScope,
  keyIdFor,
  parseUnverified,
  signGrant,
  type Scope,
} from "./grants";

const FIXTURE = JSON.parse(
  readFileSync(new URL("../../../shared/tests/fixtures/browser_grant.json", import.meta.url), "utf8"),
) as {
  seed_hex: string;
  public_key_hex: string;
  key_id: string;
  issued_at_ms: number;
  token: string;
  expect_scope: Scope;
};

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

async function fixturePrivateKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    Buffer.concat([PKCS8_PREFIX, Buffer.from(FIXTURE.seed_hex, "hex")]),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

describe("signGrant", () => {
  it("produces exactly the token the Rust test verifies", async () => {
    const token = await signGrant({
      scope: FIXTURE.expect_scope,
      keyId: FIXTURE.key_id,
      privateKey: await fixturePrivateKey(),
      ttlSecs: 3600,
      nowMs: FIXTURE.issued_at_ms,
      nonce: "0011223344556677",
    });

    // Byte-for-byte, not "deserialises the same". The signature covers the
    // payload bytes as received, so a different serialisation is a different
    // token even when it means the same thing -- and this is the cheapest place
    // to notice that the two readings of the format have diverged.
    expect(token).toBe(FIXTURE.token);
  });

  it("signs the payload bytes, so re-serialising is never necessary", async () => {
    const token = await signGrant({
      scope: FIXTURE.expect_scope,
      keyId: FIXTURE.key_id,
      privateKey: await fixturePrivateKey(),
      ttlSecs: 3600,
      nowMs: FIXTURE.issued_at_ms,
      nonce: "0011223344556677",
    });
    const payload = token.split(".")[2]!;
    const signature = b64urlDecode(token.split(".")[3]!);

    const publicKey = await crypto.subtle.importKey(
      "raw",
      Buffer.from(FIXTURE.public_key_hex, "hex"),
      { name: "Ed25519" },
      true,
      ["verify"],
    );
    expect(
      await crypto.subtle.verify("Ed25519", publicKey, signature, b64urlDecode(payload)),
    ).toBe(true);
  });

  it("emits every scope field, including the ones Rust defaults", async () => {
    // The seven appended fields are `#[serde(default)]`, so dropping all of them
    // still yields a verifiable token -- a read-only one. A signer that forgot
    // them would look fine and grant nothing, so the payload is checked for their
    // presence rather than for the grant merely verifying.
    const token = await signGrant({
      scope: emptyScope("owner-x", "agent-x"),
      keyId: FIXTURE.key_id,
      privateKey: await fixturePrivateKey(),
      ttlSecs: 60,
    });
    const claims = parseUnverified(token)!;
    for (const field of [
      "agent_id", "owner_id", "sources", "entity_kinds", "not_before_ms",
      "not_after_ms", "max_sensitivity", "expires_at_ms", "may_write",
      "may_unseal", "may_supersede_owner", "write_sources", "memory_kinds",
      "may_act", "act_actions",
    ]) {
      expect(claims.scope, `scope is missing ${field}`).toHaveProperty(field);
    }
  });

  it("gives two grants over one scope different tokens", async () => {
    // The nonce. Two identical authorisations have to stay apart in the read
    // log, or an owner cannot tell which one an agent was using.
    const args = {
      scope: emptyScope("owner-x", "agent-x"),
      keyId: FIXTURE.key_id,
      privateKey: await fixturePrivateKey(),
      ttlSecs: 60,
      nowMs: FIXTURE.issued_at_ms,
    };
    expect(await signGrant(args)).not.toBe(await signGrant(args));
  });
});

describe("keyIdFor", () => {
  it("derives the id the gateway derives", () => {
    // The check the dashboard adds over the CLI. Registration is authorised by a
    // host-signed owner session, so a host that forges one can register a key of
    // its own; nothing prevents it, and this derivation is what detects it.
    expect(keyIdFor(Buffer.from(FIXTURE.public_key_hex, "hex"))).toBe(FIXTURE.key_id);
  });

  it("is 32 hex characters", () => {
    expect(keyIdFor(new Uint8Array(32))).toMatch(/^[0-9a-f]{32}$/);
  });

  it("changes completely when the key changes by one bit", () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    b[31] = 1;
    expect(keyIdFor(a)).not.toBe(keyIdFor(b));
  });

  it("matches what Node derives from the committed seed", () => {
    // Belt and braces: the public key in the fixture is the one the seed really
    // implies, so a fixture edited by hand cannot make the test above pass.
    const raw = createPublicKey(
      createPrivateKey({
        key: Buffer.concat([PKCS8_PREFIX, Buffer.from(FIXTURE.seed_hex, "hex")]),
        format: "der",
        type: "pkcs8",
      }),
    )
      .export({ format: "der", type: "spki" })
      .subarray(-32);
    expect(Buffer.from(raw).toString("hex")).toBe(FIXTURE.public_key_hex);
  });
});

describe("encoding", () => {
  it("round-trips base64url without padding", () => {
    for (const length of [0, 1, 2, 3, 31, 32, 64, 255]) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 7) % 256);
      const encoded = b64urlEncode(bytes);
      expect(encoded).not.toContain("=");
      expect(encoded).not.toMatch(/[+/]/);
      expect([...b64urlDecode(encoded)]).toEqual([...bytes]);
    }
  });

  it("keeps padding in standard base64, which register wants", () => {
    // `/auth/device/register` decodes `public_key_b64` with the *standard*
    // alphabet and requires exactly 32 bytes, so this one must stay padded --
    // the two encodings are not interchangeable and live side by side here.
    expect(b64Encode(new Uint8Array(32))).toBe("A".repeat(43) + "=");
  });

  it("refuses a token that is not four segments", () => {
    expect(parseUnverified("kgrant.v1.abc")).toBeNull();
    expect(parseUnverified("kgrant.v2.abc.def")).toBeNull();
    expect(parseUnverified("nope.v1.abc.def")).toBeNull();
    expect(parseUnverified("kgrant.v1.not-base64-json.def")).toBeNull();
  });
});
