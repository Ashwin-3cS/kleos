/**
 * Signing a Kleos grant in the browser.
 *
 * This file is a **second implementation of `shared/src/grants.rs`**, and that is
 * the thing to keep in mind while reading it. The Rust side is the one the
 * gateway actually verifies with; this one only has to agree with it, byte for
 * byte, and the way this repo demonstrates that a mirror holds is a test that
 * compares the two sides rather than two files that look similar. See
 * `scripts/sign-fixture.mjs` and `shared/tests/browser_grant_parity.rs`.
 *
 * It exists at all because of ADR 0011: a grant is signed by a key the **owner**
 * holds, and the gateway cannot mint one. A dashboard where the server signs
 * would collapse every confidentiality claim in the project to "trust the host",
 * so the signing has to happen here, which makes this a local-crypto application
 * that happens to have forms.
 *
 * Two things make agreeing with Rust easier than it sounds:
 *
 * 1. **The signature covers the payload bytes as received.** `verify_grant` never
 *    re-serialises the parsed struct (`grants.rs:44`), so key order, whitespace
 *    and number formatting here are free. What must match is the *shape* the
 *    payload deserialises into.
 * 2. **`key_id` need not be guessed.** `/auth/device/register` returns it. We
 *    compute it anyway -- see `keyIdFor`.
 */

import { blake2b } from "blakejs";

/** `kgrant.v1.<payload>.<signature>`, from `grants.rs:41`. */
const PREFIX = "kgrant";
const VERSION = "v1";
/** `GrantClaims.typ` must equal this or `verify_grant` returns `WrongTokenType`. */
const TOKEN_TYPE = "grant";

/**
 * Domain separator for the key id, from `grants.rs:120`. Changing this string is
 * a silent key rotation: every previously registered key would derive a
 * different id and every grant it signed would stop verifying.
 */
const KEY_ID_DOMAIN = "kleos/device-key/v1";

export type Sensitivity = "public" | "personal" | "confidential" | "restricted";
export type EntityKind = "person" | "project" | "artifact" | "organization" | "topic";
export type MemoryKind = "episodic" | "procedural" | "tacit";

/**
 * Mirrors `Scope` in `shared/src/permissions.rs:65`, in declaration order.
 *
 * Every field is required here even though the last seven are `#[serde(default)]`
 * in Rust. Those defaults exist so a grant signed before the harness landed
 * deserialises as read-only rather than failing verification -- which is a
 * property for *old* tokens, not a licence for a new signer to omit fields. A
 * field this file forgets to emit would be a capability silently absent, and the
 * symptom would be a grant that reads nothing for no visible reason.
 */
export interface Scope {
  /** A label the owner typed. **Nothing authenticates it** (`protocol.rs:120`). */
  agent_id: string;
  owner_id: string;
  /** All, not any: an object from two sources needs both (`permissions.rs:176`). */
  sources: string[];
  entity_kinds: EntityKind[];
  not_before_ms: number | null;
  not_after_ms: number | null;
  max_sensitivity: Sensitivity;
  /** Always clamped by the token's own expiry, so this can stay null. */
  expires_at_ms: number | null;
  may_write: boolean;
  may_unseal: boolean;
  may_supersede_owner: boolean;
  /** Separate from `sources` so "read my notes" can never mean "write a note". */
  write_sources: string[];
  memory_kinds: MemoryKind[];
  may_act: boolean;
  act_actions: string[];
}

/** Mirrors `GrantClaims` in `grants.rs:58`. All fields required, no defaults. */
interface GrantClaims {
  typ: string;
  key_id: string;
  scope: Scope;
  issued_at_ms: number;
  expires_at_ms: number;
  nonce: string;
}

/** The read-only scope, matching `Scope::default()` (`permissions.rs:59`). */
export function emptyScope(ownerId = "", agentId = ""): Scope {
  return {
    agent_id: agentId,
    owner_id: ownerId,
    sources: [],
    entity_kinds: [],
    not_before_ms: null,
    not_after_ms: null,
    max_sensitivity: "personal",
    expires_at_ms: null,
    may_write: false,
    may_unseal: false,
    may_supersede_owner: false,
    write_sources: [],
    memory_kinds: [],
    may_act: false,
    act_actions: [],
  };
}

// -- encoding ----------------------------------------------------------

/**
 * base64url, unpadded.
 *
 * The Rust decoder's alphabet is `A-Za-z0-9-_` with no `=` in it
 * (`grants.rs:241`), so padding is not merely unnecessary: a padded segment
 * fails to decode and the token comes back `Malformed`.
 */
export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** Standard base64, which is what `/auth/device/register` wants for a public key. */
export function b64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// -- the key id --------------------------------------------------------

/**
 * `hex(blake2b256(domain || public_key)[0..16])`, from `grants.rs:120`.
 *
 * **This is a security function, not a convenience.** The register response
 * returns the key id, so the UI could simply believe it -- and must not.
 * `gateway/src/routes/memory.rs:206` and `store/device_keys/mod.rs:8` both name
 * the same residual weakness in the design: registration is authorised by an
 * owner session, owner sessions are signed by the host, so a host that forges one
 * can register a key of its own. Nothing prevents that. What detects it is a
 * client that derives the id from the public key it holds and compares.
 *
 * So `blakejs` is here because WebCrypto has no BLAKE2b, and the alternative --
 * trusting the server's arithmetic about the owner's own key -- would remove the
 * only check that makes the registration list meaningful.
 */
export function keyIdFor(publicKey: Uint8Array): string {
  const input = new Uint8Array(KEY_ID_DOMAIN.length + publicKey.length);
  input.set(new TextEncoder().encode(KEY_ID_DOMAIN), 0);
  input.set(publicKey, KEY_ID_DOMAIN.length);
  return hex(blake2b(input, undefined, 32).subarray(0, 16));
}

// -- signing -----------------------------------------------------------

export interface SignGrantOptions {
  scope: Scope;
  keyId: string;
  privateKey: CryptoKey;
  ttlSecs: number;
  nowMs?: number;
  /** Injectable only so the fixture can be reproducible; real grants get a random one. */
  nonce?: string;
}

/**
 * A nonce, so two grants over an identical scope stay distinguishable in the
 * read log (`grants.rs:76`). Nothing stores or checks it, so it is for
 * disambiguation and not for replay protection -- worth knowing before anyone
 * builds on it.
 */
export function freshNonce(): string {
  return hex(crypto.getRandomValues(new Uint8Array(8)));
}

/** Signs a grant. Returns `kgrant.v1.<payload>.<signature>`. */
export async function signGrant(options: SignGrantOptions): Promise<string> {
  const nowMs = options.nowMs ?? Date.now();
  const claims: GrantClaims = {
    typ: TOKEN_TYPE,
    key_id: options.keyId,
    scope: options.scope,
    issued_at_ms: nowMs,
    expires_at_ms: nowMs + options.ttlSecs * 1000,
    nonce: options.nonce ?? freshNonce(),
  };
  const payload = new TextEncoder().encode(JSON.stringify(claims));
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", options.privateKey, payload),
  );
  return `${PREFIX}.${VERSION}.${b64urlEncode(payload)}.${b64urlEncode(signature)}`;
}

/**
 * Reads a token's claims **without verifying anything**.
 *
 * Named to say so. Used only to show an owner when a token they hold expires;
 * the authoritative reading of a grant is `/memory/scope/introspect`, which
 * checks the signature, the registration, the revocation and the expiry, and
 * applies the TTL clamp. A screen that rendered this instead would be the UI
 * agreeing with itself.
 */
export function parseUnverified(token: string): GrantClaims | null {
  const parts = token.split(".");
  if (parts.length !== 4) return null;
  const [prefix, version, payload] = parts;
  if (prefix !== PREFIX || version !== VERSION || !payload) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(payload))) as GrantClaims;
  } catch {
    return null;
  }
}
