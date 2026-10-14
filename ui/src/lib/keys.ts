/**
 * The owner's device keys, held in this browser.
 *
 * ADR 0011 says a grant is signed by a key the owner holds and that the gateway
 * cannot mint one. That is why an operator who runs the host still cannot grant
 * themselves read access to someone's memory -- and it is why this file exists
 * rather than a `POST /grants` route.
 *
 * ## Non-extractable, and what that buys
 *
 * Keys are generated with `extractable: false` and stored as `CryptoKey` objects
 * in IndexedDB, which structured-clones them with that flag intact. The page can
 * sign with a key it can never read. So a bug in this application -- or a script
 * injected into it -- can ask for signatures while the key itself stays inside
 * the browser's key store.
 *
 * It is not a hardware guarantee. Someone with the page's origin can sign
 * whatever they like for as long as they are there. What it removes is the
 * *exfiltration* step: there is no serialised private key to steal, log, or sync.
 *
 * ## No JavaScript fallback, deliberately
 *
 * `crypto.subtle` Ed25519 is Chrome/Edge 137+, Safari 17+, Firefox 130+. Where it
 * is missing this module refuses and the UI says so. A `@noble/ed25519` fallback
 * would work everywhere and would put the private key in ordinary, readable
 * JavaScript memory -- weakening precisely the property this screen exists to
 * uphold, silently, on the browsers least likely to be up to date. Refusing is
 * the honest failure.
 *
 * ## One key per agent
 *
 * There is no per-grant revocation anywhere in Kleos: `POST /auth/device/revoke`
 * revokes a *key*, and with it every grant that key ever signed. Rather than
 * build a revocation list, the dashboard adopts the convention that makes the
 * existing lever sufficient -- a key per agent, so "revoke ChatGPT" is revoking
 * ChatGPT's key. Nothing limits how many keys an owner registers, so this costs
 * a registration call. See ADR 0023.
 *
 * ## Losing this browser is recoverable
 *
 * Registration and revocation are authorised by the owner *session*, not by a
 * key. So clearing site data costs the ability to sign *new* grants with the old
 * keys and nothing else: the owner registers a fresh key and revokes the
 * stranded ones. Worth saying in the UI, because "your key lives in this
 * browser" otherwise reads as a threat.
 */

import { keyIdFor } from "./grants";

const DB_NAME = "kleos";
const DB_VERSION = 1;
const STORE = "device-keys";

/** One key this browser holds, as stored. */
export interface StoredKey {
  /** Derived locally from the public key, never taken from the server. */
  keyId: string;
  /** What the owner calls the agent this key signs for. Display only. */
  label: string;
  publicKey: Uint8Array;
  privateKey: CryptoKey;
  createdAtMs: number;
}

export class UnsupportedBrowser extends Error {
  constructor() {
    super(
      "This browser has no Ed25519 in WebCrypto, so it cannot hold a Kleos " +
        "device key. Chrome 137+, Safari 17+ or Firefox 130+ can; otherwise use " +
        "the kleos-device CLI, which is what this screen replaces.",
    );
    this.name = "UnsupportedBrowser";
  }
}

/**
 * Whether this browser can hold a key at all.
 *
 * Feature-detected by *attempting a key generation* rather than by sniffing the
 * user agent, because the algorithm's presence is the thing that matters and
 * version tables go stale. The throwaway key is discarded.
 */
export async function isSupported(): Promise<boolean> {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) return false;
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "keyId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transact<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const request = run(db.transaction(STORE, mode).objectStore(STORE));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }),
  );
}

/**
 * Generates a key for one agent and stores it.
 *
 * Does **not** register it: registration needs the gateway and an owner session,
 * and the two steps fail for unrelated reasons. A key generated but not
 * registered is a recoverable state the UI can retry; a registration the local
 * store knows nothing about is not.
 */
export async function createKey(label: string): Promise<StoredKey> {
  if (!(await isSupported())) throw new UnsupportedBrowser();

  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));

  const stored: StoredKey = {
    // Derived here. The register response will also state a key id, and
    // comparing the two is the only check that makes the registration list
    // meaningful -- see `grants.ts::keyIdFor`.
    keyId: keyIdFor(publicKey),
    label,
    publicKey,
    privateKey: pair.privateKey,
    createdAtMs: Date.now(),
  };
  await transact("readwrite", (store) => store.add(stored));
  return stored;
}

export async function listKeys(): Promise<StoredKey[]> {
  const keys = await transact<StoredKey[]>("readonly", (store) => store.getAll());
  return keys.sort((a, b) => b.createdAtMs - a.createdAtMs);
}

export async function getKey(keyId: string): Promise<StoredKey | undefined> {
  return transact<StoredKey | undefined>("readonly", (store) => store.get(keyId));
}

/**
 * Forgets a key locally.
 *
 * **This is not revocation**, and the UI must not offer it as such. The gateway
 * still holds the public key as registered and still accepts every grant it
 * signed until each expires. Revocation is `POST /auth/device/revoke`, which is a
 * server-side fact; this only loses the ability to sign anything new.
 */
export async function forgetKey(keyId: string): Promise<void> {
  await transact("readwrite", (store) => store.delete(keyId));
}
