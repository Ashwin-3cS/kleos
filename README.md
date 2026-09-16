# memorai (placeholder name)

A decentralized personal memory layer for humans and AI agents. Every
individual's digital life is ingested inside a TEE (AWS Nitro Enclave),
attested via NSM, and (in later phases) encrypted with Seal and stored on
Walrus. The user owns it; authorized AI agents query it with scoped
permissions. No government ID -- identity comes from stacked OAuth signals
(Google, GitHub, wallet signature) verified **inside the enclave**.

This repo is **Phase 1**: infrastructure scaffold only. No web app, no SDK,
no smart contracts, no memory ingestion or embeddings. Just the enclave, the
gateway, and the deploy plumbing, proven end to end via CLI with a mock
OAuth identity-verification flow.

The only asset carried over from the abandoned prior product
(`suiverify`, a decentralized KYC platform) is the Nitro Enclave build/deploy
template at `suiverify/nautilus-attestation-backend/` -- its NSM attestation
logic and socat-based VSOCK bridging pattern. That project is read-only
reference material and is not part of this repo.

## Architecture

```
gateway (Axum, host, TCP)
  - OAuth redirect flow (code exchange only, Phase 2) + session JWT
  - Proxies all sensitive work to the enclave over VSOCK
        |
        v
enclave (Axum, inside Nitro Enclave)        <- core trust boundary
  - Verifies OAuth tokens itself, against the provider, inside the TEE
  - Computes trust tier from stacked signals
  - NSM attestation over the result
  - (Phase 2) ingests data, extracts memory objects, Seal-encrypts
        |
        v
storage (wired in later phases): Walrus, Walrus Memory, Supabase
```

**Why verification happens in the enclave and not the gateway:** the NSM
attestation only means something if the thing it's attesting actually
happened inside the TEE. If the gateway verified the OAuth token and just
told the enclave "trust me, this checked out," the attestation would cover
nothing of value. So `enclave/src/routes/identity.rs` calls Google/GitHub's
verification endpoints itself, and only then produces the attestation.

**Phase 1 end-to-end flow** (see `scripts/smoke_test.sh`):
1. Client hits `POST /identity/verify` on the gateway with a raw OAuth token
   (obtained manually -- curl, or a one-off script; real code exchange is
   Phase 2, see `gateway/src/routes/auth.rs`).
2. Gateway forwards the token to the enclave over its VSOCK-bridged TCP
   client (`gateway/src/vsock/client.rs`).
3. Enclave calls the provider's verification endpoint itself, through an
   outbound VSOCK tunnel (`enclave/src/services/oauth/{google,github}.rs`).
4. Enclave computes a trust tier from the signals present: Google alone = 1,
   + GitHub = 2, + wallet = 3, + domain = 4 (wallet/domain are Phase 2 stubs
   that reject explicitly rather than pretending to work).
5. Enclave produces an NSM attestation document over the result.
6. Gateway returns `{ identity, attestation }` as JSON, unmodified.

No on-chain writes happen in Phase 1. Nothing is persisted.

## No Rust VSOCK crate

There is no VSOCK crate anywhere in this codebase, by design (mirroring the
proven `nautilus-attestation-backend` pattern). All VSOCK<->TCP bridging is
done at the shell level with `socat`:

- Inbound: `enclave/run.sh` runs
  `socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:4000 &`, so the
  enclave's Rust binary just binds plain TCP (`enclave/src/vsock/listener.rs`)
  -- completely ordinary Axum/tokio code.
- Outbound: `enclave/run.sh` opens tunnels like
  `socat TCP-LISTEN:8002,reuseaddr,fork VSOCK-CONNECT:3:8002 &`, so
  `enclave/src/services/http.rs` and the OAuth provider clients just call
  `http://127.0.0.1:<port>/...` with plain `reqwest` and the tunnel carries
  it out over VSOCK to the host.
- On the host, `scripts/parent_forwarder.sh` bridges each of those VSOCK
  ports onward to the real external service, and bridges the gateway's
  inbound TCP calls into the enclave's VSOCK port 4000.

In both `mock` and `nitro` mode the Rust code only ever speaks plain TCP/
HTTP; the difference is entirely in whether a socat bridge exists on the
other end.

## VSOCK ports

| Port | Direction        | Purpose                        |
|------|-------------------|---------------------------------|
| 4000 | Gateway -> Enclave | Main API                       |
| 5000 | Enclave -> Host    | Log forwarding                 |
| 8002 | Enclave -> Host    | Google OAuth APIs               |
| 8003 | Enclave -> Host    | GitHub API                      |
| 8004 | Enclave -> Host    | Walrus publisher/aggregator     |
| 8005 | Enclave -> Host    | Walrus Memory relayer           |

## Local development (mock mode)

Nitro enclaves only run on EC2. Locally, the `enclave` crate builds with its
default `mock` feature: the enclave binds `127.0.0.1:4000` directly (no
socat, no VSOCK) and its OAuth providers short-circuit token verification
instead of dialing a tunnel that doesn't exist locally -- pass a token of
the form `mock_google_<subject>` / `mock_github_<login>` and the provider
deterministically returns that identity. The attestation document returned
in mock mode is prefixed `MOCK_ATTESTATION_` so it can never be mistaken for
a real one.

```bash
cargo build                     # workspace, mock feature (default)
./scripts/run_local.sh          # starts enclave + gateway in mock mode
./scripts/smoke_test.sh         # posts mock tokens through the gateway
kill $(cat .local/enclave.pid) $(cat .local/gateway.pid)
```

## EC2 / Nitro deploy path

```bash
cargo build --release --no-default-features --features nitro -p enclave
./scripts/build_enclave.sh      # stagex/docker build -> enclave/out/*.eif
./scripts/deploy.sh             # ships .eif + gateway binary to DEPLOY_HOST
# on the parent instance:
nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path memorai-enclave.eif --enclave-cid 16
./parent_forwarder.sh &
ENCLAVE_MODE=nitro ./memorai-gateway
```

`enclave/Dockerfile` is a stagex-based multi-stage build (adapted from
`suiverify/nautilus-attestation-backend/Containerfile`) producing a
reproducible `.eif` via `eif_build`. It needs the stagex image cache and a
network-reachable cargo registry (for the pinned
`aws-nitro-enclaves-nsm-api` git dependency); it was not run in this
sandboxed dev environment (no docker/stagex here) but is structurally
verified: `cargo build --release --no-default-features --features nitro -p enclave`
was run standalone and **compiles cleanly**, including resolving the
`aws-nitro-enclaves-nsm-api` git dependency.

## Repo layout

```
enclave/    Axum server that runs inside the Nitro Enclave (or locally in mock mode)
gateway/    Axum server that runs on the host, proxies to the enclave
shared/     Types shared by both: identity, memory (stub), VSOCK protocol envelopes
scripts/    build/run/deploy/smoke-test plumbing
```

`enclave/src/services/memory.rs`, `enclave/src/services/seal.rs`,
`gateway/src/routes/memory.rs`, and `shared/src/memory.rs`'s types are
Phase 2 stubs -- typed and compiling, bodies are `todo!()`. No memory
ingestion, embeddings, or agent features exist yet.

## Env vars

See `.env.example` at the repo root.

## Deviations from the nautilus reference

- Uses `fastcrypto`'s `Ed25519KeyPair`, same as the nautilus reference --
  matches Sui's crypto stack for later phases (on-chain signing, Sui SDK
  interop).
- Cargo feature renamed `aws` -> `nitro` per the new project's naming.
- Dropped Redis, Sui, government-API, and DigiLocker-specific code paths
  entirely; replaced with the OAuth-provider + Walrus/Walrus-Memory port
  plan above.
