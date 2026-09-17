//! Exercises the real Postgres store, including the same "no plaintext in
//! the persisted bytes" check the in-memory path gets -- because the thing
//! the invariant is actually about is what lands on disk.
//!
//! Skipped unless `SEALED_TOKEN_STORE_URL` is set, so the default suite
//! needs no services. To run it:
//!
//! ```text
//! docker compose -f orchestrator/docker-compose.yml up -d postgres
//! SEALED_TOKEN_STORE_URL=postgres://memorai:memoraidev@127.0.0.1:5435/memorai \
//!   cargo test -p gateway --test postgres_store_tests -- --nocapture
//! ```

use gateway::store::postgres::PostgresTokenStore;
use gateway::store::{SealedOAuthToken, SealedTokenStore};

const MOCK_REFRESH_TOKEN: &[u8] = b"mock_refresh_google_alice";

fn url() -> Option<String> {
    std::env::var("SEALED_TOKEN_STORE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn sealed(owner: &str, byte: u8) -> SealedOAuthToken {
    // Stands in for what the enclave returns: a MOCK_SEAL_V1 blob whose
    // body is not the plaintext.
    let mut ciphertext = b"MOCK_SEAL_V1:".to_vec();
    ciphertext.extend(MOCK_REFRESH_TOKEN.iter().map(|b| b ^ byte));
    SealedOAuthToken {
        owner_id: owner.to_string(),
        provider: "google".to_string(),
        sealed_refresh_token: ciphertext,
        key_id: format!("mock-seal-{byte}"),
        scheme: "MOCK_SEAL_V1".to_string(),
        scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".to_string()],
        granted_at_ms: 1_700_000_000_000,
        expires_at_ms: Some(1_700_000_003_600),
    }
}

#[tokio::test]
async fn migration_is_idempotent_and_upsert_replaces_in_place() {
    let Some(url) = url() else {
        eprintln!("SEALED_TOKEN_STORE_URL unset; skipping Postgres store test");
        return;
    };

    // Connecting twice runs the migration twice; it must not fail.
    let store = PostgresTokenStore::connect(&url).await.unwrap();
    let store2 = PostgresTokenStore::connect(&url).await.unwrap();
    assert_eq!(store.backend(), "postgres");

    let owner = format!("owner-{}", std::process::id());
    store.upsert(&sealed(&owner, 0x5a)).await.unwrap();
    store2.upsert(&sealed(&owner, 0x7f)).await.unwrap();

    let row = store.get(&owner, "google").await.unwrap().unwrap();
    // Second write replaced the first rather than adding a row.
    assert_eq!(row.key_id, "mock-seal-127");
    assert_eq!(row.scheme, "MOCK_SEAL_V1");
    assert_eq!(row.granted_at_ms, 1_700_000_000_000);
    assert_eq!(row.expires_at_ms, Some(1_700_000_003_600));
    assert_eq!(row.scopes.len(), 1);

    assert!(
        !row.sealed_refresh_token
            .windows(MOCK_REFRESH_TOKEN.len())
            .any(|w| w == MOCK_REFRESH_TOKEN),
        "plaintext refresh token found in the bytes read back from Postgres"
    );

    assert!(store.get(&owner, "github").await.unwrap().is_none());
}
