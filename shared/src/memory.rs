use serde::{Deserialize, Serialize};

// Phase 2 concern (ingestion/embeddings). Only the wire-level types are
// defined here so the gateway/enclave crates have something concrete to
// stub their routes and services against in Phase 1.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryObject {
    pub id: String,
    pub owner_id: String,
    pub kind: String,
    pub content_ref: String,
    pub seal_encrypted: bool,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub memory_id: String,
    pub observed_at_ms: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub owner_id: String,
    pub events: Vec<TimelineEvent>,
}
