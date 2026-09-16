use crate::error::EnclaveError;
use shared::{MemoryObject, Timeline};

// Phase 2: ingestion, chunking, embeddings. Left as typed stubs so the
// gateway/route layer has something concrete to compile against now.

pub async fn ingest(_owner_id: &str, _raw: Vec<u8>) -> Result<MemoryObject, EnclaveError> {
    todo!("memory ingestion is out of scope for Phase 1")
}

pub async fn timeline_for(_owner_id: &str) -> Result<Timeline, EnclaveError> {
    todo!("timeline assembly is out of scope for Phase 1")
}
