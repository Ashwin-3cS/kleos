"""memorai orchestration service.

Everything agentic -- ingestion, resolution, retrieval, summarization --
runs here, outside the enclave. This package is never part of the trust
boundary; it calls the Rust gateway for the operations that must happen
inside the TEE (sealing raw content) or that must be owner-authorised
(minting and introspecting agent scopes).
"""

__version__ = "0.1.0"
