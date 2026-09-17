"""HTTP client for the Rust gateway.

The orchestrator calls the gateway for exactly three things: proving an
identity to get an owner session, getting raw content sealed inside the
enclave, and resolving an agent's grant token into the authoritative scope.
Nothing else about the memory layer round-trips through Rust.
"""

from __future__ import annotations

import base64

import httpx

from .permissions import Scope
from .schema import EncryptedContentRef


class GatewayError(RuntimeError):
    pass


class SealedContent:
    __slots__ = ("ciphertext", "ref", "attestation")

    def __init__(self, ciphertext: bytes, ref: EncryptedContentRef, attestation: str) -> None:
        self.ciphertext = ciphertext
        self.ref = ref
        self.attestation = attestation


class GatewayClient:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = httpx.Client(base_url=self._base_url, timeout=timeout)
        self._session_token: str | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def health(self) -> dict:
        return self._get("/health")

    def open_session(
        self,
        google_token: str | None = None,
        github_token: str | None = None,
    ) -> dict:
        """Verifies an identity through the enclave and keeps the session JWT.

        In mock mode the tokens are the Phase 1 ``mock_google_<subject>`` /
        ``mock_github_<login>`` forms; the enclave still does the verifying.
        """
        body = self._post(
            "/auth/session",
            {"google_token": google_token, "github_token": github_token},
        )
        self._session_token = body["session_token"]
        return body

    def adopt_session(self, session_token: str) -> None:
        """Uses a session minted elsewhere (e.g. handed to a queued job)."""
        self._session_token = session_token

    @property
    def owner_session(self) -> str:
        if self._session_token is None:
            raise GatewayError("no owner session; call open_session() first")
        return self._session_token

    def seal_encrypt(self, plaintext: bytes) -> SealedContent:
        """Encrypts raw content inside the enclave.

        The owner id is taken from the session by the gateway, not sent by
        us -- the caller cannot choose whose key content is sealed under.
        """
        body = self._post(
            "/memory/seal/encrypt",
            {"owner_id": "", "plaintext_b64": base64.b64encode(plaintext).decode()},
            auth=True,
        )
        ciphertext = base64.b64decode(body["ciphertext_b64"])
        return SealedContent(
            ciphertext=ciphertext,
            ref=EncryptedContentRef(
                key_id=body["key_id"],
                scheme=body["scheme"],
                blob_id=None,
                byte_len=len(ciphertext),
            ),
            attestation=body["attestation"],
        )

    def grant_scope(self, scope: Scope, ttl_secs: int = 3600) -> str:
        body = self._post(
            "/memory/scope/grant",
            {"scope": scope.model_dump(mode="json"), "ttl_secs": ttl_secs},
            auth=True,
        )
        return body["grant_token"]

    def introspect_scope(self, grant_token: str) -> Scope:
        body = self._post("/memory/scope/introspect", {"grant_token": grant_token})
        if not body.get("active"):
            raise GatewayError("grant is not active")
        return Scope.model_validate(body["scope"])

    def _get(self, path: str) -> dict:
        return self._unwrap(self._http.get(path))

    def _post(self, path: str, json: dict, auth: bool = False) -> dict:
        headers = {"Authorization": f"Bearer {self.owner_session}"} if auth else {}
        return self._unwrap(self._http.post(path, json=json, headers=headers))

    @staticmethod
    def _unwrap(response: httpx.Response) -> dict:
        if response.status_code >= 400:
            raise GatewayError(f"gateway {response.status_code}: {response.text}")
        return response.json()
