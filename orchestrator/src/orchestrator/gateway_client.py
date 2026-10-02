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

    def seal_decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        """Unseals content inside the enclave, back out to this process.

        The owner comes from the session on the gateway side, not from us, so a
        caller cannot ask for another owner's content. Called only for objects
        that already passed the permission check -- the decrypt budget is the
        disclosure budget (ADR 0010).
        """
        body = self._post(
            "/memory/seal/decrypt",
            {
                "owner_id": "",
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                "key_id": key_id,
            },
            auth=True,
        )
        return base64.b64decode(body["plaintext_b64"])

    # There is deliberately no `grant_scope` here any more. Grants are signed by
    # a key the owner holds, so nothing in this process -- or in the gateway --
    # can mint one; the owner's client signs a scope and hands the agent the
    # result. See ADR 0011 and the `kleos-device` command. All this side does is
    # introspect what it is given, below.

    def introspect_session(self, session_token: str) -> str:
        """Resolves an owner session token to its owner id.

        The orchestrator holds no signing key, so anything it has to
        authenticate it asks the gateway about. This is what makes the read log
        owner-authenticated rather than grant-authenticated: an owner's record
        of what agents read must not be readable by an agent. See ADR 0005.
        """
        body = self._post("/auth/session/introspect", {"session_token": session_token})
        if not body.get("active"):
            raise GatewayError("session is not active")
        return body["owner_id"]

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
