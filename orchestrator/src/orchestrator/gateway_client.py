"""HTTP client for the Rust gateway.

The orchestrator calls the gateway for proving an identity to get an owner
session, getting raw content sealed inside the enclave, resolving an agent's
grant token into the authoritative scope, and -- since ADR 0024 -- having a
read *assembled* in the enclave and encrypted to the device that asked.

That last one is different in kind from the rest. Everything else here is a
request whose answer this process reads. `assemble` is a request whose answer
this process deliberately cannot read, and relays.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import httpx

from .permissions import Scope
from .schema import EncryptedContentRef
from .storage.reads import grant_fingerprint


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedGrant:
    """What a grant token resolves to: its scope, and who presented it.

    Frozen, because this is the authority for a read and nothing downstream has
    any business editing it.
    """

    scope: Scope
    #: The registered device key that signed this grant. Authenticated.
    device_id: str
    #: Keyed hash of the token, for the read and mutation logs. The token itself
    #: is never stored anywhere -- an audit log holding live bearer credentials is
    #: a vulnerability wearing an accountability costume (ADR 0005).
    grant_fp: str


@dataclass(frozen=True, slots=True)
class SealedAssembly:
    """A read answered inside the enclave: a blob, and the structure around it.

    The split is ADR 0024's line, arriving as one object. `sealed` is the
    answer, encrypted to the device that signed the grant, and nothing in this
    process can open it. Everything beside it is structure the host already had
    -- which ids were disclosed, which were denied and why, how many were
    considered -- and the read log cannot be written without it.

    Frozen for the reason `ResolvedGrant` is: the structural half is what goes
    into the owner's audit record, and nothing downstream has any business
    editing it on the way there.
    """

    #: The `SealedToDevice` envelope, relayed verbatim. Kept as a dict rather
    #: than parsed into fields: this process is a courier for it, and a courier
    #: that unpacks the parcel is one more place a format change breaks.
    sealed: dict
    disclosed_ids: list[str]
    denials: list[dict]
    considered: int
    attestation: str


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

    def unseal_for_grant(self, ciphertext: bytes, key_id: str, grant_token: str) -> bytes:
        """Unseals content under an agent's own grant, with no owner session.

        `seal_decrypt` above needs one, and an agent has none -- which is why
        every read against sealed content failed before this existed. The gateway
        verifies the grant itself and takes the owner from the verified scope, so
        the owner is at least as unspoofable as it is behind a session.

        Called only for objects that have already passed the ordinary permission
        check *and* `evaluate_unseal`: seeing a resolved claim and reading the raw
        body it came from are different disclosures. The decrypt budget is the
        disclosure budget (ADR 0010).
        """
        body = self._post(
            "/memory/seal/unseal",
            {
                "grant_token": grant_token,
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                "key_id": key_id,
            },
        )
        return base64.b64decode(body["plaintext_b64"])

    def assemble(
        self, grant_token: str, question: str, candidates: list[dict]
    ) -> SealedAssembly:
        """Has a read assembled inside the enclave, sealed to the asking device.

        What goes up is the candidates this process ranked, **with their content
        still sealed** -- it has not read them and does not need to. What comes
        back is a blob it cannot read and the structure it already had.

        Note what is absent from the request: the owner, and the recipient. Both
        are derived by the gateway from the verified grant. A caller that could
        name the recipient could ask for the answer sealed to a key it controls,
        which is the entire design defeated by a field, so there is no field.

        Nor is there a permission verdict. This process computed none: the ACLs
        travel with the candidates and the enclave decides, because a decision
        made out here is a decision the operator makes.
        """
        body = self._post(
            "/memory/assemble",
            {
                "grant_token": grant_token,
                "question": question,
                "candidates": candidates,
            },
        )
        return SealedAssembly(
            sealed=body["sealed"],
            disclosed_ids=list(body.get("disclosed_ids", [])),
            denials=list(body.get("denials", [])),
            considered=int(body.get("considered", 0)),
            attestation=body.get("attestation", ""),
        )

    def request_action(
        self, grant_token: str, action_id: str, args: dict
    ) -> dict:
        """Asks the enclave, through the gateway, to perform one action.

        What comes back is an **acknowledgement**: whether it happened, a digest
        over what it did, and one line of summary. Not the credential it needed,
        and not the material that credential unlocks.

        A refusal arrives as a successful response with ``ok: false``, which is
        the shape rather than an accident -- an attempt made and failed is a
        different fact from an attempt never made, and both are recorded.
        """
        return self._post(
            "/memory/act",
            {"grant_token": grant_token, "action_id": action_id, "args": args},
        )

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

    def introspect_grant(self, grant_token: str) -> ResolvedGrant:
        """Resolves a grant token to the scope **and the device that signed it**.

        `Scope.agent_id` is a string the owner typed into a scope file before
        running `kleos-device sign`; nothing authenticates it, so two agents handed
        the same file are indistinguishable. The signing key is different: the
        gateway looked it up in the owner's registered device keys and checked the
        signature against it. So this is the one identity in an agent's request
        that can be relied on, and it is what makes "device 1 decided this"
        answerable. See ADR 0016.
        """
        body = self._post("/memory/scope/introspect", {"grant_token": grant_token})
        if not body.get("active"):
            raise GatewayError("grant is not active")
        return ResolvedGrant(
            scope=Scope.model_validate(body["scope"]),
            # Absent only against a gateway older than ADR 0016. Empty rather than
            # a guess: a fabricated device id would be indistinguishable from an
            # authenticated one in every record that stores it.
            device_id=body.get("key_id", ""),
            grant_fp=grant_fingerprint(grant_token),
        )

    def introspect_scope(self, grant_token: str) -> Scope:
        """The scope alone, for the read paths that do not record who asked.

        Kept as a wrapper rather than replaced so that adding the device to one
        read path is not a change to all four at once.
        """
        return self.introspect_grant(grant_token).scope

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
