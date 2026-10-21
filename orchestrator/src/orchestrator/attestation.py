"""Verifying a Nitro attestation document, mirrored from Rust (ADR 0026).

The Rust original is `shared/src/attestation.rs` and it is the specification:
same outcomes, same refusal names, same commitment layout. Two
implementations is a cost taken deliberately, for the reason ADR 0017 took it
for `evaluate` — this process is Python, and asking the host whether to trust
the host is a loop.

**What a check here is worth.** Less than it looks, and saying so is part of
the design. This process runs on the host, so an operator who wanted to skip
the check would skip it. What it catches is an orchestrator pointed at
something that is not an enclave, and a mock document reaching a deployment
that should not accept one — mistakes, which are most failures. What it does
not catch is anything a hostile operator does. The verification that means
something runs on the device (`device/src/main.rs`) and in the owner's
browser, neither of which is the operator.

**Keep this file and the Rust file in step.** They drift silently: nothing
fails if one accepts a document the other refuses, until the device and the
host disagree about an answer in front of a user.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

#: The prefix `enclave/src/services/attestation.rs` puts on a mock document.
MOCK_PREFIX = "MOCK_ATTESTATION_"

#: SHA-256 of the DER of the AWS Nitro Enclaves root certificate, as published
#: at https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
NITRO_ROOT_SHA256 = bytes.fromhex(
    "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
)

#: Domain separation for `commitment`. Must equal `COMMITMENT_DOMAIN` in Rust.
_COMMITMENT_DOMAIN = b"KLEOS_ATTEST_V1"

#: COSE algorithm id for ECDSA with SHA-384, the only one Nitro uses.
_COSE_ALG_ES384 = -35


class Purpose:
    """The names the enclave routes commit under. Mirrors `attestation::purpose`."""

    ASSEMBLE = "assemble"
    IDENTITY = "identity"
    OAUTH = "oauth"
    SEAL_ENCRYPT = "seal_encrypt"
    ATTEST_DIGEST = "attest_digest"


class Trust(Enum):
    """What a verification established, weakest first.

    Three outcomes rather than a boolean, because "signed by the AWS Nitro PKI"
    and "signed by our enclave image" are different facts and the gap between
    them is the attack: any Nitro enclave produces a document that chains to
    the AWS root, including one the operator built. See ADR 0026.
    """

    MOCK = "mock"
    SIGNED_BY_AWS = "signed_by_aws"
    PINNED = "pinned"

    @property
    def rank(self) -> int:
        return {"mock": 0, "signed_by_aws": 1, "pinned": 2}[self.value]

    def at_least(self, floor: Trust) -> bool:
        return self.rank >= floor.rank


class AttestationError(Exception):
    """A refusal, named the same as the Rust enum variant it mirrors."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def commitment(purpose: str, parts: list[bytes]) -> bytes:
    """SHA-384 over a purpose and length-prefixed parts.

    What an enclave route puts in a document's ``public_key``. Length-prefixed
    because plain concatenation does not uniquely determine what it committed
    to, and a digest because NSM caps that field at 1024 bytes — the assemble
    route used to commit the whole ciphertext, which would have been refused by
    the driver the first time it ran on real hardware.
    """
    hasher = hashlib.sha384()
    hasher.update(_COMMITMENT_DOMAIN)
    hasher.update(len(purpose.encode()).to_bytes(8, "big"))
    hasher.update(purpose.encode())
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


@dataclass(frozen=True)
class Policy:
    """What a verifier accepts. Deny-by-default in the way that matters: mocks
    are off and there is no root until configuration supplies one."""

    root_der: bytes = b""
    expected_pcr0: bytes | None = None
    max_age_ms: int = 0
    allow_mock: bool = False

    @classmethod
    def with_root(cls, root_der: bytes, **kwargs: Any) -> Policy:
        """A policy trusting ``root_der``, refused unless it matches the
        published AWS fingerprint. Checked at construction so a wrong
        certificate is a startup error and not a per-document refusal that
        reads like a bad document."""
        if not root_der:
            raise AttestationError("no_root_configured")
        if hashlib.sha256(root_der).digest() != NITRO_ROOT_SHA256:
            raise AttestationError("root_fingerprint_mismatch")
        return cls(root_der=root_der, **kwargs)

    @classmethod
    def mock_only(cls) -> Policy:
        return cls(allow_mock=True)


@dataclass(frozen=True)
class Verified:
    trust: Trust
    module_id: str
    timestamp_ms: int
    pcrs: dict[int, bytes] = field(default_factory=dict)
    #: The ``public_key`` the document commits to. For a mock, the bytes the
    #: stub committed — harmless, because ``trust`` is MOCK.
    public_key: bytes | None = None
    user_data: bytes | None = None

    def binds_key(self, key: bytes) -> bool:
        """Whether this document commits to ``key``.

        The step that makes a verification about the data in front of the
        caller rather than about some enclave somewhere.
        """
        return self.public_key is not None and self.public_key == key

    @property
    def pcr0(self) -> bytes | None:
        return self.pcrs.get(0)


def verify(document_hex: str, policy: Policy, now_ms: int) -> Verified:
    """Verifies ``document_hex`` under ``policy`` as of ``now_ms``.

    ``now_ms`` is a parameter rather than a clock read, for the reason
    `permissions.evaluate` takes everything it decides on: a function that
    cannot be given the time cannot be tested for expiry.
    """
    if document_hex.startswith(MOCK_PREFIX):
        if not policy.allow_mock:
            raise AttestationError(
                "mock_not_allowed",
                "this is a mock attestation and mocks are not allowed here",
            )
        rest = document_hex[len(MOCK_PREFIX) :]
        try:
            committed = bytes.fromhex(rest)
        except ValueError:
            committed = None
        return Verified(
            trust=Trust.MOCK,
            module_id="mock",
            timestamp_ms=now_ms,
            public_key=committed,
        )

    if not policy.root_der:
        raise AttestationError(
            "no_root_configured",
            "no Nitro root certificate configured, so there is nothing to verify against",
        )

    # Imported here rather than at module scope: the write path imports this
    # module for `commitment`, which needs neither, and a missing optional
    # dependency should not take down ingestion.
    try:
        import cbor2
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise AttestationError("verifier_unavailable", str(exc)) from exc

    try:
        raw = bytes.fromhex(document_hex)
    except ValueError as exc:
        raise AttestationError("not_hex") from exc

    protected, payload, signature = _cose_sign1(cbor2, raw)
    _check_algorithm(cbor2, protected)

    doc = _decode_map(cbor2, payload, "attestation document")
    module_id = _text(doc, "module_id")
    timestamp_ms = _uint(doc, "timestamp")
    pcrs = _pcrs(doc)
    leaf_der = _bytes(doc, "certificate")
    cabundle = _cabundle(doc)

    if not cabundle:
        raise AttestationError("missing_field", "cabundle")
    if cabundle[0] != policy.root_der:
        raise AttestationError(
            "root_not_in_bundle",
            "the document's CA bundle does not start with the configured root",
        )

    # AWS orders the bundle [root, intermediate_1, ...] and the leaf arrives
    # separately, so the chain is the bundle followed by the leaf.
    chain = [x509.load_der_x509_certificate(der) for der in [*cabundle, leaf_der]]
    _verify_chain(chain, now_ms, x509, ec, hashes, InvalidSignature)

    # RFC 8152 section 4.4: the signed bytes are the CBOR encoding of
    # ["Signature1", protected, external_aad, payload] with an empty aad.
    signed = cbor2.dumps(["Signature1", protected, b"", payload])
    leaf_key = chain[-1].public_key()
    try:
        # COSE carries ECDSA as raw r||s; cryptography wants DER.
        half = len(signature) // 2
        der_sig = utils.encode_dss_signature(
            int.from_bytes(signature[:half], "big"),
            int.from_bytes(signature[half:], "big"),
        )
        leaf_key.verify(der_sig, signed, ec.ECDSA(hashes.SHA384()))
    except (InvalidSignature, ValueError) as exc:
        raise AttestationError("bad_signature") from exc

    age_ms = now_ms - timestamp_ms
    if policy.max_age_ms > 0 and (age_ms < 0 or age_ms > policy.max_age_ms):
        raise AttestationError(
            "stale", f"the document is {age_ms}ms old and the limit is {policy.max_age_ms}ms"
        )

    if policy.expected_pcr0 is None:
        trust = Trust.SIGNED_BY_AWS
    else:
        actual = pcrs.get(0)
        if actual is None:
            raise AttestationError("missing_field", "pcr0")
        if actual != policy.expected_pcr0:
            raise AttestationError(
                "measurement_mismatch", "PCR0 does not match the expected measurement"
            )
        trust = Trust.PINNED

    return Verified(
        trust=trust,
        module_id=module_id,
        timestamp_ms=timestamp_ms,
        pcrs=pcrs,
        public_key=doc.get("public_key"),
        user_data=doc.get("user_data"),
    )


def _cose_sign1(cbor2: Any, raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Splits a COSE_Sign1 into the three pieces the signature covers.

    Tagged (CBOR tag 18) and untagged both occur: AWS emits the tagged form and
    several tools strip it, so accepting either is not laxity.
    """
    try:
        value = cbor2.loads(raw)
    except Exception as exc:
        raise AttestationError("malformed_cbor", "not CBOR") from exc
    if isinstance(value, cbor2.CBORTag):
        if value.tag != 18:
            raise AttestationError("malformed_cbor", f"unexpected CBOR tag {value.tag}")
        value = value.value
    # `Sequence` and not `list`: cbor2 decodes nested arrays as tuples and
    # nested maps as a frozen mapping, so an isinstance against the mutable
    # types refuses every real document.
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 4:
        raise AttestationError("malformed_cbor", "COSE_Sign1 is not 4 elements")
    protected, _unprotected, payload, signature = value
    labelled = (
        ("protected header", protected),
        ("payload", payload),
        ("signature", signature),
    )
    for name, part in labelled:
        if not isinstance(part, bytes):
            raise AttestationError("malformed_cbor", name)
    return protected, payload, signature


def _check_algorithm(cbor2: Any, protected: bytes) -> None:
    try:
        header = cbor2.loads(protected)
    except Exception as exc:
        raise AttestationError("malformed_cbor", "protected header is not CBOR") from exc
    if not isinstance(header, Mapping):
        raise AttestationError("malformed_cbor", "protected header is not a map")
    # COSE label 1 is `alg`.
    if 1 not in header:
        raise AttestationError("missing_field", "alg")
    alg = header[1]
    if alg != _COSE_ALG_ES384:
        raise AttestationError(
            "unsupported_algorithm", f"{alg}; a Nitro document is ES384"
        )


def _verify_chain(
    chain: list[Any],
    now_ms: int,
    x509: Any,
    ec: Any,
    hashes: Any,
    invalid_signature: type[Exception],
) -> None:
    """Each certificate signed by the one above it, and all of them in date.

    Revocation is deliberately not checked: AWS documents that CRLs must be
    disabled for this chain.
    """
    now = datetime.fromtimestamp(now_ms / 1000, tz=UTC)
    for index, cert in enumerate(chain):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise AttestationError(
                "certificate_expired", f"certificate {index} is outside its validity period"
            )
    for index in range(1, len(chain)):
        parent, child = chain[index - 1], chain[index]
        try:
            parent.public_key().verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        except (invalid_signature, ValueError, TypeError) as exc:
            raise AttestationError(
                "broken_chain",
                f"certificate {index} was not signed by the one above it",
            ) from exc


def _decode_map(cbor2: Any, raw: bytes, what: str) -> Mapping:
    try:
        value = cbor2.loads(raw)
    except Exception as exc:
        raise AttestationError("malformed_cbor", what) from exc
    if not isinstance(value, Mapping):
        raise AttestationError("malformed_cbor", what)
    return value


def _text(doc: Mapping, key: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str):
        raise AttestationError("missing_field", key)
    return value


def _uint(doc: Mapping, key: str) -> int:
    value = doc.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AttestationError("missing_field", key)
    return value


def _bytes(doc: Mapping, key: str) -> bytes:
    value = doc.get(key)
    if not isinstance(value, bytes):
        raise AttestationError("missing_field", key)
    return value


def _cabundle(doc: Mapping) -> list[bytes]:
    value = doc.get("cabundle")
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or not all(isinstance(v, bytes) for v in value)
    ):
        raise AttestationError("missing_field", "cabundle")
    return list(value)


def _pcrs(doc: Mapping) -> dict[int, bytes]:
    value = doc.get("pcrs")
    if not isinstance(value, Mapping):
        raise AttestationError("missing_field", "pcrs")
    out: dict[int, bytes] = {}
    for index, pcr in value.items():
        if not isinstance(index, int) or not isinstance(pcr, bytes):
            raise AttestationError("malformed_cbor", "pcrs")
        out[index] = pcr
    return out
