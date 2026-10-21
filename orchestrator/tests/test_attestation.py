"""The Python verifier, against a chain the test builds (ADR 0026).

Mirrors `shared/tests/attestation_tests.rs` case for case, deliberately: two
implementations drift silently, and the failure mode is the device and the host
disagreeing about an answer in front of a user. Where a case here has no
counterpart there, or the other way round, that is a gap worth noticing.

`test_commitment_matches_the_rust_vector` is the one that catches drift in the
part both languages compute rather than merely check.
"""

from __future__ import annotations

import datetime as dt

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from orchestrator.attestation import (
    MOCK_PREFIX,
    NITRO_ROOT_SHA256,
    AttestationError,
    Policy,
    Purpose,
    Trust,
    commitment,
    verify,
)

NOW = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
NOW_MS = int(NOW.timestamp() * 1000)


def _cert(subject: str, signer_key, signer_name, key, *, ca: bool):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(signer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=365))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signer_key, hashes.SHA384()), name


class Chain:
    """A root and a leaf signed by it, both P-384, valid around `NOW`."""

    def __init__(self) -> None:
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        root, root_name = _cert(
            "aws.nitro-enclaves", self.root_key, None, self.root_key, ca=True
        )
        leaf, _ = _cert(
            "i-0123456789abcdef.enclave",
            self.root_key,
            root_name,
            self.leaf_key,
            ca=False,
        )
        self.root_der = root.public_bytes(serialization.Encoding.DER)
        self.leaf_der = leaf.public_bytes(serialization.Encoding.DER)


def document(
    chain: Chain,
    *,
    timestamp_ms: int = NOW_MS,
    pcr0: bytes = b"\xab" * 48,
    public_key: bytes | None = b"\x07" * 32,
    alg: int = -35,
    cabundle: list[bytes] | None = None,
    leaf_key=None,
) -> str:
    """One COSE_Sign1, tagged 18, ES384, signed over the Sig_structure."""
    payload_fields: dict = {
        "module_id": "i-0123456789abcdef-enc0123456789",
        "timestamp": timestamp_ms,
        "digest": "SHA384",
        "pcrs": {0: pcr0},
        "certificate": chain.leaf_der,
        "cabundle": cabundle if cabundle is not None else [chain.root_der],
    }
    if public_key is not None:
        payload_fields["public_key"] = public_key
    payload = cbor2.dumps(payload_fields)
    protected = cbor2.dumps({1: alg})

    signed = cbor2.dumps(["Signature1", protected, b"", payload])
    der = (leaf_key or chain.leaf_key).sign(signed, ec.ECDSA(hashes.SHA384()))
    # COSE carries ECDSA as raw r||s; `sign` gives DER.
    r, s = decode_dss_signature(der)
    raw_sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")

    cose = cbor2.dumps(
        cbor2.CBORTag(18, [protected, {}, payload, raw_sig])
    )
    return cose.hex()


@pytest.fixture
def chain() -> Chain:
    return Chain()


@pytest.fixture
def policy(chain: Chain) -> Policy:
    # Unchecked, because the published AWS root is not in this repository and a
    # test that cannot build its own chain cannot test the chain walk. The pin
    # itself is tested separately.
    return Policy(root_der=chain.root_der)


def test_a_well_formed_document_verifies_as_signed_by_aws(chain, policy):
    verified = verify(document(chain), policy, NOW_MS)
    assert verified.trust is Trust.SIGNED_BY_AWS
    assert verified.module_id == "i-0123456789abcdef-enc0123456789"
    assert verified.timestamp_ms == NOW_MS
    assert verified.pcr0 == b"\xab" * 48


def test_an_expected_measurement_that_matches_is_pinned(chain, policy):
    pinned = Policy(root_der=policy.root_der, expected_pcr0=b"\xab" * 48)
    assert verify(document(chain), pinned, NOW_MS).trust is Trust.PINNED


def test_a_different_measurement_is_refused_rather_than_downgraded(chain, policy):
    # The attack ADR 0026 is about: a real enclave running an image we did not
    # build. The chain verifies and the answer is still a refusal.
    other = Policy(root_der=policy.root_der, expected_pcr0=b"\x01" * 48)
    with pytest.raises(AttestationError) as exc:
        verify(document(chain), other, NOW_MS)
    assert exc.value.reason == "measurement_mismatch"


def test_a_tampered_payload_fails_the_signature(chain, policy):
    raw = bytearray(bytes.fromhex(document(chain)))
    raw[len(raw) // 2] ^= 0xFF
    with pytest.raises(AttestationError):
        verify(raw.hex(), policy, NOW_MS)


def test_a_leaf_signed_by_somebody_else_breaks_the_chain(chain, policy):
    theirs = Chain()
    # Their leaf, their key, our root in the bundle.
    doc = document(theirs, cabundle=[chain.root_der])
    with pytest.raises(AttestationError) as exc:
        verify(doc, policy, NOW_MS)
    assert exc.value.reason == "broken_chain"


def test_a_bundle_that_does_not_start_with_our_root_is_refused(chain, policy):
    theirs = Chain()
    with pytest.raises(AttestationError) as exc:
        verify(document(theirs), policy, NOW_MS)
    assert exc.value.reason == "root_not_in_bundle"


def test_an_algorithm_other_than_es384_is_refused(chain, policy):
    with pytest.raises(AttestationError) as exc:
        verify(document(chain, alg=-7), policy, NOW_MS)
    assert exc.value.reason == "unsupported_algorithm"


def test_a_stale_document_is_refused_when_a_limit_is_set(chain, policy):
    bounded = Policy(root_der=policy.root_der, max_age_ms=60_000)
    with pytest.raises(AttestationError) as exc:
        verify(document(chain), bounded, NOW_MS + 120_000)
    assert exc.value.reason == "stale"
    # ...and accepted inside the window.
    assert verify(document(chain), bounded, NOW_MS + 30_000).trust is Trust.SIGNED_BY_AWS


def test_a_document_from_the_future_is_refused(chain, policy):
    bounded = Policy(root_der=policy.root_der, max_age_ms=60_000)
    with pytest.raises(AttestationError) as exc:
        verify(document(chain, timestamp_ms=NOW_MS + 600_000), bounded, NOW_MS)
    assert exc.value.reason == "stale"


def test_an_expired_certificate_is_refused(chain, policy):
    far_future = NOW_MS + 5 * 365 * 86_400 * 1000
    with pytest.raises(AttestationError) as exc:
        verify(document(chain), policy, far_future)
    assert exc.value.reason == "certificate_expired"


def test_key_binding_is_what_makes_it_about_the_data(chain, policy):
    verified = verify(document(chain), policy, NOW_MS)
    assert verified.binds_key(b"\x07" * 32)
    assert not verified.binds_key(b"\x08" * 32)


def test_a_document_committing_to_no_key_binds_nothing(chain, policy):
    verified = verify(document(chain, public_key=None), policy, NOW_MS)
    assert not verified.binds_key(b"\x07" * 32)
    assert not verified.binds_key(b"")


def test_a_mock_is_refused_unless_mocks_are_allowed(chain, policy):
    mock = MOCK_PREFIX + (b"\x07" * 32).hex()
    with pytest.raises(AttestationError) as exc:
        verify(mock, policy, NOW_MS)
    assert exc.value.reason == "mock_not_allowed"
    verified = verify(mock, Policy.mock_only(), NOW_MS)
    assert verified.trust is Trust.MOCK
    assert verified.binds_key(b"\x07" * 32)


def test_a_mock_never_reaches_a_stronger_verdict():
    # Even with a measurement configured. The prefix stopped being a comment
    # the moment this held.
    mock = MOCK_PREFIX + (b"\x07" * 32).hex()
    policy = Policy(allow_mock=True, expected_pcr0=b"\xab" * 48)
    verified = verify(mock, policy, NOW_MS)
    assert verified.trust is Trust.MOCK
    assert not verified.trust.at_least(Trust.SIGNED_BY_AWS)


def test_a_real_document_is_refused_when_no_root_is_configured(chain):
    with pytest.raises(AttestationError) as exc:
        verify(document(chain), Policy.mock_only(), NOW_MS)
    assert exc.value.reason == "no_root_configured"


def test_the_pinned_fingerprint_rejects_a_certificate_that_is_not_the_aws_root(chain):
    with pytest.raises(AttestationError) as exc:
        Policy.with_root(chain.root_der)
    assert exc.value.reason == "root_fingerprint_mismatch"
    with pytest.raises(AttestationError) as exc:
        Policy.with_root(b"")
    assert exc.value.reason == "no_root_configured"
    assert (
        NITRO_ROOT_SHA256.hex().upper()
        == "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
    )


@pytest.mark.parametrize("junk", ["", "zz", "00", "deadbeef", MOCK_PREFIX])
def test_garbage_is_refused_without_crashing(junk, chain, policy):
    with pytest.raises(AttestationError):
        verify(junk, policy, NOW_MS)


def test_commitment_matches_the_rust_vector():
    """The one cross-language check that matters.

    `commitment` is computed on both sides -- the enclave writes it in Rust and
    the device and this process recompute it -- so a disagreement here is not a
    verification that fails but one that *passes on one side only*. The vector
    is printed by `shared`'s own test of the same name.
    """
    digest = commitment(Purpose.ASSEMBLE, [b"\x01\x02", b"key-id", b"ciphertext"])
    assert len(digest) == 48
    assert digest.hex() == (
        # The same vector is asserted in `shared/tests/attestation_tests.rs`.
        "ad50054e35c925b99d0323219d2b90b0caf93e95680609f3"
        "97baec68c6e9b5dbb03101c5dae1a1afa3e0460236f5d678"
    )


def test_commitment_is_unambiguous_about_where_the_parts_divide():
    """Length-prefixing, which the concatenation it replaced did not have.

    `pk || key_id || ciphertext` can be re-split at a different boundary to
    give the same bytes from different parts, so the old commitment did not
    uniquely determine what it committed to.
    """
    assert commitment("p", [b"ab", b"c"]) != commitment("p", [b"a", b"bc"])
    assert commitment("p", [b"abc"]) != commitment("p", [b"ab", b"c"])


def test_the_purpose_is_inside_the_digest():
    """So a document produced for a sealed field cannot be replayed as one
    produced for an assembly."""
    parts = [b"pk", b"key-id"]
    assert commitment(Purpose.ASSEMBLE, parts) != commitment(Purpose.SEAL_ENCRYPT, parts)


# --- AttestationCheck: the host-side wiring -------------------------------
#
# What the orchestrator actually calls. Worth testing separately from `verify`
# because the bug it guards against is not a bad document -- it is a check that
# is configured off, or wired to one of the two seal routes and not the other.


class _Settings:
    """The three fields `AttestationCheck` reads, and nothing else."""

    def __init__(self, **kwargs) -> None:
        self.verify_attestation = kwargs.get("verify_attestation", True)
        self.attestation_allow_mock = kwargs.get("attestation_allow_mock", False)
        self.attestation_root_path = kwargs.get("attestation_root_path", None)
        self.attestation_expected_pcr0 = kwargs.get("attestation_expected_pcr0", None)
        self.attestation_max_age_secs = kwargs.get("attestation_max_age_secs", 0)


def _check(**kwargs):
    from orchestrator.gateway_client import AttestationCheck

    return AttestationCheck(_Settings(**kwargs))


def _mock_for(purpose: str, parts: list[bytes]) -> str:
    return MOCK_PREFIX + commitment(purpose, parts).hex()


def test_the_check_refuses_a_mock_under_default_settings():
    from orchestrator.gateway_client import GatewayError

    parts = [b"pk", b"key-id"]
    with pytest.raises(GatewayError, match="mock"):
        _check().check(_mock_for(Purpose.SEAL_ENCRYPT, parts), Purpose.SEAL_ENCRYPT, parts)


def test_the_check_accepts_a_mock_when_configuration_says_so():
    parts = [b"pk", b"key-id"]
    _check(attestation_allow_mock=True).check(
        _mock_for(Purpose.SEAL_ENCRYPT, parts), Purpose.SEAL_ENCRYPT, parts
    )


def test_the_check_refuses_a_document_about_some_other_call():
    """The half that is easy to leave out.

    The document verifies -- it is a well-formed mock and mocks are allowed --
    and it is about a different key id. Without the commitment check, relaying
    somebody else's attestation beside this ciphertext would pass.
    """
    from orchestrator.gateway_client import GatewayError

    other = _mock_for(Purpose.SEAL_ENCRYPT, [b"pk", b"some-other-key-id"])
    with pytest.raises(GatewayError, match="does not commit"):
        _check(attestation_allow_mock=True).check(
            other, Purpose.SEAL_ENCRYPT, [b"pk", b"key-id"]
        )


def test_the_check_refuses_a_document_produced_for_a_different_purpose():
    from orchestrator.gateway_client import GatewayError

    parts = [b"pk", b"key-id"]
    assembled = _mock_for(Purpose.ASSEMBLE, parts)
    with pytest.raises(GatewayError, match="does not commit"):
        _check(attestation_allow_mock=True).check(assembled, Purpose.SEAL_ENCRYPT, parts)


def test_a_missing_document_is_a_refusal_not_a_pass():
    from orchestrator.gateway_client import GatewayError

    with pytest.raises(GatewayError, match="no attestation"):
        _check(attestation_allow_mock=True).check("", Purpose.SEAL_ENCRYPT, [b"pk"])


def test_the_check_can_be_turned_off_and_then_passes_anything():
    # Documented behaviour rather than a loophole: `VERIFY_ATTESTATION=0` is a
    # configuration choice, and the eval harness runs with no gateway at all.
    _check(verify_attestation=False).check("not a document", Purpose.SEAL_ENCRYPT, [b"x"])
