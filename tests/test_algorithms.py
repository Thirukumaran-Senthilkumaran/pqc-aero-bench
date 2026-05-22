"""Sanity tests for the algorithm registry.

These run real keygen / sign / encaps round-trips, so they cost a few
seconds each but they catch library breakages directly.
"""

import pytest

from pqc_aero_bench import algorithms


def test_kem_registry_completeness():
    names = set(algorithms.kem_names())
    assert {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}.issubset(names)


def test_signature_registry_completeness():
    names = set(algorithms.signature_names())
    expected_pq = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "Falcon-512", "Falcon-1024",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    }
    expected_classical = {"RSA-2048", "ECDSA-P256", "Ed25519"}
    assert expected_pq.issubset(names)
    assert expected_classical.issubset(names)


@pytest.mark.parametrize("name", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_kem_roundtrip(name):
    k = algorithms.kems()[name]
    pk, sk = k.keygen()
    ct, ss = k.encaps(pk)
    ss2 = k.decaps(sk, ct)
    assert ss == ss2
    assert len(pk) > 0 and len(sk) > 0 and len(ct) > 0 and len(ss) > 0


@pytest.mark.parametrize("name", [
    "ML-DSA-44", "Falcon-512", "Ed25519", "ECDSA-P256",
])
def test_signature_roundtrip(name):
    s = algorithms.signatures()[name]
    pk, sk = s.keygen()
    msg = b"aviation cyber"
    sig = s.sign(sk, msg)
    assert s.verify(pk, msg, sig)
    assert not s.verify(pk, b"tampered", sig)


def test_pq_flag_is_correct():
    sigs = algorithms.signatures()
    assert sigs["ML-DSA-65"].pq is True
    assert sigs["Falcon-512"].pq is True
    assert sigs["SLH-DSA-SHA2-128f"].pq is True
    assert sigs["RSA-2048"].pq is False
    assert sigs["ECDSA-P256"].pq is False
    assert sigs["Ed25519"].pq is False
