"""Algorithm registry: NIST PQC standards + classical baselines.

Every algorithm exposes the same minimal interface through a thin adapter so
the benchmark engine does not care whether the implementation comes from
``quantcrypt`` (PQClean wheels) or ``cryptography`` (OpenSSL):

* KEMs:        ``keygen() -> (pk, sk)``,
               ``encaps(pk) -> (ct, ss)``,
               ``decaps(sk, ct) -> ss``
* Signatures:  ``keygen() -> (pk, sk)``,
               ``sign(sk, msg) -> sig``,
               ``verify(pk, msg, sig) -> bool``

The registry also declares each algorithm's *family*, *security category*
(NIST L1/L3/L5), and whether it is classical or post-quantum. Sizes are
discovered at runtime so the numbers in reports always reflect the
underlying library, never a hard-coded comment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Any


Bytes = bytes


@dataclass
class KEMAdapter:
    """Uniform KEM adapter used by the benchmark engine."""

    name: str
    family: str
    nist_level: int  # 1, 3, or 5; 0 for classical
    pq: bool
    keygen: Callable[[], Tuple[Bytes, Bytes]]
    encaps: Callable[[Bytes], Tuple[Bytes, Bytes]]
    decaps: Callable[[Bytes, Bytes], Bytes]
    notes: str = ""


@dataclass
class SigAdapter:
    """Uniform signature adapter used by the benchmark engine."""

    name: str
    family: str
    nist_level: int
    pq: bool
    keygen: Callable[[], Tuple[Bytes, Bytes]]
    sign: Callable[[Bytes, Bytes], Bytes]
    verify: Callable[[Bytes, Bytes, Bytes], bool]
    notes: str = ""


# ---------------------------------------------------------------------------
# Post-quantum adapters (quantcrypt / PQClean wheels)
# ---------------------------------------------------------------------------
def _build_pq_kems() -> Dict[str, KEMAdapter]:
    from quantcrypt.kem import MLKEM_512, MLKEM_768, MLKEM_1024

    out: Dict[str, KEMAdapter] = {}
    for cls, name, level in (
        (MLKEM_512, "ML-KEM-512", 1),
        (MLKEM_768, "ML-KEM-768", 3),
        (MLKEM_1024, "ML-KEM-1024", 5),
    ):
        inst = cls()
        out[name] = KEMAdapter(
            name=name,
            family="ML-KEM",
            nist_level=level,
            pq=True,
            keygen=inst.keygen,
            encaps=inst.encaps,
            decaps=inst.decaps,
            notes="NIST FIPS 203 (CRYSTALS-Kyber)",
        )
    return out


def _wrap_pq_verify(inst):
    """Adapt quantcrypt's raise-on-failure verify into a bool-returning verify."""
    def _verify(pk, m, s):
        try:
            inst.verify(pk, m, s)
            return True
        except Exception:
            return False
    return _verify


def _build_pq_signatures() -> Dict[str, SigAdapter]:
    from quantcrypt.dss import (
        MLDSA_44,
        MLDSA_65,
        MLDSA_87,
        FALCON_512,
        FALCON_1024,
        SMALL_SPHINCS,
        FAST_SPHINCS,
    )

    out: Dict[str, SigAdapter] = {}

    for cls, name, level, notes in (
        (MLDSA_44, "ML-DSA-44", 2, "NIST FIPS 204 (CRYSTALS-Dilithium)"),
        (MLDSA_65, "ML-DSA-65", 3, "NIST FIPS 204 (CRYSTALS-Dilithium)"),
        (MLDSA_87, "ML-DSA-87", 5, "NIST FIPS 204 (CRYSTALS-Dilithium)"),
    ):
        inst = cls()
        out[name] = SigAdapter(
            name=name,
            family="ML-DSA",
            nist_level=level,
            pq=True,
            keygen=inst.keygen,
            sign=lambda sk, m, _i=inst: _i.sign(sk, m),
            verify=_wrap_pq_verify(inst),
            notes=notes,
        )

    for cls, name, level in (
        (FALCON_512, "Falcon-512", 1),
        (FALCON_1024, "Falcon-1024", 5),
    ):
        inst = cls()
        out[name] = SigAdapter(
            name=name,
            family="Falcon",
            nist_level=level,
            pq=True,
            keygen=inst.keygen,
            sign=lambda sk, m, _i=inst: _i.sign(sk, m),
            verify=_wrap_pq_verify(inst),
            notes="Upcoming NIST FN-DSA (FIPS 206 draft).",
        )

    # SLH-DSA / SPHINCS+ - intentionally only the L1 'small' & 'fast' presets;
    # they are the worst-case PQC sigs by size and are great for showing why
    # narrowband links can't carry them.
    for cls, name, level, notes in (
        (SMALL_SPHINCS, "SLH-DSA-SHA2-128s", 1, "FIPS 205, small variant"),
        (FAST_SPHINCS, "SLH-DSA-SHA2-128f", 1, "FIPS 205, fast variant"),
    ):
        inst = cls()
        out[name] = SigAdapter(
            name=name,
            family="SLH-DSA",
            nist_level=level,
            pq=True,
            keygen=inst.keygen,
            sign=lambda sk, m, _i=inst: _i.sign(sk, m),
            verify=_wrap_pq_verify(inst),
            notes=notes,
        )
    return out


# ---------------------------------------------------------------------------
# Classical baselines (cryptography / OpenSSL)
# ---------------------------------------------------------------------------
def _build_classical_signatures() -> Dict[str, SigAdapter]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding

    out: Dict[str, SigAdapter] = {}

    # --- RSA-2048 / PKCS#1 v1.5 + SHA-256 (industry baseline) ---
    def _rsa_keygen():
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pk = sk.public_key()
        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pk_bytes, sk_bytes

    def _rsa_sign(sk_bytes, msg):
        sk = serialization.load_der_private_key(sk_bytes, password=None)
        return sk.sign(msg, padding.PKCS1v15(), hashes.SHA256())

    def _rsa_verify(pk_bytes, msg, sig):
        pk = serialization.load_der_public_key(pk_bytes)
        try:
            pk.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False

    out["RSA-2048"] = SigAdapter(
        name="RSA-2048",
        family="RSA",
        nist_level=0,
        pq=False,
        keygen=_rsa_keygen,
        sign=_rsa_sign,
        verify=_rsa_verify,
        notes="Classical baseline; broken by Shor's algorithm.",
    )

    # --- ECDSA P-256 + SHA-256 ---
    def _ec_keygen():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key()
        sk_b = sk.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_b = pk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pk_b, sk_b

    def _ec_sign(sk_b, msg):
        sk = serialization.load_der_private_key(sk_b, password=None)
        return sk.sign(msg, ec.ECDSA(hashes.SHA256()))

    def _ec_verify(pk_b, msg, sig):
        pk = serialization.load_der_public_key(pk_b)
        try:
            pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    out["ECDSA-P256"] = SigAdapter(
        name="ECDSA-P256",
        family="ECDSA",
        nist_level=0,
        pq=False,
        keygen=_ec_keygen,
        sign=_ec_sign,
        verify=_ec_verify,
        notes="Classical baseline; broken by Shor's algorithm.",
    )

    # --- Ed25519 ---
    def _ed_keygen():
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_b = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_b = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pk_b, sk_b

    def _ed_sign(sk_b, msg):
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_b)
        return sk.sign(msg)

    def _ed_verify(pk_b, msg, sig):
        pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_b)
        try:
            pk.verify(sig, msg)
            return True
        except Exception:
            return False

    out["Ed25519"] = SigAdapter(
        name="Ed25519",
        family="EdDSA",
        nist_level=0,
        pq=False,
        keygen=_ed_keygen,
        sign=_ed_sign,
        verify=_ed_verify,
        notes="Classical baseline; broken by Shor's algorithm.",
    )

    return out


# ---------------------------------------------------------------------------
# Public registries
# ---------------------------------------------------------------------------
_KEMS: Optional[Dict[str, KEMAdapter]] = None
_SIGS: Optional[Dict[str, SigAdapter]] = None


def kems() -> Dict[str, KEMAdapter]:
    """Return all registered KEMs (lazy-built)."""
    global _KEMS
    if _KEMS is None:
        _KEMS = _build_pq_kems()
    return _KEMS


def signatures() -> Dict[str, SigAdapter]:
    """Return all registered signatures (lazy-built)."""
    global _SIGS
    if _SIGS is None:
        _SIGS = {**_build_pq_signatures(), **_build_classical_signatures()}
    return _SIGS


def kem_names() -> List[str]:
    return list(kems().keys())


def signature_names() -> List[str]:
    return list(signatures().keys())
