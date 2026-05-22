from pqc_aero_bench.analyzer import (
    analyze_kem,
    analyze_signature,
    VERDICT_OK,
    VERDICT_INFEASIBLE,
)
from pqc_aero_bench.benchmark import KEMResult, SigResult, TimingStats
from pqc_aero_bench.datalinks import get


def _dummy_timing() -> TimingStats:
    return TimingStats(iterations=1, median_us=1.0, mad_us=0.0,
                       min_us=1.0, max_us=1.0, ops_per_sec=1_000_000.0)


def _fake_kem(pk: int, ct: int) -> KEMResult:
    return KEMResult(
        name="fake-kem", family="fake", nist_level=1, pq=True, notes="",
        public_key_bytes=pk, secret_key_bytes=pk,
        ciphertext_bytes=ct, shared_secret_bytes=32,
        keygen=_dummy_timing(), encaps=_dummy_timing(), decaps=_dummy_timing(),
    )


def _fake_sig(sig_bytes: int) -> SigResult:
    return SigResult(
        name="fake-sig", family="fake", nist_level=1, pq=True, notes="",
        message_bytes=32,
        public_key_bytes=64,
        secret_key_bytes=64,
        signature_bytes=sig_bytes,
        keygen=_dummy_timing(), sign=_dummy_timing(), verify=_dummy_timing(),
    )


def test_small_kem_fits_aeromacs():
    result = _fake_kem(pk=800, ct=800)
    link = get("AeroMACS")
    fit = analyze_kem(result, link)
    assert fit.fits_single_frame
    assert fit.verdict == VERDICT_OK


def test_giant_signature_is_infeasible_on_adsb():
    result = _fake_sig(sig_bytes=29_792)  # SLH-DSA worst case
    link = get("ADS-B-1090ES")
    fit = analyze_signature(result, link)
    assert not fit.fits_single_frame
    assert fit.verdict == VERDICT_INFEASIBLE


def test_falcon_fits_ldacs():
    result = _fake_sig(sig_bytes=666)
    link = get("LDACS")
    fit = analyze_signature(result, link)
    assert fit.fits_single_frame


def test_fragmentation_count_matches_link():
    result = _fake_sig(sig_bytes=3309)  # ML-DSA-65
    link = get("ACARS-VHF")
    fit = analyze_signature(result, link)
    # ceil(3309 / 220) = 16
    assert fit.fragments == 16
