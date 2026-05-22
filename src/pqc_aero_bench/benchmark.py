"""Timing engine.

Methodology
-----------
* Each operation is executed in a warm-up loop (discarded) and then in a
  measurement loop. We report median + median-absolute-deviation rather
  than mean/stddev because PQC signing has heavy-tailed reject-and-retry
  distributions (notably ML-DSA and Falcon).
* We use ``time.perf_counter_ns`` for monotonic, high-resolution timing.
* Object sizes are *measured* (``len(bytes)``) on real outputs, never read
  from a hard-coded table. This way the report always agrees with the
  underlying library.
* For signature schemes we hash a fixed 32-byte payload by default; you can
  override this on the CLI with ``--message-size N`` (handy for showing the
  ACARS / ADS-B short-message case).
"""

from __future__ import annotations

import os
import statistics
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from . import algorithms


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class TimingStats:
    """Robust timing statistics for a single operation."""

    iterations: int
    median_us: float
    mad_us: float          # median absolute deviation
    min_us: float
    max_us: float
    ops_per_sec: float


@dataclass
class KEMResult:
    name: str
    family: str
    nist_level: int
    pq: bool
    notes: str
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    keygen: TimingStats
    encaps: TimingStats
    decaps: TimingStats

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class SigResult:
    name: str
    family: str
    nist_level: int
    pq: bool
    notes: str
    message_bytes: int
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    keygen: TimingStats
    sign: TimingStats
    verify: TimingStats

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _time_block(fn, warmup: int, iters: int) -> TimingStats:
    """Run ``fn()`` repeatedly and return robust timing statistics."""
    for _ in range(max(0, warmup)):
        fn()

    samples_ns: List[int] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        samples_ns.append(t1 - t0)

    samples_us = [s / 1000.0 for s in samples_ns]
    median = statistics.median(samples_us)
    mad = statistics.median([abs(s - median) for s in samples_us])
    return TimingStats(
        iterations=iters,
        median_us=median,
        mad_us=mad,
        min_us=min(samples_us),
        max_us=max(samples_us),
        ops_per_sec=1_000_000.0 / median if median > 0 else float("inf"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def benchmark_kem(name: str, *, iters: int = 50, warmup: int = 5) -> KEMResult:
    """Benchmark a single KEM by name."""
    adapter = algorithms.kems()[name]

    # Sample objects once to record real sizes.
    pk, sk = adapter.keygen()
    ct, ss = adapter.encaps(pk)
    ss2 = adapter.decaps(sk, ct)
    if ss != ss2:
        raise RuntimeError(f"{name}: encaps/decaps mismatch (library bug?)")

    keygen_stats = _time_block(adapter.keygen, warmup, iters)
    encaps_stats = _time_block(lambda: adapter.encaps(pk), warmup, iters)
    decaps_stats = _time_block(lambda: adapter.decaps(sk, ct), warmup, iters)

    return KEMResult(
        name=adapter.name,
        family=adapter.family,
        nist_level=adapter.nist_level,
        pq=adapter.pq,
        notes=adapter.notes,
        public_key_bytes=len(pk),
        secret_key_bytes=len(sk),
        ciphertext_bytes=len(ct),
        shared_secret_bytes=len(ss),
        keygen=keygen_stats,
        encaps=encaps_stats,
        decaps=decaps_stats,
    )


def benchmark_signature(
    name: str,
    *,
    message_bytes: int = 32,
    iters: int = 30,
    warmup: int = 3,
) -> SigResult:
    """Benchmark a single signature scheme by name."""
    adapter = algorithms.signatures()[name]

    msg = os.urandom(message_bytes)
    pk, sk = adapter.keygen()
    sig = adapter.sign(sk, msg)
    if not adapter.verify(pk, msg, sig):
        raise RuntimeError(f"{name}: produced signature did not verify")

    # SPHINCS keygen is fast; SPHINCS sign is the slow one. iters are passed
    # straight through - the caller can lower them for the slow schemes.
    keygen_stats = _time_block(adapter.keygen, warmup, iters)
    sign_stats = _time_block(lambda: adapter.sign(sk, msg), warmup, iters)
    verify_stats = _time_block(lambda: adapter.verify(pk, msg, sig), warmup, iters)

    return SigResult(
        name=adapter.name,
        family=adapter.family,
        nist_level=adapter.nist_level,
        pq=adapter.pq,
        notes=adapter.notes,
        message_bytes=message_bytes,
        public_key_bytes=len(pk),
        secret_key_bytes=len(sk),
        signature_bytes=len(sig),
        keygen=keygen_stats,
        sign=sign_stats,
        verify=verify_stats,
    )


def benchmark_all_kems(*, iters: int = 50, warmup: int = 5, only: Optional[List[str]] = None) -> List[KEMResult]:
    names = only if only else algorithms.kem_names()
    return [benchmark_kem(n, iters=iters, warmup=warmup) for n in names]


def benchmark_all_signatures(
    *,
    message_bytes: int = 32,
    iters: int = 30,
    warmup: int = 3,
    only: Optional[List[str]] = None,
    slh_iters: int = 5,
) -> List[SigResult]:
    """Run every signature, using a smaller iter count for SLH-DSA which
    has signing times on the order of seconds."""
    names = only if only else algorithms.signature_names()
    results: List[SigResult] = []
    for n in names:
        i = slh_iters if n.startswith("SLH-DSA") else iters
        w = max(1, slh_iters // 2) if n.startswith("SLH-DSA") else warmup
        results.append(
            benchmark_signature(n, message_bytes=message_bytes, iters=i, warmup=w)
        )
    return results
