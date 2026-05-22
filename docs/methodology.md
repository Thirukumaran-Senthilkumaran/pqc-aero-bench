# Methodology

This document describes how `pqc-aero-bench` produces every number in
`results/report.md`. The goal is full reproducibility: anyone with Python ≥
3.10 should be able to clone the repository, run `pytest && python -m
pqc_aero_bench run`, and obtain numbers within statistical noise of the
committed sample run on a comparable machine.

## 1. Sources of truth

| What | Source |
|---|---|
| PQC implementations | [`quantcrypt 1.0.1`](https://pypi.org/project/quantcrypt/), which ships pre-built [PQClean](https://github.com/PQClean/PQClean) wheels |
| Classical implementations | [`cryptography`](https://pypi.org/project/cryptography/) (OpenSSL bindings) |
| Datalink parameters | Public standards cited inline in `src/pqc_aero_bench/datalinks.py` |
| Algorithm metadata (family, NIST level) | NIST FIPS 203 / 204 / 205 and the Falcon submission |

## 2. Object sizes

Sizes are **measured at runtime** by calling the real `keygen`, `encaps` and
`sign` primitives and taking `len()` of the resulting `bytes` objects. There
are no hard-coded size tables. The numbers therefore agree with the version
of the cryptographic library installed at the time of the run.

For signature schemes, the wire artefact whose size matters is the signature
itself (`sig`), because aviation deployments typically pre-distribute public
keys via a PKI. The KEM analyser instead uses `max(pk, ct)` — the largest
single artefact a participant must transmit during an ephemeral handshake.

## 3. Timing protocol

For every measured operation the engine:

1. Runs `warmup` invocations and discards them (JIT, cache warm-up, lazy
   library bindings).
2. Runs `iters` invocations, timing each with
   `time.perf_counter_ns()` (a monotonic, high-resolution clock).
3. Reports the **median** (µs) and the **median absolute deviation** (MAD),
   plus min / max for visibility.

Default `iters = 30`. SLH-DSA signing is special-cased to 3 iterations
because a single op costs ≈ 300 ms.

### Why median + MAD rather than mean + stddev?

PQC signing has heavy-tailed timing distributions. ML-DSA and Falcon both
use rejection sampling: most signs accept on the first try, but a few percent
of attempts produce 2–5× outliers. A handful of cold-cache outliers will
distort a mean and pollute its stddev. Median + MAD is robust to this and
matches what cryptanalysts report in the PQClean benchmark suite.

## 4. Datalink modelling

For each datalink we record three numbers:

- `max_payload_bytes`: largest user payload that fits in a single
  frame/message at the application layer.
- `net_bitrate_bps`: effective per-user net throughput (not the raw on-air
  rate).
- `one_way_latency_ms`: typical air-ground one-way latency for a single
  frame at light load.

These are public, conservative averages from the standards cited in
`src/pqc_aero_bench/datalinks.py` and the open literature. They are
deliberately not optimised for a particular operator. If you need an
operator-specific re-targeting, change the constants and re-run.

### Fragmentation

For an artefact of size `N` bytes on a link with `max_payload_bytes = M`:

```
fragments = ceil(N / M)
airtime   = (N · 8 / bitrate) · 1000 + fragments · one_way_latency_ms
```

That is, each fragment pays one fresh latency hit. This is the right cost
model for half-duplex narrowband links such as ACARS and VDL Mode 2, where
the MAC awards a single slot per latency window.

## 5. Verdict thresholds

The qualitative buckets are defined in `src/pqc_aero_bench/analyzer.py`:

| Fragments | Verdict | Interpretation |
|---:|---|---|
| 1 | `OK` | Fits in a single max-size frame |
| 2–4 | `MARGINAL` | 1–2× latency penalty, generally acceptable for non-time-critical traffic |
| 5–32 | `FRAGMENTED` | Significant scheduling burden; acceptable only for rare events (e.g. log-on, key roll) |
| > 32 | `INFEASIBLE` | Not a credible deployment |

These thresholds are a design choice and are easy to override.

## 6. Reproducibility checklist

- All randomness is provided by the underlying libraries; we do not seed
  RNGs for benchmarking. The *sizes* reported are deterministic; the
  *timings* are not, by design.
- The CI workflow re-runs the entire suite on Ubuntu and Windows for
  Python 3.10 / 3.11 / 3.12 on every push.
- Every committed plot in `results/plots/` was produced by
  `python -m pqc_aero_bench run` with default arguments and is regenerated
  by the same command.
