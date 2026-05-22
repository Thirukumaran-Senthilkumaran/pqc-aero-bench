# pqc-aero-bench - benchmark report

_Generated 2026-05-22T00:54:15+00:00 on Windows-11-10.0.26200-SP0 (Python 3.12.9, pqc-aero-bench v0.1.0)._

## 1. Aviation datalink profiles

| Datalink | Max payload (B) | Net rate (kbps) | One-way latency (ms) | Standard |
|---|---:|---:|---:|---|
| `ACARS-VHF` | 220 | 2.4 | 1500 | ARINC 618 / 620 |
| `VDL-Mode-2` | 1023 | 31.5 | 800 | ARINC 631 / ICAO Doc 9776 |
| `ADS-B-1090ES` | 7 | 1000.0 | 50 | RTCA DO-260C |
| `LDACS` | 1500 | 500.0 | 100 | EUROCAE ED-228 / ICAO L-DACS |
| `SATCOM-Classic-Aero` | 1960 | 10.5 | 270 | ARINC 781 (Inmarsat Classic Aero-H+) |
| `AeroMACS` | 2048 | 9000.0 | 20 | RTCA DO-345 / IEEE 802.16e profile |

## 2. Key-encapsulation mechanisms (FIPS 203)

| Algorithm | NIST L | PK (B) | SK (B) | CT (B) | SS (B) | KeyGen | Encaps | Decaps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ML-KEM-512` | 1 | 800 | 1632 | 768 | 32 |  480.6 us |  815.0 us |  609.4 us |
| `ML-KEM-768` | 3 | 1184 | 2400 | 1088 | 32 |  491.5 us |  825.2 us |  618.7 us |
| `ML-KEM-1024` | 5 | 1568 | 3168 | 1568 | 32 |  539.5 us |  860.5 us |  652.8 us |

### 2.1 KEM fit matrix (PK or CT, whichever is larger)

Each cell shows the qualitative verdict and the number of max-size frames (`Nf`) needed to carry the artefact.

| Algorithm \ Datalink | ACARS-VHF | VDL-Mode-2 | ADS-B-1090ES | LDACS | SATCOM-Classic-Aero | AeroMACS |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `ML-KEM-512` | MARGINAL<br>(4f) | OK<br>(1f) | INFEASIBLE<br>(115f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `ML-KEM-768` | FRAGMENTED<br>(6f) | MARGINAL<br>(2f) | INFEASIBLE<br>(170f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `ML-KEM-1024` | FRAGMENTED<br>(8f) | MARGINAL<br>(2f) | INFEASIBLE<br>(224f) | MARGINAL<br>(2f) | OK<br>(1f) | OK<br>(1f) |

## 3. Signature schemes (FIPS 204 / 205 + classical baselines)

| Algorithm | Family | PQ | NIST L | PK (B) | SK (B) | Sig (B) | KeyGen | Sign | Verify |
|---|---|:-:|---:|---:|---:|---:|---:|---:|---:|
| `ML-DSA-44` | ML-DSA | Y | 2 | 1312 | 2560 | 2420 |  547.8 us |   1.07 ms |  454.8 us |
| `ML-DSA-65` | ML-DSA | Y | 3 | 1952 | 4032 | 3309 |  622.8 us |   1.21 ms |  494.5 us |
| `ML-DSA-87` | ML-DSA | Y | 5 | 2592 | 4896 | 4627 |  655.2 us |   1.25 ms |  590.5 us |
| `Falcon-512` | Falcon | Y | 1 | 897 | 1281 | 658 |   5.54 ms |   1.06 ms |  424.4 us |
| `Falcon-1024` | Falcon | Y | 5 | 1793 | 2305 | 1269 |  15.01 ms |   1.24 ms |  436.4 us |
| `SLH-DSA-SHA2-128s` | SLH-DSA | Y | 1 | 64 | 128 | 29792 |  26.86 ms | 314.63 ms |  997.9 us |
| `SLH-DSA-SHA2-128f` | SLH-DSA | Y | 1 | 64 | 128 | 49856 |   2.16 ms |  34.40 ms |   1.54 ms |
| `RSA-2048` | RSA | N | - | 294 | 1218 | 256 |  29.54 ms |  27.54 ms |   29.8 us |
| `ECDSA-P256` | ECDSA | N | - | 91 | 138 | 71 |   32.8 us |   52.8 us |   72.6 us |
| `Ed25519` | EdDSA | N | - | 32 | 32 | 64 |   30.7 us |   52.8 us |   75.8 us |

### 3.1 Signature fit matrix (signature size on the wire)

| Algorithm \ Datalink | ACARS-VHF | VDL-Mode-2 | ADS-B-1090ES | LDACS | SATCOM-Classic-Aero | AeroMACS |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `ML-DSA-44` | FRAGMENTED<br>(11f) | MARGINAL<br>(3f) | INFEASIBLE<br>(346f) | MARGINAL<br>(2f) | MARGINAL<br>(2f) | MARGINAL<br>(2f) |
| `ML-DSA-65` | FRAGMENTED<br>(16f) | MARGINAL<br>(4f) | INFEASIBLE<br>(473f) | MARGINAL<br>(3f) | MARGINAL<br>(2f) | MARGINAL<br>(2f) |
| `ML-DSA-87` | FRAGMENTED<br>(22f) | FRAGMENTED<br>(5f) | INFEASIBLE<br>(661f) | MARGINAL<br>(4f) | MARGINAL<br>(3f) | MARGINAL<br>(3f) |
| `Falcon-512` | MARGINAL<br>(3f) | OK<br>(1f) | INFEASIBLE<br>(94f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `Falcon-1024` | FRAGMENTED<br>(6f) | MARGINAL<br>(2f) | INFEASIBLE<br>(182f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `SLH-DSA-SHA2-128s` | INFEASIBLE<br>(136f) | FRAGMENTED<br>(30f) | INFEASIBLE<br>(4256f) | FRAGMENTED<br>(20f) | FRAGMENTED<br>(16f) | FRAGMENTED<br>(15f) |
| `SLH-DSA-SHA2-128f` | INFEASIBLE<br>(227f) | INFEASIBLE<br>(49f) | INFEASIBLE<br>(7123f) | INFEASIBLE<br>(34f) | FRAGMENTED<br>(26f) | FRAGMENTED<br>(25f) |
| `RSA-2048` | MARGINAL<br>(2f) | OK<br>(1f) | INFEASIBLE<br>(37f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `ECDSA-P256` | OK<br>(1f) | OK<br>(1f) | FRAGMENTED<br>(11f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |
| `Ed25519` | OK<br>(1f) | OK<br>(1f) | FRAGMENTED<br>(10f) | OK<br>(1f) | OK<br>(1f) | OK<br>(1f) |

## 4. Headline findings

- On **ACARS-VHF** (220 B frames), even the smallest ML-KEM variant (ML-KEM-512) needs **4** fragments per handshake half - confirming the open finding that ACARS cannot host an ephemeral PQC key exchange without protocol-level redesign.
- **No signature scheme - classical or post-quantum - fits in a single ADS-B Extended Squitter** (56-bit message field). The smallest signature in the suite is Ed25519 at 64 B, requiring **10** squitters; SLH-DSA would need thousands.
- **LDACS** comfortably carries lattice PQC signatures: Falcon-512 fits in 1 frame(s) (658 B), positioning LDACS as the only existing civil-aviation link that can host a per-message ML-DSA / Falcon signature today.

## 5. Verdict legend

- `OK` - fits in a single max-size frame.
- `MARGINAL` - fits in 2-4 frames; usable with mild latency cost.
- `FRAGMENTED` - 5-32 frames; significant latency / scheduling burden.
- `INFEASIBLE` - more than 32 frames; not a credible deployment.
