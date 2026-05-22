# Aviation datalink context

Civil aviation does not have one datalink; it has a layered stack used in
different phases of flight and over different regions. Each link below is
a deployment target for post-quantum public-key cryptography, with its own
hard constraints. The numbers used by `pqc-aero-bench` live in
`src/pqc_aero_bench/datalinks.py`; this document explains where they come
from and what they imply.

## ACARS (Aircraft Communications Addressing and Reporting System)

- **Standards**: ARINC 618 (air-ground), ARINC 620 (ground-ground), ARINC
  724B (avionics interface).
- **Role**: Legacy airline operational and ATC messaging. Used for OOOI
  reports, weather, position uplinks, free-text crew/ATC messages,
  load-sheet uplinks.
- **Frame ceiling**: ~220 bytes per block at the application layer; longer
  messages are fragmented by the Communications Service Provider.
- **Bitrate**: 2 400 bps on VHF Plain Old ACARS (POA); higher in VDL Mode 2
  carriage (see below).
- **Latency**: 1–3 s typical one-way at light load, dominated by store-and-
  forward scheduling. Worst case (oceanic via HF or SATCOM) can exceed
  60 s.
- **Implication for PQC**: ACARS cannot host ephemeral PQC handshakes.
  Even ML-KEM-512 needs ≥ 4 ACARS blocks per direction; 12 s of airtime
  per handshake half. A realistic ACARS PQ deployment uses static,
  pre-distributed PQ keys.

## VDL Mode 2

- **Standards**: ARINC 631, ICAO Doc 9776; AVLC framing (ISO 8208 / X.25
  derivative).
- **Role**: Primary VHF datalink for ATN/OSI and the new ATN/IPS profiles;
  carries CPDLC and ADS-C in continental Europe and the US.
- **Frame ceiling**: 1 023-byte AVLC INFO field is the fragmentation unit.
- **Bitrate**: 31.5 kbps D8PSK on a 25 kHz VHF channel; effective per-user
  rate is lower under load.
- **Latency**: ~0.5–1.0 s one-way.
- **Implication for PQC**: VDL Mode 2 can carry lattice-PQC signatures
  (Falcon-512 fits in a single frame) but ML-DSA forces 2–5 fragments
  depending on parameter set. SLH-DSA is infeasible at the per-message
  level.

## ADS-B 1090ES (Extended Squitter)

- **Standards**: RTCA DO-260C (US), EUROCAE ED-102B (EU); ICAO Annex 10.
- **Role**: Mandatory surveillance broadcast for IFR aircraft in most of
  the world since the 2020 ADS-B Out mandate.
- **Frame ceiling**: The Mode-S Extended Squitter is **112 bits = 14 bytes**
  total; the **ADS-B Message Field** that carries application data is
  **56 bits = 7 bytes**. The remainder is downlink format, capability,
  ICAO address and CRC.
- **Bitrate**: 1 Mbps on the air, but **broadcast** — no scheduling,
  squitter rate per aircraft is fixed (~0.5–2 Hz for position).
- **Latency**: ~50 ms (essentially line-of-sight propagation).
- **Implication for PQC**: No cryptographic signature in current use fits
  in a single squitter. Authenticated ADS-B requires either a redesigned
  L1 (out of scope for civil mandate today) or a separate
  side-channel that carries signatures and ties them to broadcast
  squitters by hash chains. This is exactly the kind of problem this tool
  is built to motivate quantitatively.

## LDACS — L-band Digital Aeronautical Communications System

- **Standards**: EUROCAE ED-228 (currently in draft revisions); ICAO L-DACS
  work programme; SESAR / NextGen targets.
- **Role**: Next-generation air-ground datalink intended to replace VDL
  Mode 2 for continental ATM. Pre-operational trials underway.
- **Frame ceiling**: ~1 500 bytes per LDACS network-layer PDU.
- **Bitrate**: Cell capacity ~1 Mbps; ~500 kbps net per active user is
  typical in the open literature.
- **Latency**: ~50–150 ms one-way.
- **Implication for PQC**: LDACS is the **only currently-planned civil
  aviation datalink that can host per-message lattice PQC signatures
  without protocol-level surgery**. The benchmark consistently flags
  LDACS as the deployment sweet spot for Falcon and ML-DSA.

## SATCOM Classic Aero

- **Standards**: ARINC 781 (Inmarsat Classic Aero-H+); ICAO Annex 10
  Volume III.
- **Role**: Oceanic and remote-area datalink (and voice) for long-haul
  fleets. Carries ACARS, ADS-C and CPDLC over the SwiftBroadband-Safety
  successor service.
- **Frame ceiling**: ~2 KB practical packet payload.
- **Bitrate**: 10.5 kbps packet-mode data on Classic Aero-H+; much higher
  on SwiftBroadband-Safety and Inmarsat Iris.
- **Latency**: ~250–280 ms one-way from a geostationary satellite, almost
  entirely propagation.
- **Implication for PQC**: Comfortable on size for all lattice PQC; the
  binding constraint is round-trip count rather than bytes.

## AeroMACS

- **Standards**: RTCA DO-345; profile of IEEE 802.16e for airport surface;
  ICAO global plan.
- **Role**: Wideband airport-surface datalink for AOC and ATM, e.g.
  pre-departure clearance, terminal-area surveillance.
- **Frame ceiling**: ≥ 2 KB at the MAC layer.
- **Bitrate**: Several Mbps shared per sector.
- **Latency**: <50 ms one-way.
- **Implication for PQC**: Effectively unconstrained on size. Included as
  the upper-bound reference case — if a PQ primitive is too large for
  AeroMACS, it is too large for any aviation datalink, period.
