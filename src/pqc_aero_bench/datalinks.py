"""Civil-aviation datalink specifications.

Each entry captures the public, standards-derived parameters that matter when
deciding whether a cryptographic primitive can be carried on the link:

* ``max_payload_bytes`` - largest user-data payload that fits in a single
  frame/message at the application layer, *before* fragmentation.
* ``net_bitrate_bps`` - effective net throughput available to a single user
  (not the raw on-air rate). For broadcast links such as ADS-B this is the
  per-aircraft slot bandwidth, not the channel capacity.
* ``one_way_latency_ms`` - typical one-way air-ground latency for a single
  frame at light load. SATCOM uses geostationary round-trip / 2.
* ``standard`` - the primary publicly-cited specification.
* ``notes`` - extra context (security implications, scheduling, etc.).

Numbers come from public standards and the open literature; they are
intentionally conservative and meant to characterise *feasibility*, not
to certify a specific avionic implementation. See ``docs/references.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, Any


@dataclass(frozen=True)
class Datalink:
    """Public description of an aviation datalink."""

    name: str
    max_payload_bytes: int
    net_bitrate_bps: float
    one_way_latency_ms: float
    standard: str
    category: str  # 'narrowband' | 'wideband' | 'broadcast' | 'satellite'
    notes: str = ""

    def airtime_ms(self, payload_bytes: int) -> float:
        """Return the on-air time needed to transmit ``payload_bytes``.

        Latency is treated as a fixed per-frame overhead (propagation +
        MAC scheduling) and the payload is sent at ``net_bitrate_bps``.
        Fragmentation overhead is *not* counted here - the analyzer adds
        a per-fragment latency penalty separately.
        """
        bits = payload_bytes * 8
        transmit_ms = (bits / self.net_bitrate_bps) * 1000.0
        return transmit_ms + self.one_way_latency_ms

    def fragments_required(self, payload_bytes: int) -> int:
        """How many maximum-size frames are needed to carry ``payload_bytes``."""
        if payload_bytes <= 0:
            return 0
        return -(-payload_bytes // self.max_payload_bytes)  # ceil-div

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Datalink catalogue
# ---------------------------------------------------------------------------
# References:
#   ACARS         - ARINC 618/620, plain-text Char-6 character air-ground msgs;
#                   typical AGCS uplink/downlink payload <= ~220 bytes.
#   VDL Mode 2    - ARINC 631, ICAO Doc 9776; ~31.5 kbps D8PSK, AVLC frames.
#   ADS-B 1090ES  - RTCA DO-260C; 112-bit Mode-S Extended Squitter (14 bytes,
#                   ~56 bits usable for ADS-B Message Field). Broadcast.
#   LDACS         - EUROCAE ED-228 / ICAO L-band Digital Aeronautical Comm.
#                   System, ~0.5 Mbps net to a single user.
#   SATCOM Classic Aero - ARINC 781 / Inmarsat Classic Aero-H+; 10.5 kbps
#                   packet-mode data; ~1.5 s one-way is dominated by GEO.
#   AeroMACS      - RTCA DO-345 / IEEE 802.16e profile for airport surface;
#                   wideband, low latency, but airport-area only.
DATALINKS: Dict[str, Datalink] = {
    "ACARS-VHF": Datalink(
        name="ACARS-VHF",
        max_payload_bytes=220,
        net_bitrate_bps=2400.0,
        one_way_latency_ms=1500.0,
        standard="ARINC 618 / 620",
        category="narrowband",
        notes=(
            "Plain-text character-oriented air-ground messaging. Payload "
            "ceiling is the operational soft limit observed on Block 1; "
            "physical limit is higher but multi-block messages are "
            "fragmented by the CSP."
        ),
    ),
    "VDL-Mode-2": Datalink(
        name="VDL-Mode-2",
        max_payload_bytes=1023,
        net_bitrate_bps=31500.0,
        one_way_latency_ms=800.0,
        standard="ARINC 631 / ICAO Doc 9776",
        category="narrowband",
        notes=(
            "Primary VHF datalink for ATN/OSI and ATN/IPS Controller-Pilot "
            "Datalink Communications (CPDLC). AVLC INFO field is the "
            "fragmentation unit."
        ),
    ),
    "ADS-B-1090ES": Datalink(
        name="ADS-B-1090ES",
        max_payload_bytes=7,  # 56-bit ADS-B Message Field inside the 112-bit Extended Squitter
        net_bitrate_bps=1_000_000.0,
        one_way_latency_ms=50.0,
        standard="RTCA DO-260C",
        category="broadcast",
        notes=(
            "Each Extended Squitter carries a 56-bit ADS-B Message Field. "
            "Any cryptographic object that does not fit in 7 bytes must be "
            "stitched across many squitters, breaking the 'one frame, one "
            "fact' broadcast model."
        ),
    ),
    "LDACS": Datalink(
        name="LDACS",
        max_payload_bytes=1500,
        net_bitrate_bps=500_000.0,
        one_way_latency_ms=100.0,
        standard="EUROCAE ED-228 / ICAO L-DACS",
        category="wideband",
        notes=(
            "Next-generation L-band digital aeronautical communications "
            "system. PHY supports ~1 Mbps shared; ~0.5 Mbps net per user "
            "is a reasonable budget for a single CPDLC session."
        ),
    ),
    "SATCOM-Classic-Aero": Datalink(
        name="SATCOM-Classic-Aero",
        max_payload_bytes=1960,
        net_bitrate_bps=10_500.0,
        one_way_latency_ms=270.0,
        standard="ARINC 781 (Inmarsat Classic Aero-H+)",
        category="satellite",
        notes=(
            "Geostationary; one-way latency of ~270 ms is propagation-bound. "
            "Packet-mode data session, typical message ceiling around 2 KB."
        ),
    ),
    "AeroMACS": Datalink(
        name="AeroMACS",
        max_payload_bytes=2048,
        net_bitrate_bps=9_000_000.0,
        one_way_latency_ms=20.0,
        standard="RTCA DO-345 / IEEE 802.16e profile",
        category="wideband",
        notes=(
            "Airport-surface wideband. Effectively unconstrained for PQC "
            "from a sizing standpoint; included as the upper-bound "
            "reference case."
        ),
    ),
}


def get(name: str) -> Datalink:
    """Look up a datalink by name (case-insensitive on hyphenation)."""
    key = name.strip()
    if key in DATALINKS:
        return DATALINKS[key]
    # Tolerant lookup
    norm = key.lower().replace("_", "-")
    for k, v in DATALINKS.items():
        if k.lower() == norm:
            return v
    raise KeyError(f"Unknown datalink: {name!r}. Known: {sorted(DATALINKS)}")


def all_datalinks() -> list[Datalink]:
    """Return every catalogued datalink, in catalogue order."""
    return list(DATALINKS.values())
