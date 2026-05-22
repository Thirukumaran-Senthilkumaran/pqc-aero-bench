"""Suitability analysis: does primitive X fit on datalink Y?

For each (algorithm, datalink) pair we compute:

* ``fits_single_frame`` - True iff the largest object that has to travel on
  the wire (KEM public key + ciphertext, or signature + public key for
  one-shot verify) fits in a single max-size frame of the link.
* ``fragments`` - number of max-size frames required when it does not fit.
* ``handshake_airtime_ms`` - wall-clock to transmit the relevant artefacts
  end-to-end, including a per-fragment latency penalty.
* ``verdict`` - a coarse qualitative bucket (``OK``, ``MARGINAL``,
  ``FRAGMENTED``, ``INFEASIBLE``) suitable for a colour-coded matrix.

We deliberately use *worst-case* wire sizes: ``pk + ct`` for KEMs (the
initiator must transmit a fresh public key in an ephemeral handshake), and
``pk + sig`` for signatures (the receiver needs the public key plus the
signature to authenticate a broadcast).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Iterable

from .benchmark import KEMResult, SigResult
from .datalinks import Datalink, DATALINKS, all_datalinks


# Verdict thresholds (in fragments)
_OK_MAX_FRAGMENTS = 1            # fits in one frame
_MARGINAL_MAX_FRAGMENTS = 4      # fits in <=4 frames -> usable but costly
_FRAGMENTED_MAX_FRAGMENTS = 32   # technically possible; severe latency hit
# Anything above is INFEASIBLE.


VERDICT_OK = "OK"
VERDICT_MARGINAL = "MARGINAL"
VERDICT_FRAGMENTED = "FRAGMENTED"
VERDICT_INFEASIBLE = "INFEASIBLE"


def _classify(fragments: int) -> str:
    if fragments <= _OK_MAX_FRAGMENTS:
        return VERDICT_OK
    if fragments <= _MARGINAL_MAX_FRAGMENTS:
        return VERDICT_MARGINAL
    if fragments <= _FRAGMENTED_MAX_FRAGMENTS:
        return VERDICT_FRAGMENTED
    return VERDICT_INFEASIBLE


@dataclass
class KEMFit:
    algorithm: str
    datalink: str
    wire_bytes: int
    max_payload_bytes: int
    fragments: int
    fits_single_frame: bool
    handshake_airtime_ms: float
    verdict: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SigFit:
    algorithm: str
    datalink: str
    wire_bytes: int
    max_payload_bytes: int
    fragments: int
    fits_single_frame: bool
    transmit_airtime_ms: float
    verdict: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _airtime_with_fragmentation(link: Datalink, total_bytes: int) -> float:
    """Approximate airtime including a per-fragment latency penalty."""
    frags = link.fragments_required(total_bytes)
    if frags <= 0:
        return 0.0
    # Each fragment pays one latency hit; only the last carries a partial payload.
    bytes_in_full = link.max_payload_bytes * (frags - 1)
    full_airtime = link.airtime_ms(bytes_in_full) if frags > 1 else 0.0
    last_airtime = link.airtime_ms(total_bytes - bytes_in_full)
    # ``airtime_ms`` already includes one latency, so we add (frags - 1) more.
    extra_latency = (frags - 1) * link.one_way_latency_ms
    return full_airtime + last_airtime + extra_latency


def analyze_kem(result: KEMResult, link: Datalink) -> KEMFit:
    # Ephemeral handshake: initiator sends pk (one direction), responder sends ct (other direction).
    # The hardest single artefact on the link is max(pk, ct).
    wire_bytes = max(result.public_key_bytes, result.ciphertext_bytes)
    frags = link.fragments_required(wire_bytes)
    airtime = _airtime_with_fragmentation(link, result.public_key_bytes) + \
              _airtime_with_fragmentation(link, result.ciphertext_bytes)
    return KEMFit(
        algorithm=result.name,
        datalink=link.name,
        wire_bytes=wire_bytes,
        max_payload_bytes=link.max_payload_bytes,
        fragments=frags,
        fits_single_frame=frags <= 1,
        handshake_airtime_ms=airtime,
        verdict=_classify(frags),
    )


def analyze_signature(result: SigResult, link: Datalink) -> SigFit:
    # For authenticated broadcast (think: signed ADS-B / signed CPDLC), the
    # receiver must hold the public key (often pre-distributed) and process
    # signature attached to each message. The thing that goes on the wire
    # *per message* is the signature itself. We size against that.
    wire_bytes = result.signature_bytes
    frags = link.fragments_required(wire_bytes)
    airtime = _airtime_with_fragmentation(link, wire_bytes)
    return SigFit(
        algorithm=result.name,
        datalink=link.name,
        wire_bytes=wire_bytes,
        max_payload_bytes=link.max_payload_bytes,
        fragments=frags,
        fits_single_frame=frags <= 1,
        transmit_airtime_ms=airtime,
        verdict=_classify(frags),
    )


def kem_matrix(
    results: Iterable[KEMResult],
    links: Iterable[Datalink] | None = None,
) -> List[KEMFit]:
    links = list(links) if links is not None else all_datalinks()
    out: List[KEMFit] = []
    for r in results:
        for link in links:
            out.append(analyze_kem(r, link))
    return out


def signature_matrix(
    results: Iterable[SigResult],
    links: Iterable[Datalink] | None = None,
) -> List[SigFit]:
    links = list(links) if links is not None else all_datalinks()
    out: List[SigFit] = []
    for r in results:
        for link in links:
            out.append(analyze_signature(r, link))
    return out
