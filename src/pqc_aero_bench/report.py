"""JSON + Markdown report generation."""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from . import __version__
from .analyzer import KEMFit, SigFit, VERDICT_OK, VERDICT_MARGINAL, VERDICT_FRAGMENTED, VERDICT_INFEASIBLE
from .benchmark import KEMResult, SigResult
from .datalinks import Datalink, DATALINKS


_VERDICT_BADGE = {
    VERDICT_OK: "OK",
    VERDICT_MARGINAL: "MARGINAL",
    VERDICT_FRAGMENTED: "FRAGMENTED",
    VERDICT_INFEASIBLE: "INFEASIBLE",
}


def _env() -> Dict[str, Any]:
    return {
        "tool": "pqc-aero-bench",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def build_json(
    kem_results: List[KEMResult],
    sig_results: List[SigResult],
    kem_fits: List[KEMFit],
    sig_fits: List[SigFit],
) -> Dict[str, Any]:
    return {
        "environment": _env(),
        "datalinks": [d.to_dict() for d in DATALINKS.values()],
        "kem": {
            "results": [r.to_dict() for r in kem_results],
            "fit_matrix": [f.to_dict() for f in kem_fits],
        },
        "signatures": {
            "results": [r.to_dict() for r in sig_results],
            "fit_matrix": [f.to_dict() for f in sig_fits],
        },
    }


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _fmt_us(us: float) -> str:
    if us < 1000:
        return f"{us:6.1f} us"
    if us < 1_000_000:
        return f"{us/1000:6.2f} ms"
    return f"{us/1_000_000:6.2f} s"


def _kem_size_table(results: List[KEMResult]) -> str:
    rows = ["| Algorithm | NIST L | PK (B) | SK (B) | CT (B) | SS (B) | KeyGen | Encaps | Decaps |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        rows.append(
            f"| `{r.name}` | {r.nist_level} | {r.public_key_bytes} | {r.secret_key_bytes} | "
            f"{r.ciphertext_bytes} | {r.shared_secret_bytes} | "
            f"{_fmt_us(r.keygen.median_us)} | {_fmt_us(r.encaps.median_us)} | {_fmt_us(r.decaps.median_us)} |"
        )
    return "\n".join(rows)


def _sig_size_table(results: List[SigResult]) -> str:
    rows = ["| Algorithm | Family | PQ | NIST L | PK (B) | SK (B) | Sig (B) | KeyGen | Sign | Verify |",
            "|---|---|:-:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        rows.append(
            f"| `{r.name}` | {r.family} | {'Y' if r.pq else 'N'} | "
            f"{r.nist_level if r.nist_level else '-'} | "
            f"{r.public_key_bytes} | {r.secret_key_bytes} | {r.signature_bytes} | "
            f"{_fmt_us(r.keygen.median_us)} | {_fmt_us(r.sign.median_us)} | {_fmt_us(r.verify.median_us)} |"
        )
    return "\n".join(rows)


def _matrix(fits: List, *, value_label: str, wire_label: str) -> str:
    """Render an (algorithm x datalink) verdict matrix as a Markdown table."""
    algorithms: List[str] = []
    datalinks: List[str] = []
    by_pair: Dict[tuple[str, str], Any] = {}
    for f in fits:
        if f.algorithm not in algorithms:
            algorithms.append(f.algorithm)
        if f.datalink not in datalinks:
            datalinks.append(f.datalink)
        by_pair[(f.algorithm, f.datalink)] = f

    header = "| Algorithm \\ Datalink | " + " | ".join(datalinks) + " |"
    sep = "|---|" + "|".join([":---:"] * len(datalinks)) + "|"
    out = [header, sep]
    for alg in algorithms:
        cells = []
        for dl in datalinks:
            f = by_pair[(alg, dl)]
            cells.append(f"{_VERDICT_BADGE[f.verdict]}<br>({f.fragments}f)")
        out.append(f"| `{alg}` | " + " | ".join(cells) + " |")
    return "\n".join(out)


def _datalink_table() -> str:
    rows = ["| Datalink | Max payload (B) | Net rate (kbps) | One-way latency (ms) | Standard |",
            "|---|---:|---:|---:|---|"]
    for d in DATALINKS.values():
        rows.append(
            f"| `{d.name}` | {d.max_payload_bytes} | "
            f"{d.net_bitrate_bps/1000:.1f} | {d.one_way_latency_ms:.0f} | {d.standard} |"
        )
    return "\n".join(rows)


def _highlights(kem_fits: List[KEMFit], sig_fits: List[SigFit]) -> str:
    """Auto-generate qualitative bullets from the numeric matrix."""
    lines: List[str] = []

    # KEM headline
    acars_kem = [f for f in kem_fits if f.datalink == "ACARS-VHF"]
    if acars_kem:
        worst = max(acars_kem, key=lambda f: f.fragments)
        best_pq = min(
            (f for f in acars_kem if f.algorithm.startswith("ML-KEM")),
            key=lambda f: f.fragments,
            default=None,
        )
        if best_pq:
            lines.append(
                f"- On **ACARS-VHF** (220 B frames), even the smallest ML-KEM variant "
                f"({best_pq.algorithm}) needs **{best_pq.fragments}** fragments per "
                f"handshake half - confirming the open finding that ACARS cannot host "
                f"an ephemeral PQC key exchange without protocol-level redesign."
            )

    # ADS-B for signatures
    adsb_sig = [f for f in sig_fits if f.datalink == "ADS-B-1090ES"]
    if adsb_sig:
        none_fit = all(not f.fits_single_frame for f in adsb_sig)
        if none_fit:
            smallest = min(adsb_sig, key=lambda f: f.wire_bytes)
            lines.append(
                f"- **No signature scheme - classical or post-quantum - fits in a single "
                f"ADS-B Extended Squitter** (56-bit message field). The smallest "
                f"signature in the suite is {smallest.algorithm} at "
                f"{smallest.wire_bytes} B, requiring **{smallest.fragments}** "
                f"squitters; SLH-DSA would need thousands."
            )

    # LDACS sweet-spot
    ldacs_sig = [f for f in sig_fits if f.datalink == "LDACS"]
    if ldacs_sig:
        ok = [f for f in ldacs_sig if f.verdict in (VERDICT_OK, VERDICT_MARGINAL) and f.algorithm.startswith(("ML-DSA", "Falcon"))]
        if ok:
            cheapest = min(ok, key=lambda f: f.wire_bytes)
            lines.append(
                f"- **LDACS** comfortably carries lattice PQC signatures: "
                f"{cheapest.algorithm} fits in {cheapest.fragments} frame(s) "
                f"({cheapest.wire_bytes} B), positioning LDACS as the only existing "
                f"civil-aviation link that can host a per-message ML-DSA / Falcon "
                f"signature today."
            )

    if not lines:
        lines.append("- See the fit matrices below for the full quantitative picture.")
    return "\n".join(lines)


def build_markdown(
    kem_results: List[KEMResult],
    sig_results: List[SigResult],
    kem_fits: List[KEMFit],
    sig_fits: List[SigFit],
) -> str:
    env = _env()
    parts = []
    parts.append("# pqc-aero-bench - benchmark report\n")
    parts.append(
        f"_Generated {env['generated_utc']} on {env['platform']} "
        f"(Python {env['python']}, pqc-aero-bench v{env['version']})._\n"
    )

    parts.append("## 1. Aviation datalink profiles\n")
    parts.append(_datalink_table() + "\n")

    parts.append("## 2. Key-encapsulation mechanisms (FIPS 203)\n")
    parts.append(_kem_size_table(kem_results) + "\n")
    parts.append("### 2.1 KEM fit matrix (PK or CT, whichever is larger)\n")
    parts.append(
        "Each cell shows the qualitative verdict and the number of "
        "max-size frames (`Nf`) needed to carry the artefact.\n"
    )
    parts.append(_matrix(kem_fits, value_label="frags", wire_label="max(pk,ct)") + "\n")

    parts.append("## 3. Signature schemes (FIPS 204 / 205 + classical baselines)\n")
    parts.append(_sig_size_table(sig_results) + "\n")
    parts.append("### 3.1 Signature fit matrix (signature size on the wire)\n")
    parts.append(_matrix(sig_fits, value_label="frags", wire_label="sig") + "\n")

    parts.append("## 4. Headline findings\n")
    parts.append(_highlights(kem_fits, sig_fits) + "\n")

    parts.append("## 5. Verdict legend\n")
    parts.append(
        "- `OK` - fits in a single max-size frame.\n"
        "- `MARGINAL` - fits in 2-4 frames; usable with mild latency cost.\n"
        "- `FRAGMENTED` - 5-32 frames; significant latency / scheduling burden.\n"
        "- `INFEASIBLE` - more than 32 frames; not a credible deployment.\n"
    )

    return "\n".join(parts)


def write_markdown(path: Path, md: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(md, encoding="utf-8")
