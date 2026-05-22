"""Publication-quality matplotlib plots.

We use matplotlib only (no seaborn) so the dependency surface stays small
and the figures render identically on CI. The colour palette is colour-blind
friendly (Wong 2011).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .analyzer import KEMFit, SigFit, VERDICT_OK, VERDICT_MARGINAL, VERDICT_FRAGMENTED, VERDICT_INFEASIBLE
from .benchmark import KEMResult, SigResult
from .datalinks import DATALINKS


_WONG = {
    "blue":   "#0072B2",
    "orange": "#E69F00",
    "green":  "#009E73",
    "red":    "#D55E00",
    "purple": "#CC79A7",
    "yellow": "#F0E442",
    "sky":    "#56B4E9",
    "grey":   "#999999",
}

_VERDICT_COLOR = {
    VERDICT_OK:         _WONG["green"],
    VERDICT_MARGINAL:   _WONG["sky"],
    VERDICT_FRAGMENTED: _WONG["orange"],
    VERDICT_INFEASIBLE: _WONG["red"],
}

_VERDICT_ORDER = [VERDICT_OK, VERDICT_MARGINAL, VERDICT_FRAGMENTED, VERDICT_INFEASIBLE]


def _setup_style() -> None:
    plt.rcParams.update({
        "figure.dpi": 110,
        "savefig.dpi": 150,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
    })


# ---------------------------------------------------------------------------
# Size comparison bar charts
# ---------------------------------------------------------------------------
def plot_kem_sizes(results: List[KEMResult], path: Path) -> None:
    _setup_style()
    names = [r.name for r in results]
    pks = [r.public_key_bytes for r in results]
    cts = [r.ciphertext_bytes for r in results]

    x = np.arange(len(names))
    w = 0.35
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(x - w/2, pks, w, label="Public key", color=_WONG["blue"])
    ax.bar(x + w/2, cts, w, label="Ciphertext", color=_WONG["orange"])

    for dl_name in ("ACARS-VHF", "VDL-Mode-2"):
        d = DATALINKS[dl_name]
        ax.axhline(d.max_payload_bytes, ls="--", color=_WONG["grey"], lw=1)
        ax.text(len(names) - 0.5, d.max_payload_bytes, f"  {dl_name} ({d.max_payload_bytes} B)",
                va="bottom", ha="right", fontsize=8, color=_WONG["grey"])

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylabel("Bytes")
    ax.set_title("ML-KEM object sizes vs narrowband datalink ceilings")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_signature_sizes(results: List[SigResult], path: Path) -> None:
    _setup_style()
    # Sort: classical first then PQ, alphabetised within group
    results = sorted(results, key=lambda r: (r.pq, r.family, r.name))
    names = [r.name for r in results]
    sigs = [r.signature_bytes for r in results]
    pks  = [r.public_key_bytes for r in results]
    colors_sig = [_WONG["red"] if r.pq else _WONG["grey"] for r in results]

    x = np.arange(len(names))
    w = 0.4
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w/2, sigs, w, label="Signature", color=colors_sig)
    ax.bar(x + w/2, pks,  w, label="Public key", color=_WONG["blue"], alpha=0.85)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.set_ylabel("Bytes (log scale)")
    ax.set_title("Signature & public-key sizes (red = post-quantum)")

    # Annotate datalink ceilings
    for dl_name, color in (("ACARS-VHF", _WONG["purple"]),
                           ("VDL-Mode-2", _WONG["sky"]),
                           ("LDACS", _WONG["green"])):
        d = DATALINKS[dl_name]
        ax.axhline(d.max_payload_bytes, ls="--", color=color, lw=1)
        ax.text(len(names) - 0.5, d.max_payload_bytes,
                f"  {dl_name} ({d.max_payload_bytes} B)",
                va="bottom", ha="right", fontsize=8, color=color)

    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Verdict heat-map
# ---------------------------------------------------------------------------
def _verdict_index(v: str) -> int:
    return _VERDICT_ORDER.index(v)


def plot_fit_matrix(fits: List, path: Path, *, title: str) -> None:
    """Render an algorithm x datalink heat map of verdicts."""
    _setup_style()
    algorithms: List[str] = []
    datalinks: List[str] = []
    pairs = {}
    for f in fits:
        if f.algorithm not in algorithms:
            algorithms.append(f.algorithm)
        if f.datalink not in datalinks:
            datalinks.append(f.datalink)
        pairs[(f.algorithm, f.datalink)] = f

    Z = np.zeros((len(algorithms), len(datalinks)), dtype=int)
    for i, alg in enumerate(algorithms):
        for j, dl in enumerate(datalinks):
            Z[i, j] = _verdict_index(pairs[(alg, dl)].verdict)

    cmap = matplotlib.colors.ListedColormap([_VERDICT_COLOR[v] for v in _VERDICT_ORDER])
    fig, ax = plt.subplots(figsize=(1.4 * len(datalinks) + 3, 0.45 * len(algorithms) + 2))
    im = ax.imshow(Z, aspect="auto", cmap=cmap, vmin=0, vmax=len(_VERDICT_ORDER) - 1)
    ax.set_xticks(range(len(datalinks)))
    ax.set_xticklabels(datalinks, rotation=30, ha="right")
    ax.set_yticks(range(len(algorithms)))
    ax.set_yticklabels(algorithms)
    ax.set_title(title)

    # Annotate each cell with fragment count
    for i, alg in enumerate(algorithms):
        for j, dl in enumerate(datalinks):
            f = pairs[(alg, dl)]
            ax.text(j, i, f"{f.fragments}", ha="center", va="center",
                    color="white" if Z[i, j] >= 2 else "black", fontsize=9, fontweight="bold")

    # Colour-bar as discrete legend
    from matplotlib.patches import Patch
    legend = [Patch(facecolor=_VERDICT_COLOR[v], label=v) for v in _VERDICT_ORDER]
    ax.legend(handles=legend, bbox_to_anchor=(1.02, 1), loc="upper left",
              frameon=False, fontsize=9)

    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Airtime bar chart
# ---------------------------------------------------------------------------
def plot_signature_airtime(fits: List[SigFit], path: Path) -> None:
    """For each datalink, plot per-signature transmit airtime."""
    _setup_style()
    algorithms: List[str] = []
    datalinks: List[str] = []
    for f in fits:
        if f.algorithm not in algorithms:
            algorithms.append(f.algorithm)
        if f.datalink not in datalinks:
            datalinks.append(f.datalink)

    fig, ax = plt.subplots(figsize=(10, 5))
    bar_w = 0.8 / len(datalinks)
    x = np.arange(len(algorithms))
    palette = [_WONG["blue"], _WONG["orange"], _WONG["green"], _WONG["red"],
               _WONG["purple"], _WONG["sky"], _WONG["grey"]]
    for k, dl in enumerate(datalinks):
        ys = [next(f.transmit_airtime_ms for f in fits if f.algorithm == a and f.datalink == dl)
              for a in algorithms]
        ax.bar(x + (k - len(datalinks)/2) * bar_w + bar_w/2, ys, bar_w,
               label=dl, color=palette[k % len(palette)])

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=35, ha="right")
    ax.set_ylabel("Signature transmit airtime (ms, log scale)")
    ax.set_title("Per-signature transmit time across aviation datalinks")
    ax.legend(frameon=False, fontsize=8, loc="upper left", ncol=2)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Compute speed
# ---------------------------------------------------------------------------
def plot_signature_speed(results: List[SigResult], path: Path) -> None:
    _setup_style()
    results = sorted(results, key=lambda r: (r.pq, r.family, r.name))
    names = [r.name for r in results]
    signs = [r.sign.median_us for r in results]
    verifs = [r.verify.median_us for r in results]

    x = np.arange(len(names))
    w = 0.4
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w/2, signs, w, label="Sign",   color=_WONG["red"])
    ax.bar(x + w/2, verifs, w, label="Verify", color=_WONG["blue"])
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=35, ha="right")
    ax.set_ylabel("Median time (us, log scale)")
    ax.set_title("Signature scheme compute cost (per operation)")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_all(
    kem_results: List[KEMResult],
    sig_results: List[SigResult],
    kem_fits: List[KEMFit],
    sig_fits: List[SigFit],
    out_dir: Path,
) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: List[Path] = []

    p = out_dir / "kem_sizes.png"
    plot_kem_sizes(kem_results, p); paths.append(p)

    p = out_dir / "signature_sizes.png"
    plot_signature_sizes(sig_results, p); paths.append(p)

    p = out_dir / "signature_speed.png"
    plot_signature_speed(sig_results, p); paths.append(p)

    p = out_dir / "kem_fit_matrix.png"
    plot_fit_matrix(kem_fits, p, title="KEM fit on aviation datalinks (max(pk,ct))")
    paths.append(p)

    p = out_dir / "signature_fit_matrix.png"
    plot_fit_matrix(sig_fits, p, title="Signature fit on aviation datalinks (sig)")
    paths.append(p)

    p = out_dir / "signature_airtime.png"
    plot_signature_airtime(sig_fits, p); paths.append(p)

    return paths
