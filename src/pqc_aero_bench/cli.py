"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from . import __version__
from . import algorithms, benchmark, analyzer, plots, report
from .datalinks import DATALINKS


console = Console()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pqc-aero-bench",
        description=(
            "Benchmark NIST post-quantum primitives against civil-aviation "
            "datalink constraints (ACARS, VDL-2, ADS-B, LDACS, SATCOM, AeroMACS)."
        ),
    )
    p.add_argument("--version", action="version", version=f"pqc-aero-bench {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ----- run -----
    run = sub.add_parser("run", help="Run the full benchmark and emit a report.")
    run.add_argument("-o", "--out", type=Path, default=Path("results"),
                     help="Output directory (default: ./results)")
    run.add_argument("--iters", type=int, default=50,
                     help="Iterations per measured op (default: 50)")
    run.add_argument("--message-size", type=int, default=32,
                     help="Bytes hashed/signed in signature benchmarks (default: 32)")
    run.add_argument("--no-plots", action="store_true",
                     help="Skip generating PNG plots.")
    run.add_argument("--no-classical", action="store_true",
                     help="Skip RSA/ECDSA/Ed25519 baselines.")
    run.add_argument("--quick", action="store_true",
                     help="Lower iteration counts for a fast sanity run (~30 s).")
    run.add_argument("--kems", nargs="*", default=None,
                     help="Restrict the KEM set (default: all).")
    run.add_argument("--signatures", nargs="*", default=None,
                     help="Restrict the signature set (default: all).")

    # ----- list -----
    sub.add_parser("list", help="List known algorithms and datalinks.")

    # ----- analyze -----
    an = sub.add_parser("analyze", help="Analyze suitability from a saved JSON report.")
    an.add_argument("json_path", type=Path, help="Path to a previously generated JSON report.")

    return p


def _print_listing() -> None:
    t = Table(title="Aviation datalinks", show_lines=False)
    t.add_column("Name", style="cyan")
    t.add_column("Max payload (B)", justify="right")
    t.add_column("Net rate (kbps)", justify="right")
    t.add_column("Latency (ms)", justify="right")
    t.add_column("Standard")
    for d in DATALINKS.values():
        t.add_row(d.name, str(d.max_payload_bytes),
                  f"{d.net_bitrate_bps/1000:.1f}", f"{d.one_way_latency_ms:.0f}",
                  d.standard)
    console.print(t)

    t = Table(title="Key-encapsulation mechanisms")
    t.add_column("Name", style="cyan")
    t.add_column("Family")
    t.add_column("NIST L", justify="right")
    t.add_column("Notes")
    for k in algorithms.kems().values():
        t.add_row(k.name, k.family, str(k.nist_level), k.notes)
    console.print(t)

    t = Table(title="Signatures")
    t.add_column("Name", style="cyan")
    t.add_column("Family")
    t.add_column("PQ?", justify="center")
    t.add_column("NIST L", justify="right")
    t.add_column("Notes")
    for s in algorithms.signatures().values():
        t.add_row(s.name, s.family, "yes" if s.pq else "no",
                  str(s.nist_level) if s.nist_level else "-", s.notes)
    console.print(t)


def _filter_signatures(only: Optional[List[str]], drop_classical: bool) -> Optional[List[str]]:
    names = list(algorithms.signature_names())
    if only:
        names = [n for n in names if n in only]
    if drop_classical:
        sig_table = algorithms.signatures()
        names = [n for n in names if sig_table[n].pq]
    return names


def _do_run(args: argparse.Namespace) -> int:
    out_dir: Path = args.out
    iters = args.iters
    if args.quick:
        iters = max(5, iters // 5)

    console.rule(f"[bold]pqc-aero-bench v{__version__}")
    console.print(f"Output directory: [bold]{out_dir}[/bold]")
    console.print(f"Iterations per op: [bold]{iters}[/bold]   message size: [bold]{args.message_size}[/bold] B")

    # --- KEMs ---
    console.rule("Benchmarking KEMs")
    kem_names = args.kems if args.kems else algorithms.kem_names()
    kem_results = []
    for n in kem_names:
        console.print(f"  - {n} ...", end="")
        r = benchmark.benchmark_kem(n, iters=iters, warmup=max(2, iters // 10))
        kem_results.append(r)
        console.print(f"  pk={r.public_key_bytes} ct={r.ciphertext_bytes} "
                      f"keygen={r.keygen.median_us:.1f}us encaps={r.encaps.median_us:.1f}us "
                      f"decaps={r.decaps.median_us:.1f}us")

    # --- Signatures ---
    console.rule("Benchmarking signatures")
    sig_names = _filter_signatures(args.signatures, args.no_classical)
    sig_results = []
    slh_iters = max(3, iters // 10)
    for n in sig_names:
        console.print(f"  - {n} ...", end="")
        i = slh_iters if n.startswith("SLH-DSA") else iters
        r = benchmark.benchmark_signature(n, message_bytes=args.message_size,
                                          iters=i, warmup=max(1, i // 5))
        sig_results.append(r)
        console.print(f"  sig={r.signature_bytes}B  sign={r.sign.median_us:.1f}us "
                      f"verify={r.verify.median_us:.1f}us")

    # --- Analyze ---
    console.rule("Analyzing fit against aviation datalinks")
    kem_fits = analyzer.kem_matrix(kem_results)
    sig_fits = analyzer.signature_matrix(sig_results)

    # --- Reports ---
    out_dir.mkdir(parents=True, exist_ok=True)
    data = report.build_json(kem_results, sig_results, kem_fits, sig_fits)
    report.write_json(out_dir / "report.json", data)
    md = report.build_markdown(kem_results, sig_results, kem_fits, sig_fits)
    report.write_markdown(out_dir / "report.md", md)
    console.print(f"  wrote [bold]{out_dir / 'report.json'}[/bold]")
    console.print(f"  wrote [bold]{out_dir / 'report.md'}[/bold]")

    # --- Plots ---
    if not args.no_plots:
        console.rule("Rendering plots")
        plot_dir = out_dir / "plots"
        paths = plots.plot_all(kem_results, sig_results, kem_fits, sig_fits, plot_dir)
        for p in paths:
            console.print(f"  wrote [bold]{p}[/bold]")

    console.rule("[bold green]Done")
    return 0


def _do_analyze(args: argparse.Namespace) -> int:
    import json
    data = json.loads(args.json_path.read_text(encoding="utf-8"))
    table = Table(title=f"Signature fit matrix ({args.json_path})")
    table.add_column("Algorithm")
    table.add_column("Datalink")
    table.add_column("Wire B", justify="right")
    table.add_column("Frags", justify="right")
    table.add_column("Verdict")
    for f in data["signatures"]["fit_matrix"]:
        table.add_row(f["algorithm"], f["datalink"], str(f["wire_bytes"]),
                      str(f["fragments"]), f["verdict"])
    console.print(table)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "list":
        _print_listing()
        return 0
    if args.cmd == "run":
        return _do_run(args)
    if args.cmd == "analyze":
        return _do_analyze(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
