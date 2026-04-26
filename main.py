#!/usr/bin/env python3
"""
NetForensics — Automated Network Forensics & Protocol Analyzer.

Entry-point CLI that orchestrates the full analysis pipeline:
  Phase 1 – Engine Initialisation & Triage
  Phase 2 – Payload Scanning & Auto-Decoding
  Phase 3 – Automated Artifact Extraction
  Phase 4 – Threat Intel & Suspicious Traffic   (coming soon)

Usage:
    python main.py -f capture.pcap
    python main.py --file capture.pcapng --regex "CTF{.*?}"
"""

from __future__ import annotations

import argparse
import sys

from ui.display import (
    console,
    create_progress,
    print_banner,
    print_decoded_strings,
    print_error,
    print_extracted_artifacts,
    print_flag_matches,
    print_info,
    print_no_results_notice,
    print_section_header,
    print_triage_summary,
    print_top_talkers,
    print_protocol_breakdown,
    print_success,
)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser.

    Returns:
        A fully configured ``argparse.ArgumentParser``.
    """
    parser = argparse.ArgumentParser(
        prog="N3t4n6",
        description=(
            "Automated Network Forensics & Protocol Analyzer  —  "
            "Ingest PCAP/PCAPNG files, triage traffic, decode hidden "
            "payloads, extract artifacts, and surface threats."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -f capture.pcap\n"
            "  python main.py --file capture.pcapng -r \"flag{.*?}\"\n"
        ),
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="PCAP",
        help="Path to a PCAP or PCAPNG capture file to analyse.",
    )
    parser.add_argument(
        "-r", "--regex",
        default=r"flag\{.*?\}",
        metavar="PATTERN",
        help=(
            "Regex pattern used to scan payloads for CTF flags. "
            "Default: flag{.*?}"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default="./extracted_artifacts",
        metavar="DIR",
        help="Directory for extracted artifacts (default: ./extracted_artifacts).",
    )
    return parser


# ---------------------------------------------------------------------------
# Phase 1 — Engine Initialisation & Triage
# ---------------------------------------------------------------------------

def run_phase1(pcap_path: str) -> None:
    """Execute Phase 1: parse the PCAP and render the triage summary.

    Args:
        pcap_path: Path to the capture file.
    """
    # Lazy import so startup errors surface clearly
    try:
        from core.parser import PcapParser
    except ImportError as exc:
        print_error(f"Missing dependency: {exc}")
        sys.exit(1)

    print_section_header("PHASE 1 — ENGINE INITIALISATION & TRIAGE")

    # -- Parse with a live progress bar ------------------------------------
    parser = PcapParser(pcap_path)
    progress = create_progress()

    with progress:
        task_id = progress.add_task(
            "Parsing packets…",
            total=None,  # indeterminate — we don't know packet count yet
        )

        def _on_packet(pkt_num: int) -> None:
            progress.update(task_id, completed=pkt_num)

        stats = parser.run_triage(progress_callback=_on_packet)

        # Finalise the progress bar
        progress.update(
            task_id,
            completed=stats.total_packets,
            total=stats.total_packets,
            description="Parsing complete ✓",
        )

    # -- Render triage output -----------------------------------------------
    print_triage_summary(
        file_path=stats.file_path,
        file_size=stats.file_size,
        total_packets=stats.total_packets,
        start_time=stats.start_time,
        end_time=stats.end_time,
    )

    print_top_talkers(
        talkers=stats.top_talkers(5),
        total_packets=stats.total_packets,
    )

    print_protocol_breakdown(
        transport=stats.transport_breakdown(),
        application=stats.protocol_breakdown(),
    )

    print_success(
        f"Triage complete — {stats.total_packets:,} packets analysed."
    )


# ---------------------------------------------------------------------------
# Phase 2 — Payload Scanning & Auto-Decoding
# ---------------------------------------------------------------------------

def run_phase2(pcap_path: str, flag_pattern: str) -> None:
    """Execute Phase 2: scan payloads for flags and decode encoded strings.

    Args:
        pcap_path:    Path to the capture file.
        flag_pattern: Regex pattern for CTF flag hunting.
    """
    import re as _re

    try:
        from core.decoder import PayloadDecoder
    except ImportError as exc:
        print_error(f"Missing dependency: {exc}")
        return

    print_section_header("PHASE 2 — PAYLOAD SCANNING & AUTO-DECODING")

    # Validate the regex pattern before starting
    try:
        _re.compile(flag_pattern)
    except _re.error as exc:
        print_error(f"Invalid regex pattern '{flag_pattern}': {exc}")
        return

    print_info(f"Flag pattern: [bold bright_white]{flag_pattern}[/bold bright_white]")

    decoder = PayloadDecoder(file_path=pcap_path, flag_pattern=flag_pattern)
    progress = create_progress()

    with progress:
        task_id = progress.add_task(
            "Scanning payloads…",
            total=None,
        )

        def _on_packet(pkt_num: int) -> None:
            progress.update(task_id, completed=pkt_num)

        results = decoder.run(progress_callback=_on_packet)

        progress.update(
            task_id,
            completed=results.packets_scanned,
            total=results.packets_scanned,
            description="Scan complete ✓",
        )

    # -- Render results ----------------------------------------------------
    if results.flags:
        print_flag_matches(results.flags)
    else:
        print_no_results_notice("flags matching the pattern")

    if results.decoded_strings:
        print_decoded_strings(results.decoded_strings)
    else:
        print_no_results_notice("encoded/decoded strings")

    # Summary
    total_findings = len(results.flags) + len(results.decoded_strings)
    if total_findings > 0:
        print_success(
            f"Payload scan complete — {len(results.flags)} flag(s), "
            f"{len(results.decoded_strings)} decoded string(s) found."
        )
    else:
        print_info(
            "Payload scan complete — no flags or encoded strings detected."
        )


# ---------------------------------------------------------------------------
# Phase 3 — Automated Artifact Extraction
# ---------------------------------------------------------------------------

def run_phase3(pcap_path: str, output_dir: str) -> None:
    """Execute Phase 3: carve files from HTTP/FTP responses.

    Args:
        pcap_path:  Path to the capture file.
        output_dir: Directory to save the extracted artifacts.
    """
    try:
        from core.extractor import ArtifactExtractor
    except ImportError as exc:
        print_error(f"Missing dependency: {exc}")
        return

    print_section_header("PHASE 3 — AUTOMATED ARTIFACT EXTRACTION")

    extractor = ArtifactExtractor(file_path=pcap_path, output_dir=output_dir)
    progress = create_progress()

    with progress:
        task_id = progress.add_task(
            "Extracting artifacts…",
            total=None,
        )

        def _on_packet(pkt_num: int) -> None:
            progress.update(task_id, completed=pkt_num)

        results = extractor.run(progress_callback=_on_packet)

        progress.update(
            task_id,
            completed=results.packets_scanned,
            total=results.packets_scanned,
            description="Extraction complete ✓",
        )

    # -- Render results ----------------------------------------------------
    if results.files:
        print_extracted_artifacts(results.files, results.output_dir)
        print_success(
            f"Extraction complete — {len(results.files)} file(s) saved to {results.output_dir}."
        )
    else:
        print_no_results_notice("extractable files")
        print_info("Extraction complete — no files carved.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    print_banner()

    args = build_argparser().parse_args()

    # -- Validate dependencies early ----------------------------------------
    try:
        import pyshark  # noqa: F401
    except ImportError:
        print_error(
            "pyshark is not installed.\n"
            "Run:  pip install pyshark"
        )
        sys.exit(1)

    try:
        # Quick tshark reachability check
        import shutil
        if shutil.which("tshark") is None:
            print_error(
                "tshark (Wireshark CLI) is not found on $PATH.\n"
                "Install Wireshark / tshark and try again."
            )
            sys.exit(1)
    except Exception:
        pass  # non-critical; pyshark will surface the error later

    # -- Run phases --------------------------------------------------------
    try:
        run_phase1(args.file)
        run_phase2(args.file, args.regex)
        run_phase3(args.file, args.output)
    except FileNotFoundError as exc:
        print_error(str(exc))
        sys.exit(1)
    except PermissionError as exc:
        print_error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted by user.[/dim]")
        sys.exit(130)
    except Exception as exc:
        print_error(f"Unexpected error during analysis:\n{exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
