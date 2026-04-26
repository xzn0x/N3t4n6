"""
ui.display — Rich-powered terminal display components.

Centralises all terminal output so the engine modules remain
UI-agnostic.  Every public function accepts plain data structures
and renders them with ``rich`` tables, panels, and progress bars.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich import box

from core.utils import human_readable_bytes

# Shared console instance
console = Console()


# ---------------------------------------------------------------------------
# Branding
# ---------------------------------------------------------------------------

BANNER = r"""[bold cyan]
 ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
 ██╔██╗ ██║█████╗     ██║   █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
 ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
 ██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
[/bold cyan]
[dim]  ─── Automated Network Forensics & Protocol Analyzer ───[/dim]
[dim italic]  v1.0.0  •  Powered by tshark + pyshark[/dim italic]
"""


def print_banner() -> None:
    """Render the ASCII art banner to the terminal."""
    console.print(BANNER)


# ---------------------------------------------------------------------------
# Phase 1 — Triage Summary
# ---------------------------------------------------------------------------

def print_triage_summary(
    file_path: str,
    file_size: int,
    total_packets: int,
    start_time: str | None,
    end_time: str | None,
) -> None:
    """Render the capture-file metadata panel.

    Args:
        file_path:     Path to the analysed file.
        file_size:     Size in bytes.
        total_packets: Total packets processed.
        start_time:    First-packet timestamp or None.
        end_time:      Last-packet timestamp or None.
    """
    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold bright_white", min_width=20)
    info.add_column("Value", style="cyan")

    info.add_row("📄  Capture File", file_path)
    info.add_row("📦  File Size", human_readable_bytes(file_size))
    info.add_row("📊  Total Packets", f"{total_packets:,}")
    info.add_row("🕐  First Packet", start_time or "N/A")
    info.add_row("🕑  Last Packet", end_time or "N/A")

    panel = Panel(
        info,
        title="[bold bright_white]📋  CAPTURE OVERVIEW[/bold bright_white]",
        border_style="bright_cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 2),
    )
    console.print()
    console.print(panel)


def print_top_talkers(talkers: List[Tuple[str, int]], total_packets: int) -> None:
    """Render the Top-N IP Talkers table.

    Args:
        talkers:       List of ``(ip_address, packet_count)`` tuples,
                       already sorted in descending order.
        total_packets: Used to compute the traffic-share percentage.
    """
    table = Table(
        title="🔝  Top IP Talkers",
        title_style="bold bright_yellow",
        box=box.ROUNDED,
        border_style="bright_yellow",
        header_style="bold bright_white on grey23",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("IP Address", min_width=20)
    table.add_column("Packets", justify="right", min_width=10)
    table.add_column("Share", justify="right", min_width=10)
    table.add_column("Bar", min_width=25)

    total = total_packets or 1
    max_count = talkers[0][1] if talkers else 1

    for rank, (ip, count) in enumerate(talkers, start=1):
        pct = (count / total) * 100
        bar_len = int((count / max_count) * 20)
        bar = Text("█" * bar_len, style="bright_yellow") + Text(
            "░" * (20 - bar_len), style="grey50"
        )
        table.add_row(str(rank), ip, f"{count:,}", f"{pct:.1f}%", bar)

    console.print()
    console.print(table)


def print_protocol_breakdown(
    transport: Dict[str, float],
    application: Dict[str, float],
) -> None:
    """Render the protocol distribution tables (transport + application).

    Args:
        transport:   ``{protocol: percentage}`` for transport-layer protocols.
        application: ``{protocol: percentage}`` for application-layer protocols.
    """
    # -- Transport layer table ---------------------------------------------
    t_table = Table(
        title="🔌  Transport-Layer Breakdown",
        title_style="bold bright_magenta",
        box=box.ROUNDED,
        border_style="bright_magenta",
        header_style="bold bright_white on grey23",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    t_table.add_column("Protocol", min_width=12)
    t_table.add_column("Share", justify="right", min_width=10)
    t_table.add_column("Bar", min_width=30)

    for proto, pct in transport.items():
        bar_len = int(pct / 5)  # scale: 20 chars = 100 %
        bar = Text("█" * bar_len, style="bright_magenta") + Text(
            "░" * (20 - bar_len), style="grey50"
        )
        t_table.add_row(proto, f"{pct:.1f}%", bar)

    console.print()
    console.print(t_table)

    # -- Application layer table -------------------------------------------
    a_table = Table(
        title="🌐  Application-Layer Breakdown",
        title_style="bold bright_green",
        box=box.ROUNDED,
        border_style="bright_green",
        header_style="bold bright_white on grey23",
        row_styles=["", "dim"],
        padding=(0, 1),
    )
    a_table.add_column("Protocol", min_width=12)
    a_table.add_column("Share", justify="right", min_width=10)
    a_table.add_column("Bar", min_width=30)

    for proto, pct in application.items():
        bar_len = int(pct / 5)
        bar = Text("█" * bar_len, style="bright_green") + Text(
            "░" * (20 - bar_len), style="grey50"
        )
        a_table.add_row(proto, f"{pct:.1f}%", bar)

    console.print()
    console.print(a_table)


# ---------------------------------------------------------------------------
# Phase 2 — Flags & Decoded Strings
# ---------------------------------------------------------------------------

def print_flag_matches(flags: list) -> None:
    """Render discovered CTF flag matches in a success-themed table.

    Args:
        flags: List of :class:`core.decoder.FlagMatch` instances.
    """
    if not flags:
        return

    # Outer success panel wrapping the table
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="bright_green",
        header_style="bold bright_white on dark_green",
        row_styles=["", "dim"],
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("Pkt", justify="right", width=6)
    table.add_column("Source IP", min_width=16)
    table.add_column("Dest IP", min_width=16)
    table.add_column("Protocol", min_width=8)
    table.add_column("Layer", min_width=12)
    table.add_column("Flag / Match", min_width=30, style="bold bright_green")

    for idx, flag in enumerate(flags, start=1):
        table.add_row(
            str(idx),
            str(flag.packet_number),
            flag.source_ip,
            flag.dest_ip,
            flag.protocol,
            flag.layer_source,
            flag.matched_text,
        )

    panel = Panel(
        table,
        title="[bold bright_green]🏁  FLAG MATCHES FOUND[/bold bright_green]",
        border_style="bright_green",
        box=box.DOUBLE_EDGE,
        padding=(1, 1),
    )
    console.print()
    console.print(panel)


def print_decoded_strings(decoded: list) -> None:
    """Render auto-decoded strings in a styled table.

    Args:
        decoded: List of :class:`core.decoder.DecodedString` instances.
    """
    if not decoded:
        return

    # Encoding badge colours
    _ENC_STYLES = {
        "Base64": "bold bright_cyan",
        "Hex": "bold bright_yellow",
        "URL-Encoded": "bold bright_magenta",
        "Plaintext": "dim",
    }

    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="bright_cyan",
        header_style="bold bright_white on grey23",
        row_styles=["", "dim"],
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("Pkt", justify="right", width=6)
    table.add_column("Encoding", min_width=12)
    table.add_column("Layer", min_width=14)
    table.add_column("Encoded Value", min_width=25, max_width=45, overflow="ellipsis")
    table.add_column("Decoded Value", min_width=25, max_width=50, style="bold bright_white")

    for idx, ds in enumerate(decoded, start=1):
        enc_label = ds.encoding.value
        enc_style = _ENC_STYLES.get(enc_label, "")
        table.add_row(
            str(idx),
            str(ds.packet_number),
            Text(enc_label, style=enc_style),
            ds.layer_source,
            ds.encoded_value,
            ds.decoded_value,
        )

    panel = Panel(
        table,
        title="[bold bright_cyan]🔓  AUTO-DECODED STRINGS[/bold bright_cyan]",
        border_style="bright_cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 1),
    )
    console.print()
    console.print(panel)


def print_no_results_notice(category: str) -> None:
    """Print a dim notice when a scan finds no results.

    Args:
        category: Label like 'Flags' or 'Decoded Strings'.
    """
    console.print(f"  [dim]ℹ  No {category} found in this capture.[/dim]")


# ---------------------------------------------------------------------------
# Progress bar helper
# ---------------------------------------------------------------------------

def create_progress() -> Progress:
    """Return a pre-configured ``rich.progress.Progress`` instance.

    The progress bar is designed for indeterminate-length iteration
    (we don't know the packet count ahead of time), so we show a
    spinner + elapsed time instead of a percentage bar.
    """
    return Progress(
        SpinnerColumn(spinner_name="dots12", style="bright_cyan"),
        TextColumn("[bold bright_white]{task.description}"),
        BarColumn(bar_width=40, style="grey50", complete_style="bright_cyan"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# ---------------------------------------------------------------------------
# Phase 3 — Extracted Artifacts
# ---------------------------------------------------------------------------

def print_extracted_artifacts(files: list, output_dir: str) -> None:
    """Render a table of successfully carved files.

    Args:
        files:      List of :class:`core.extractor.ExtractedFile`.
        output_dir: Directory where files were saved.
    """
    if not files:
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="bright_magenta",
        header_style="bold bright_white on grey23",
        row_styles=["", "dim"],
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("Pkt", justify="right", width=6)
    table.add_column("Filename", min_width=20, style="bold bright_white")
    table.add_column("Size", justify="right", min_width=10)
    table.add_column("Content-Type", min_width=20)
    table.add_column("MD5 Hash", style="cyan", min_width=32, max_width=32)

    for idx, f in enumerate(files, start=1):
        table.add_row(
            str(idx),
            str(f.packet_number),
            f.filename,
            human_readable_bytes(f.size),
            f.content_type,
            f.md5_hash,
        )

    panel = Panel(
        table,
        title="[bold bright_magenta]📁  EXTRACTED ARTIFACTS[/bold bright_magenta]",
        subtitle=f"[dim]Saved to: {output_dir}[/dim]",
        border_style="bright_magenta",
        box=box.DOUBLE_EDGE,
        padding=(1, 1),
    )
    console.print()
    console.print(panel)


# ---------------------------------------------------------------------------
# Alerts & status messages
# ---------------------------------------------------------------------------

def print_success(message: str) -> None:
    """Print a bright-green success panel."""
    console.print(
        Panel(
            f"[bold bright_green]{message}[/bold bright_green]",
            border_style="bright_green",
            box=box.HEAVY,
            title="[bold bright_green]✅  SUCCESS[/bold bright_green]",
        )
    )


def print_warning(message: str) -> None:
    """Print a yellow warning panel."""
    console.print(
        Panel(
            f"[bold yellow]{message}[/bold yellow]",
            border_style="yellow",
            box=box.HEAVY,
            title="[bold yellow]⚠️   WARNING[/bold yellow]",
        )
    )


def print_error(message: str) -> None:
    """Print a red error panel."""
    console.print(
        Panel(
            f"[bold bright_red]{message}[/bold bright_red]",
            border_style="bright_red",
            box=box.HEAVY,
            title="[bold bright_red]❌  ERROR[/bold bright_red]",
        )
    )


def print_info(message: str) -> None:
    """Print a dim info line."""
    console.print(f"  [dim]ℹ  {message}[/dim]")


def print_section_header(title: str) -> None:
    """Print a prominent section divider."""
    console.print()
    console.rule(f"[bold bright_white] {title} ", style="bright_cyan")
    console.print()
