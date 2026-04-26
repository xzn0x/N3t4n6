"""
core.parser — PCAP/PCAPNG parsing engine.

Wraps pyshark to ingest capture files and produce structured triage
statistics: packet counts, top talkers, and protocol distribution.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import pyshark

from core.utils import validate_file_path, human_readable_bytes


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class TriageStats:
    """Aggregated statistics produced by the triage pass over a PCAP.

    Attributes:
        file_path:          Absolute path to the analysed capture file.
        file_size:          Size of the capture file in bytes.
        total_packets:      Number of packets processed.
        ip_counter:         Counter mapping IP addresses → packet counts.
        protocol_counter:   Counter mapping protocol names → packet counts.
        transport_counter:  Counter mapping transport protocols → packet counts.
        start_time:         Timestamp of the first packet (str or None).
        end_time:           Timestamp of the last packet (str or None).
    """
    file_path: str = ""
    file_size: int = 0
    total_packets: int = 0
    ip_counter: Counter = field(default_factory=Counter)
    protocol_counter: Counter = field(default_factory=Counter)
    transport_counter: Counter = field(default_factory=Counter)
    start_time: str | None = None
    end_time: str | None = None

    # -- Derived helpers ----------------------------------------------------

    def top_talkers(self, n: int = 5) -> List[Tuple[str, int]]:
        """Return the *n* most-common IP addresses by packet count."""
        return self.ip_counter.most_common(n)

    def protocol_breakdown(self) -> Dict[str, float]:
        """Return protocol → percentage mapping for display.

        Only protocols that account for ≥ 0.1 % of traffic are included;
        the remainder is folded into an ``Other`` bucket.
        """
        total = self.total_packets or 1  # avoid division by zero
        breakdown: Dict[str, float] = {}
        other = 0.0
        for proto, count in self.protocol_counter.most_common():
            pct = (count / total) * 100
            if pct >= 0.1:
                breakdown[proto] = round(pct, 2)
            else:
                other += pct
        if other > 0:
            breakdown["Other"] = round(other, 2)
        return breakdown

    def transport_breakdown(self) -> Dict[str, float]:
        """Return transport-layer protocol → percentage mapping."""
        total = self.total_packets or 1
        return {
            proto: round((count / total) * 100, 2)
            for proto, count in self.transport_counter.most_common()
        }


# ---------------------------------------------------------------------------
# Parser class
# ---------------------------------------------------------------------------

class PcapParser:
    """High-performance PCAP/PCAPNG parser built on pyshark.

    Usage::

        parser = PcapParser("/path/to/capture.pcap")
        stats  = parser.run_triage()

    The parser iterates through every packet once, collecting IP addresses,
    application-layer protocol names, and transport-layer protocol names.
    """

    # Protocols we specifically track at the application layer
    TRACKED_APP_PROTOCOLS = frozenset({
        "DNS", "HTTP", "TLS", "FTP", "SMTP", "SSH", "DHCP",
        "SNMP", "SMB", "SMB2", "QUIC", "NTP",
    })

    # Protocols we track at the transport layer
    TRACKED_TRANSPORT = frozenset({"TCP", "UDP", "ICMP", "ICMPv6"})

    def __init__(self, file_path: str) -> None:
        """Initialise the parser.

        Args:
            file_path: Path to a PCAP or PCAPNG capture file.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            PermissionError: If the file is not readable.
        """
        self.file_path: str = validate_file_path(file_path)
        self.file_size: int = os.path.getsize(self.file_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_triage(self, progress_callback=None) -> TriageStats:
        """Perform a single-pass triage of the capture file.

        Args:
            progress_callback: Optional callable invoked after each packet
                with ``(packet_number: int)``.  Useful for progress bars.

        Returns:
            A populated :class:`TriageStats` instance.

        Raises:
            pyshark.capture.capture.TSharkNotFoundException:
                If ``tshark`` is not installed or not on ``$PATH``.
            Exception:
                On corrupted / unreadable capture data (caught upstream).
        """
        stats = TriageStats(
            file_path=self.file_path,
            file_size=self.file_size,
        )

        cap = pyshark.FileCapture(
            self.file_path,
            keep_packets=False,   # stream mode — lower memory footprint
        )

        try:
            for pkt_num, packet in enumerate(cap, start=1):
                self._process_packet(packet, stats)
                if progress_callback:
                    progress_callback(pkt_num)
        finally:
            cap.close()

        stats.total_packets = sum(stats.transport_counter.values()) or \
            sum(stats.protocol_counter.values())
        # Recount total from ip_counter in case transport counters are empty
        if stats.total_packets == 0:
            stats.total_packets = pkt_num  # type: ignore[possibly-undefined]

        return stats

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_packet(self, packet, stats: TriageStats) -> None:
        """Extract IP, transport, and application-layer info from *packet*.

        This method is intentionally defensive: any attribute access on the
        pyshark packet object may raise ``AttributeError`` when the layer
        is absent, so every access is wrapped in a try/except.
        """
        # -- Timestamp bookkeeping ------------------------------------------
        try:
            ts = str(packet.sniff_time)
            if stats.start_time is None:
                stats.start_time = ts
            stats.end_time = ts
        except AttributeError:
            pass

        # -- IP layer -------------------------------------------------------
        self._extract_ip(packet, stats)

        # -- Transport layer ------------------------------------------------
        self._extract_transport(packet, stats)

        # -- Application / highest layer ------------------------------------
        self._extract_application(packet, stats)

    @staticmethod
    def _extract_ip(packet, stats: TriageStats) -> None:
        """Record source and destination IPs."""
        try:
            src = packet.ip.src
            dst = packet.ip.dst
            stats.ip_counter[src] += 1
            stats.ip_counter[dst] += 1
        except AttributeError:
            # IPv6 fallback
            try:
                src = packet.ipv6.src
                dst = packet.ipv6.dst
                stats.ip_counter[src] += 1
                stats.ip_counter[dst] += 1
            except AttributeError:
                pass  # Non-IP packet (e.g. ARP)

    @staticmethod
    def _extract_transport(packet, stats: TriageStats) -> None:
        """Record transport-layer protocol (TCP/UDP/ICMP)."""
        for proto_name in PcapParser.TRACKED_TRANSPORT:
            if hasattr(packet, proto_name.lower()):
                stats.transport_counter[proto_name] += 1
                return
        # Fallback — tag as the highest layer if nothing matched
        try:
            highest = packet.highest_layer.upper()
            if highest in PcapParser.TRACKED_TRANSPORT:
                stats.transport_counter[highest] += 1
        except AttributeError:
            pass

    @staticmethod
    def _extract_application(packet, stats: TriageStats) -> None:
        """Record application-layer protocol."""
        try:
            highest = packet.highest_layer.upper()
        except AttributeError:
            return

        # Map to a tracked protocol if possible
        for proto in PcapParser.TRACKED_APP_PROTOCOLS:
            if hasattr(packet, proto.lower()):
                stats.protocol_counter[proto] += 1
                return

        # If the highest layer itself is interesting, count it
        if highest in PcapParser.TRACKED_APP_PROTOCOLS:
            stats.protocol_counter[highest] += 1
        else:
            # Bucket everything else under a generic label
            stats.protocol_counter[highest] += 1
