"""
core.decoder — Payload scanning and auto-decoding engine.

Scans packet payloads for CTF flags using configurable regex patterns,
and automatically detects + decodes Base64, Hex, and URL-encoded strings
found in HTTP streams and DNS TXT records.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import pyshark


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

class EncodingType(Enum):
    """Supported encoding types for auto-detection."""
    BASE64 = "Base64"
    HEX = "Hex"
    URL = "URL-Encoded"
    PLAINTEXT = "Plaintext"


@dataclass
class FlagMatch:
    """A single regex match found inside a packet payload.

    Attributes:
        packet_number:  1-based index of the packet within the capture.
        matched_text:   The raw string that matched the regex.
        source_ip:      Source IP of the packet (if available).
        dest_ip:        Destination IP of the packet (if available).
        protocol:       Highest-layer protocol name.
        layer_source:   Which layer the match came from (e.g. 'HTTP payload',
                        'TCP data', 'DNS TXT').
    """
    packet_number: int
    matched_text: str
    source_ip: str = "N/A"
    dest_ip: str = "N/A"
    protocol: str = "N/A"
    layer_source: str = "Payload"


@dataclass
class DecodedString:
    """A successfully decoded string extracted from the capture.

    Attributes:
        packet_number:  1-based index of the source packet.
        encoding:       The detected encoding type.
        encoded_value:  The raw encoded string as it appeared in the packet.
        decoded_value:  The decoded plaintext result.
        source_ip:      Source IP of the packet.
        dest_ip:        Destination IP of the packet.
        layer_source:   Context label (e.g. 'HTTP Body', 'DNS TXT Record').
    """
    packet_number: int
    encoding: EncodingType
    encoded_value: str
    decoded_value: str
    source_ip: str = "N/A"
    dest_ip: str = "N/A"
    layer_source: str = "Payload"


@dataclass
class DecoderResults:
    """Aggregated results from the payload scanning and decoding pass.

    Attributes:
        flags:           All regex matches (potential CTF flags).
        decoded_strings: All auto-decoded strings.
        packets_scanned: Total number of packets inspected.
        pattern_used:    The regex pattern that was applied.
    """
    flags: List[FlagMatch] = field(default_factory=list)
    decoded_strings: List[DecodedString] = field(default_factory=list)
    packets_scanned: int = 0
    pattern_used: str = ""


# ---------------------------------------------------------------------------
# Regex patterns for auto-detection
# ---------------------------------------------------------------------------

# Base64: at least 16 chars of valid base64 alphabet, optionally padded.
# Deliberately strict to reduce false positives on random hex/text.
_BASE64_PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/=])'               # negative lookbehind
    r'([A-Za-z0-9+/]{16,}={0,2})'        # body + optional padding
    r'(?![A-Za-z0-9+/=])',               # negative lookahead
)

# Hex: contiguous even-length hex string (≥ 16 chars / 8 bytes).
_HEX_PATTERN = re.compile(
    r'(?<![0-9a-fA-F])'
    r'([0-9a-fA-F]{16,})'
    r'(?![0-9a-fA-F])',
)

# URL-encoded: sequences like %20%41%42 (at least 3 encoded chars).
_URL_ENCODED_PATTERN = re.compile(
    r'((?:%[0-9a-fA-F]{2}){3,})',
)


# ---------------------------------------------------------------------------
# Decoder class
# ---------------------------------------------------------------------------

class PayloadDecoder:
    """Scan PCAP payloads for flags and auto-decode encoded strings.

    Usage::

        decoder = PayloadDecoder(
            file_path="/path/to/capture.pcap",
            flag_pattern=r"flag\\{.*?\\}",
        )
        results = decoder.run(progress_callback=some_fn)

    The decoder makes a **single pass** over the capture using pyshark's
    ``FileCapture`` in stream mode.  For each packet it:

    1.  Extracts textual payload data from known layers (HTTP, DNS TXT,
        raw TCP/UDP data fields).
    2.  Searches for the user-supplied regex pattern (flag hunting).
    3.  Runs auto-detection heuristics for Base64, Hex, and URL-encoded
        strings and attempts decoding.
    """

    def __init__(self, file_path: str, flag_pattern: str = r"flag\{.*?\}") -> None:
        """Initialise the decoder.

        Args:
            file_path:    Absolute path to the capture file.
            flag_pattern: Regex pattern for CTF flag matching.

        Raises:
            re.error: If *flag_pattern* is not valid regex.
        """
        self.file_path = file_path
        self.flag_regex = re.compile(flag_pattern, re.IGNORECASE | re.DOTALL)
        self.flag_pattern = flag_pattern

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, progress_callback=None) -> DecoderResults:
        """Execute the scanning and decoding pass.

        Args:
            progress_callback: Optional ``(packet_number: int) -> None``.

        Returns:
            Populated :class:`DecoderResults`.
        """
        results = DecoderResults(pattern_used=self.flag_pattern)

        cap = pyshark.FileCapture(
            self.file_path,
            keep_packets=False,
        )

        try:
            for pkt_num, packet in enumerate(cap, start=1):
                results.packets_scanned = pkt_num
                self._process_packet(pkt_num, packet, results)
                if progress_callback:
                    progress_callback(pkt_num)
        finally:
            cap.close()

        # De-duplicate flags (same match text from overlapping fields)
        results.flags = self._deduplicate_flags(results.flags)

        # De-duplicate decoded strings (same value from overlapping layers)
        results.decoded_strings = self._deduplicate_decoded(results.decoded_strings)

        return results

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process_packet(
        self,
        pkt_num: int,
        packet,
        results: DecoderResults,
    ) -> None:
        """Extract payloads from a packet and run scanning/decoding."""
        src_ip, dst_ip = self._get_ips(packet)
        protocol = self._get_protocol(packet)

        # Gather (payload_text, layer_label) tuples from the packet
        payloads = self._extract_payloads(packet)

        for payload_text, layer_label in payloads:
            # --- Flag scanning ---
            for match in self.flag_regex.finditer(payload_text):
                results.flags.append(FlagMatch(
                    packet_number=pkt_num,
                    matched_text=match.group(0),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    protocol=protocol,
                    layer_source=layer_label,
                ))

            # --- Auto-decoding ---
            self._try_decode_all(
                pkt_num, payload_text, layer_label,
                src_ip, dst_ip, results,
            )

    # ------------------------------------------------------------------
    # Payload extraction from specific layers
    # ------------------------------------------------------------------

    def _extract_payloads(self, packet) -> List[tuple]:
        """Return a list of ``(text, layer_label)`` from known layers.

        Inspects HTTP bodies/URIs, DNS TXT records, FTP data,
        and raw TCP/UDP payload fields.
        """
        payloads: List[tuple] = []

        # -- HTTP layer -----------------------------------------------------
        payloads.extend(self._extract_http(packet))

        # -- DNS TXT records ------------------------------------------------
        payloads.extend(self._extract_dns_txt(packet))

        # -- FTP layer ------------------------------------------------------
        payloads.extend(self._extract_ftp(packet))

        # -- Raw TCP/UDP data (fallback) ------------------------------------
        payloads.extend(self._extract_raw_data(packet))

        return payloads

    @staticmethod
    def _decode_field(field_obj) -> str:
        """Attempt to decode a pyshark LayerField to a UTF-8 string.
        
        Handles cases where pyshark exposes binary data as a colon-separated
        hex string, a raw_value, or a binary_value.
        """
        if hasattr(field_obj, 'binary_value') and field_obj.binary_value:
            try:
                return field_obj.binary_value.decode("utf-8", errors="replace")
            except Exception:
                pass
                
        if hasattr(field_obj, 'raw_value') and field_obj.raw_value:
            try:
                return bytes.fromhex(field_obj.raw_value).decode("utf-8", errors="replace")
            except Exception:
                pass
                
        s_val = str(field_obj)
        if ':' in s_val and len(s_val) > 2:
            try:
                return bytes.fromhex(s_val.replace(":", "")).decode("utf-8", errors="replace")
            except Exception:
                pass
                
        return s_val

    @staticmethod
    def _extract_http(packet) -> List[tuple]:
        """Extract HTTP request URIs, headers, and body content."""
        results: List[tuple] = []
        try:
            http_layer = packet.http
        except AttributeError:
            return results

        # Request URI
        for attr in ("request_full_uri", "request_uri"):
            try:
                uri = getattr(http_layer, attr)
                if uri:
                    results.append((str(uri), "HTTP URI"))
            except AttributeError:
                continue

        # Response body / file data
        for attr in ("file_data", "response_body", "data"):
            try:
                body = getattr(http_layer, attr)
                if body:
                    results.append((PayloadDecoder._decode_field(body), "HTTP Body"))
            except AttributeError:
                continue

        # Authorization header (may contain Base64 creds)
        try:
            auth = http_layer.authorization
            if auth:
                results.append((str(auth), "HTTP Authorization"))
        except AttributeError:
            pass

        # Cookie / Set-Cookie
        for attr in ("cookie", "set_cookie"):
            try:
                val = getattr(http_layer, attr)
                if val:
                    results.append((str(val), f"HTTP {attr.replace('_', '-').title()}"))
            except AttributeError:
                continue

        return results

    @staticmethod
    def _extract_dns_txt(packet) -> List[tuple]:
        """Extract DNS TXT record data."""
        results: List[tuple] = []
        try:
            dns_layer = packet.dns
        except AttributeError:
            return results

        # TXT record data
        for attr in ("txt", "resp_txt", "qry_name"):
            try:
                val = getattr(dns_layer, attr)
                if val:
                    results.append((str(val), f"DNS {attr.upper()}"))
            except AttributeError:
                continue

        return results

    @staticmethod
    def _extract_ftp(packet) -> List[tuple]:
        """Extract FTP command and response lines."""
        results: List[tuple] = []
        try:
            ftp_layer = packet.ftp
        except AttributeError:
            return results

        for attr in ("request_command", "request_arg", "response_arg"):
            try:
                val = getattr(ftp_layer, attr)
                if val:
                    results.append((str(val), f"FTP {attr.replace('_', ' ').title()}"))
            except AttributeError:
                continue

        return results

    @staticmethod
    def _extract_raw_data(packet) -> List[tuple]:
        """Extract raw TCP/UDP payload data fields.

        Checks multiple possible field locations:
        - The ``DATA`` layer's ``data`` field.
        - ``tcp.payload`` / ``tcp.segment_data`` (colon-separated hex).
        - ``udp.payload`` (colon-separated hex).
        """
        results: List[tuple] = []

        # -- DATA layer (explicit raw payload) ------------------------------
        try:
            data_layer = packet.data
            raw = getattr(data_layer, "data", None)
            if raw:
                hex_str = str(raw).replace(":", "")
                try:
                    decoded_bytes = bytes.fromhex(hex_str)
                    text = decoded_bytes.decode("utf-8", errors="replace")
                    results.append((text, "TCP/UDP Data"))
                except (ValueError, UnicodeDecodeError):
                    results.append((hex_str, "TCP/UDP Data (hex)"))
        except AttributeError:
            pass

        # -- TCP payload / segment_data (colon-separated hex) ---------------
        try:
            tcp_layer = packet.tcp
            for attr in ("payload", "segment_data"):
                try:
                    raw_hex = getattr(tcp_layer, attr, None)
                    if raw_hex:
                        hex_str = str(raw_hex).replace(":", "")
                        try:
                            decoded_bytes = bytes.fromhex(hex_str)
                            text = decoded_bytes.decode("utf-8", errors="replace")
                            results.append((text, "TCP Payload"))
                        except (ValueError, UnicodeDecodeError):
                            pass
                except AttributeError:
                    continue
        except AttributeError:
            pass

        # -- UDP payload ----------------------------------------------------
        try:
            udp_layer = packet.udp
            raw_hex = getattr(udp_layer, "payload", None)
            if raw_hex:
                hex_str = str(raw_hex).replace(":", "")
                try:
                    decoded_bytes = bytes.fromhex(hex_str)
                    text = decoded_bytes.decode("utf-8", errors="replace")
                    results.append((text, "UDP Payload"))
                except (ValueError, UnicodeDecodeError):
                    pass
        except AttributeError:
            pass

        return results

    # ------------------------------------------------------------------
    # Auto-decoding logic
    # ------------------------------------------------------------------

    def _try_decode_all(
        self,
        pkt_num: int,
        text: str,
        layer_label: str,
        src_ip: str,
        dst_ip: str,
        results: DecoderResults,
    ) -> None:
        """Attempt Base64, Hex, and URL decoding on *text*."""
        self._try_base64(pkt_num, text, layer_label, src_ip, dst_ip, results)
        self._try_hex(pkt_num, text, layer_label, src_ip, dst_ip, results)
        self._try_url_decode(pkt_num, text, layer_label, src_ip, dst_ip, results)

    def _try_base64(
        self, pkt_num, text, layer, src, dst, results,
    ) -> None:
        """Detect and decode Base64 strings."""
        for match in _BASE64_PATTERN.finditer(text):
            candidate = match.group(1)
            # Must be valid base64 length (multiple of 4 when padded)
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                # Filter: decoded result should be mostly printable ASCII
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_meaningful(decoded_str):
                    results.decoded_strings.append(DecodedString(
                        packet_number=pkt_num,
                        encoding=EncodingType.BASE64,
                        encoded_value=candidate,
                        decoded_value=decoded_str,
                        source_ip=src,
                        dest_ip=dst,
                        layer_source=layer,
                    ))
            except (ValueError, UnicodeDecodeError, base64.binascii.Error):
                continue

    def _try_hex(
        self, pkt_num, text, layer, src, dst, results,
    ) -> None:
        """Detect and decode hex-encoded strings."""
        for match in _HEX_PATTERN.finditer(text):
            candidate = match.group(1)
            if len(candidate) % 2 != 0:
                continue
            try:
                decoded_bytes = bytes.fromhex(candidate)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_meaningful(decoded_str):
                    results.decoded_strings.append(DecodedString(
                        packet_number=pkt_num,
                        encoding=EncodingType.HEX,
                        encoded_value=candidate,
                        decoded_value=decoded_str,
                        source_ip=src,
                        dest_ip=dst,
                        layer_source=layer,
                    ))
            except (ValueError, UnicodeDecodeError):
                continue

    def _try_url_decode(
        self, pkt_num, text, layer, src, dst, results,
    ) -> None:
        """Detect and decode URL-encoded sequences."""
        for match in _URL_ENCODED_PATTERN.finditer(text):
            candidate = match.group(1)
            try:
                decoded_str = urllib.parse.unquote(candidate)
                if decoded_str != candidate and self._is_meaningful(decoded_str):
                    results.decoded_strings.append(DecodedString(
                        packet_number=pkt_num,
                        encoding=EncodingType.URL,
                        encoded_value=candidate,
                        decoded_value=decoded_str,
                        source_ip=src,
                        dest_ip=dst,
                        layer_source=layer,
                    ))
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_meaningful(text: str, min_printable_ratio: float = 0.75) -> bool:
        """Heuristic: is *text* likely a meaningful decoded string?

        Returns True if the string has a sufficient ratio of printable
        ASCII characters and a minimum length.
        """
        if len(text) < 4:
            return False
        printable_count = sum(
            1 for c in text if 32 <= ord(c) <= 126 or c in "\r\n\t"
        )
        return (printable_count / len(text)) >= min_printable_ratio

    @staticmethod
    def _get_ips(packet) -> tuple:
        """Return ``(src_ip, dst_ip)`` or ``('N/A', 'N/A')``."""
        try:
            return str(packet.ip.src), str(packet.ip.dst)
        except AttributeError:
            try:
                return str(packet.ipv6.src), str(packet.ipv6.dst)
            except AttributeError:
                return "N/A", "N/A"

    @staticmethod
    def _get_protocol(packet) -> str:
        """Return the highest-layer protocol name."""
        try:
            return str(packet.highest_layer)
        except AttributeError:
            return "UNKNOWN"

    @staticmethod
    def _deduplicate_flags(items: List[FlagMatch]) -> List[FlagMatch]:
        """Remove duplicate flag matches (same matched text + packet)."""
        seen: set = set()
        unique: List[FlagMatch] = []
        for item in items:
            key = (item.packet_number, item.matched_text)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    @staticmethod
    def _deduplicate_decoded(items: List[DecodedString]) -> List[DecodedString]:
        """Remove duplicate decoded strings (same decoded value + packet)."""
        seen: set = set()
        unique: List[DecodedString] = []
        for item in items:
            key = (item.packet_number, item.decoded_value)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique
