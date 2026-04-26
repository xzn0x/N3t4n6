"""
core.extractor — Automated artifact extraction and file carving.

Detects file transfers in network traffic (e.g., HTTP responses)
and extracts the raw bytes to a local directory. Computes hashes
for the extracted artifacts.
"""

from __future__ import annotations

import mimetypes
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

import pyshark

from core.utils import compute_md5, ensure_output_dir, validate_file_path


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ExtractedFile:
    """Represents a file carved from the network capture.

    Attributes:
        filename:       The extracted or generated file name.
        file_path:      Absolute path to where the file was saved.
        size:           Size of the file in bytes.
        md5_hash:       MD5 hash of the file contents.
        content_type:   MIME type (if known).
        source_ip:      Source IP of the packet providing the file.
        dest_ip:        Destination IP.
        packet_number:  1-based index of the packet in the capture.
    """
    filename: str
    file_path: str
    size: int
    md5_hash: str
    content_type: str
    source_ip: str
    dest_ip: str
    packet_number: int


@dataclass
class ExtractorResults:
    """Aggregated results from the artifact extraction pass.

    Attributes:
        files:           List of successfully extracted files.
        packets_scanned: Total number of packets inspected.
        output_dir:      Directory where files were saved.
    """
    files: List[ExtractedFile] = field(default_factory=list)
    packets_scanned: int = 0
    output_dir: str = ""


# ---------------------------------------------------------------------------
# Extractor class
# ---------------------------------------------------------------------------

class ArtifactExtractor:
    """Carve files from PCAP payloads and save them to disk.

    Usage::

        extractor = ArtifactExtractor("/path/to/capture.pcap", "./out")
        results = extractor.run(progress_callback=some_fn)

    Iterates through the capture, targeting HTTP responses (and potentially
    FTP data) to dump binary file content. Computes MD5 hashes for each.
    """

    def __init__(self, file_path: str, output_dir: str) -> None:
        """Initialise the extractor.

        Args:
            file_path:  Absolute path to the capture file.
            output_dir: Directory where carved files will be stored.
        """
        self.file_path = validate_file_path(file_path)
        self.output_dir = ensure_output_dir(output_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, progress_callback=None) -> ExtractorResults:
        """Execute the extraction pass.

        Args:
            progress_callback: Optional ``(packet_number: int) -> None``.

        Returns:
            Populated :class:`ExtractorResults`.
        """
        results = ExtractorResults(output_dir=self.output_dir)

        # We process all packets so the progress bar aligns with previous phases.
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

        return results

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process_packet(self, pkt_num: int, packet, results: ExtractorResults) -> None:
        """Identify and extract files from a single packet."""
        try:
            src_ip = str(packet.ip.src)
            dst_ip = str(packet.ip.dst)
        except AttributeError:
            try:
                src_ip = str(packet.ipv6.src)
                dst_ip = str(packet.ipv6.dst)
            except AttributeError:
                src_ip, dst_ip = "N/A", "N/A"

        # -- HTTP extraction --
        if hasattr(packet, 'http'):
            self._extract_http_file(pkt_num, packet, src_ip, dst_ip, results)

        # Future extensions could add FTP-DATA, SMB file extraction here.

    def _extract_http_file(
        self, pkt_num: int, packet, src_ip: str, dst_ip: str, results: ExtractorResults
    ) -> None:
        """Extract `file_data` from an HTTP response."""
        http = packet.http

        # Usually responses contain the file data we want.
        # Check if file_data is present.
        if not hasattr(http, 'file_data'):
            return

        # Attempt to get binary data
        raw_bytes = self._get_binary_data(http.file_data)
        if not raw_bytes:
            return

        # Try to determine Content-Type
        content_type = getattr(http, 'content_type', 'application/octet-stream').split(';')[0].strip()

        # Try to guess a filename
        filename = f"pkt_{pkt_num}_extracted"
        
        # 1. Content-Disposition
        if hasattr(http, 'content_disposition'):
            cd = str(http.content_disposition)
            if 'filename=' in cd:
                parts = cd.split('filename=')
                if len(parts) > 1:
                    filename = parts[1].split(';')[0].strip('"\'')

        # 2. Extract from request URI if it's a response to a request we've tracked
        # pyshark sometimes includes request_uri in the response object
        elif hasattr(http, 'request_uri'):
            uri = str(http.request_uri)
            parsed = urllib.parse.urlparse(uri)
            basename = os.path.basename(parsed.path)
            if basename:
                filename = f"pkt_{pkt_num}_{basename}"

        # 3. Add extension if there's no obvious file name and we know the mime type
        if filename.startswith("pkt_") and "." not in filename:
            ext = mimetypes.guess_extension(content_type)
            if ext:
                filename += ext
            elif "text/plain" in content_type:
                filename += ".txt"
            elif "html" in content_type:
                filename += ".html"

        # Ensure the filename is safe and unique
        filename = os.path.basename(filename) # Prevent directory traversal
        if not filename:
            filename = f"pkt_{pkt_num}_file.bin"

        out_path = os.path.join(self.output_dir, filename)
        
        # Uniquify if file exists
        counter = 1
        base, ext = os.path.splitext(filename)
        while os.path.exists(out_path):
            filename = f"{base}_{counter}{ext}"
            out_path = os.path.join(self.output_dir, filename)
            counter += 1

        # Write to disk
        try:
            with open(out_path, 'wb') as f:
                f.write(raw_bytes)
        except IOError:
            return

        # Record the successful extraction
        results.files.append(ExtractedFile(
            filename=filename,
            file_path=out_path,
            size=len(raw_bytes),
            md5_hash=compute_md5(raw_bytes),
            content_type=content_type,
            source_ip=src_ip,
            dest_ip=dst_ip,
            packet_number=pkt_num
        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_binary_data(field_obj) -> bytes | None:
        """Extract robust binary data from a pyshark LayerField.
        
        Pyshark exposes binary data via `binary_value`, `raw_value` (hex string),
        or the fallback string representation (often colon-separated hex).
        """
        if hasattr(field_obj, 'binary_value') and field_obj.binary_value:
            return field_obj.binary_value
            
        if hasattr(field_obj, 'raw_value') and field_obj.raw_value:
            try:
                return bytes.fromhex(field_obj.raw_value)
            except ValueError:
                pass
                
        s_val = str(field_obj)
        if ':' in s_val and len(s_val) > 2:
            try:
                return bytes.fromhex(s_val.replace(":", ""))
            except ValueError:
                pass
                
        # Fallback to UTF-8 encoding of the string representation
        return s_val.encode("utf-8", errors="replace")
