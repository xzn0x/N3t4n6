"""
core.utils — Shared utility functions for the Network Forensics Analyzer.

Provides file-system helpers, hashing routines, and validation logic
used across multiple engine modules.
"""

import os
import hashlib


def validate_file_path(file_path: str) -> str:
    """Validate that the supplied path exists and is a readable file.

    Args:
        file_path: Absolute or relative path to the target PCAP file.

    Returns:
        The resolved absolute path string.

    Raises:
        FileNotFoundError: If the path does not point to an existing file.
        PermissionError: If the file exists but is not readable.
    """
    abs_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"No such file: '{abs_path}'")
    if not os.access(abs_path, os.R_OK):
        raise PermissionError(f"Permission denied: '{abs_path}'")
    return abs_path


def compute_md5(data: bytes) -> str:
    """Return the hex-digest MD5 hash of raw bytes.

    Args:
        data: Raw byte content to hash.

    Returns:
        32-character lowercase hex string.
    """
    return hashlib.md5(data).hexdigest()


def compute_sha256(data: bytes) -> str:
    """Return the hex-digest SHA-256 hash of raw bytes.

    Args:
        data: Raw byte content to hash.

    Returns:
        64-character lowercase hex string.
    """
    return hashlib.sha256(data).hexdigest()


def ensure_output_dir(directory: str) -> str:
    """Create the output directory if it does not already exist.

    Args:
        directory: Path to the target output directory.

    Returns:
        The absolute path to the directory.
    """
    abs_dir = os.path.abspath(directory)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def human_readable_bytes(num_bytes: int) -> str:
    """Convert a byte count to a human-readable string (e.g. 1.4 MB).

    Args:
        num_bytes: Integer byte count.

    Returns:
        Formatted string with appropriate unit suffix.
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"
