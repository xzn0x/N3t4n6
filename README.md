# NetForensics — Automated Network Forensics & Protocol Analyzer

NetForensics is a Command-Line Interface (CLI) tool designed to ingest PCAP/PCAPNG files, automate the triage process for CTF network challenges, decode hidden payloads, extract malicious or suspicious artifacts, and highlight potential threats. 

The project is built with Python 3, using `pyshark` for robust packet parsing (leveraging Wireshark's native protocol dissectors) and `rich` for an interactive, visually stunning terminal UI.

## Features

**Completed Phases:**
* **Phase 1: Engine Initialization & Triage**
  * Single-pass PCAP/PCAPNG parsing with live progress bars.
  * Triage Summary panel showing file metadata and packet counts.
  * Top 5 IP addresses (Talkers) with visual percentage bars.
  * Protocol breakdowns for both Transport and Application layers.
* **Phase 2: Payload Scanning & Auto-Decoding**
  * Regex-based payload scanning for CTF flags (configurable, defaults to `flag{.*?}`).
  * Automated encoding detection and decoding for Base64, Hex, and URL-encoded strings.
  * Deep layer extraction: scans HTTP URIs/bodies/auth headers, DNS TXT records, FTP commands, and raw TCP/UDP data fields.
  * Heuristic filtering and deduplication to suppress false positives.

* **Phase 3: Automated Artifact Extraction (File Carving)**
  * Detects and extracts files from HTTP responses.
  * Automatically calculates MD5 hashes for all carved files.
  * Saves extracted artifacts to an `./extracted_artifacts/` directory.
  * Presents findings in a detailed, styled table (Packet, Filename, Size, Type, Hash).

**Upcoming Phases:**
* **Phase 4: Threat Intelligence & Suspicious Traffic** - Flag suspicious behavior like large DNS queries, ICMP ping sweeps, or cleartext credentials.

## Prerequisites

* **Python 3.7+**
* **tshark / Wireshark:** `pyshark` requires `tshark` to be installed and available on your system `$PATH`.
  * Ubuntu/Debian: `sudo apt install tshark`
  * macOS: `brew install wireshark`
  * Windows: Download from the official Wireshark website.

## Installation

1. Clone or download the repository.
2. Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

*(Note: Depending on your environment, you may need to use `pip install --break-system-packages -r requirements.txt` or install within a virtual environment).*

## Usage

Run `main.py` and provide a capture file using the `-f` or `--file` argument.

```bash
python main.py -f <path_to_pcap>
```

### Options

* `-h, --help`: Show the help message and exit.
* `-f PCAP, --file PCAP`: Path to a PCAP or PCAPNG capture file to analyze (Required).
* `-r PATTERN, --regex PATTERN`: Regex pattern used to scan payloads for CTF flags. (Default: `flag\{.*?\}`).
* `-o DIR, --output DIR`: Directory for extracted artifacts. (Default: `./extracted_artifacts`). *(Used in Phase 3)*

### Examples

**Basic Triage and Scan:**
```bash
python main.py -f capture.pcap
```

**Scan with a custom flag format:**
```bash
python main.py --file capture.pcapng -r "CTF{.*?}"
```

## Project Structure

```
.
├── core/
│   ├── __init__.py
│   ├── decoder.py         # Payload decoding and regex scanning (Phase 2)
│   ├── extractor.py       # File carving (Phase 3)
│   ├── parser.py          # PCAP parsing engine (Phase 1)
│   ├── threat_intel.py    # Threat detection (Phase 4 - Upcoming)
│   └── utils.py           # Shared utilities (hashing, file validation)
├── ui/
│   ├── __init__.py
│   └── display.py         # Rich terminal UI components
├── main.py                # CLI entry point
└── requirements.txt       # Python dependencies
```

## Architecture Notes
* **Memory Efficiency:** Uses `pyshark` in stream mode (`keep_packets=False`) to handle large capture files without exhausting RAM.
* **UI-Agnostic Core:** The core engine modules return plain data structures (like `dataclasses`), keeping all terminal rendering isolated in the `ui` module.
