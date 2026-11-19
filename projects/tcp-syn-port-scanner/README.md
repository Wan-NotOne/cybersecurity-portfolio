# TCP SYN Port Scanner

**Python · Scapy · Network Security · Public portfolio edition**

## Overview
Scapy TCP SYN analysis against an exact allow-listed lab target and ports. Includes response correlation, bounded retries, dry-run by default, and explicit RST cleanup.

## Security and responsible use
This tool is for an explicitly authorised isolated course laboratory only. It is **not** a general-purpose internet or campus scanner. The included source preserves the original laboratory scope restrictions. Dry-run is the default; `--execute` is required to send packets. Do not modify scope constants or use an unauthorised interface or target.

## Source and testing
- Source: [`src/tcp_port_scanner.py`](src/tcp_port_scanner.py)
- Unit tests: [`tests/test_tcp_port_scanner.py`](tests/test_tcp_port_scanner.py)
- Dependency: `pip install -r requirements.txt`
- Offline test command: `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v`
- Safe dry-run: `python3 src/tcp_port_scanner.py --scope /path/to/your/authorised/scope.json --output dry-run.json`

A valid, lecturer-authorised lab scope file is required. No original lab scope configuration is bundled in this public edition, to avoid implying that other users are authorised to scan those targets. Unit tests use isolated mocked packets and do not transmit traffic.

## Original coursework findings
The original isolated lab classified four authorised TCP ports as open, agreeing with independent Nmap observations, and reported 16/16 tests passing. These are historical coursework results, not a fresh test of this public copy.

## Limitations
A SYN/ACK does not prove application health. The original packet capture combined Scapy and Nmap traffic, and the origin of some RST packets was not conclusively established.

## Privacy and provenance
This is a selectively copied public portfolio edition, not the original course submission. Selected original scope, result and Nmap XML evidence is now included under [`evidence/`](evidence/). The original PCAP captures, full original reports and student identifiers are not copied into this curated edition. Historical results are labelled as such. The public copy passed a fresh offline unit-test run and targeted security review on 19 November 2026.

## Published evidence

- [`evidence/scope.json`](evidence/scope.json) — authorised isolated-lab scope (historical configuration; **not** authorisation for readers to run a scan).
- [`evidence/result.json`](evidence/result.json) — recorded output from the original lab.
- [`evidence/nmap-validation.xml`](evidence/nmap-validation.xml) — independent Nmap comparison from the original lab.

These are verbatim copies of selected original coursework evidence, including private Docker lab addresses and timestamps. The owner reported successful SHA-256 verification of the original evidence set. The raw PCAP remains in the original coursework repository and is not mirrored here. No live network scans were run to publish this evidence.
