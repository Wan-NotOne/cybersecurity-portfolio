# ARP Network Device Discovery

**Python · Scapy · Network Security · Public portfolio edition**

## Overview
ARP-based discovery of explicitly authorised lab hosts. Includes strict scope validation, dry-run by default, rate limiting, bounded retries, and deterministic JSON output.

## Security and responsible use
This tool is for an explicitly authorised isolated course laboratory only. It is **not** a general-purpose internet or campus scanner. The included source preserves the original laboratory scope restrictions. Dry-run is the default; `--execute` is required to send packets. Do not modify scope constants or use an unauthorised interface or target.

## Source and testing
- Source: [`src/device_mapper.py`](src/device_mapper.py)
- Unit tests: [`tests/test_device_mapper.py`](tests/test_device_mapper.py)
- Dependency: `pip install -r requirements.txt`
- Offline test command: `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v`
- Safe dry-run: `python3 src/device_mapper.py --scope /path/to/your/authorised/scope.json --output dry-run.json`

A valid, lecturer-authorised lab scope file is required. No original lab scope configuration is bundled in this public edition, to avoid implying that other users are authorised to scan those targets. Unit tests use isolated mocked packets and do not transmit traffic.

## Original coursework findings
The original isolated lab observed two authorised hosts and reported 11/11 tests passing. These are historical coursework results, not a fresh test of this public copy.

## Limitations
A missing ARP response does not establish that a host is offline. Reported scan duration includes application waiting and is not ARP round-trip latency.

## Privacy and provenance
This is a selectively copied public portfolio edition, not the original course submission. Selected original scope, result and Nmap XML evidence is now included under [`evidence/`](evidence/). The original PCAP captures, full original reports and student identifiers are not copied into this curated edition. Historical results are labelled as such. The public copy passed a fresh offline unit-test run and targeted security review on 19 November 2026.

## Published evidence

- [`evidence/scope.json`](evidence/scope.json) — authorised isolated-lab scope (historical configuration; **not** authorisation for readers to run a scan).
- [`evidence/result.json`](evidence/result.json) — recorded output from the original lab.
- [`evidence/nmap-validation.xml`](evidence/nmap-validation.xml) — independent Nmap comparison from the original lab.

These are verbatim copies of selected original coursework evidence, including private Docker lab addresses and timestamps. The owner reported successful SHA-256 verification of the original evidence set. The raw PCAP remains in the original coursework repository and is not mirrored here. No live network scans were run to publish this evidence.
