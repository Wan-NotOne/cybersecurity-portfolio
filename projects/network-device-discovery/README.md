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

A valid, lecturer-authorised lab scope file is required. A lab scope file is not permission to scan networks outside the explicitly authorised environment. Unit tests use isolated mocked packets and do not transmit traffic.

## Results
The lab experiment observed two authorised hosts and reported 11/11 tests passing. These results are supported by the experiment evidence; the current source copy has not yet been retested.

## Limitations
A missing ARP response does not establish that a host is offline. Reported scan duration includes application waiting and is not ARP round-trip latency.

## Evidence
Experiment outputs and independent validation records are kept in the `evidence/` directory. Evidence integrity and safe publication will be checked before release.
