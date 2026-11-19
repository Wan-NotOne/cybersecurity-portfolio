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

A valid, lecturer-authorised lab scope file is required. A lab scope file is not permission to scan networks outside the explicitly authorised environment. Unit tests use isolated mocked packets and do not transmit traffic.

## Results
The lab experiment classified four authorised TCP ports as open, agreeing with independent Nmap observations, and reported 16/16 tests passing. These results are supported by the experiment evidence; the current source copy has not yet been retested.

## Limitations
A SYN/ACK does not prove application health. The original packet capture combined Scapy and Nmap traffic, and the origin of some RST packets was not conclusively established.

## Evidence
Experiment outputs and independent validation records are kept in the `evidence/` directory. Evidence integrity and safe publication will be checked before release.
