# tcp_port_scanner.py: to identify which TCP ports are open, closed, or potentially filtered on an authorised target device using TCP SYN scanning.

import argparse
import ipaddress
import json
import math
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"
EXPECTED_SCOPE_ID = "wqe7002-a1-standard-tcp-syn-scan-v1"
EXPECTED_TARGET = "172.28.70.10"
EXPECTED_PORTS = (22, 80, 443, 8080)
EXPECTED_INTERFACE = "eth0"
MAX_RATE = 20
MAX_ATTEMPTS = 2
MAX_PORTS = 30

def utc_now():
    """Return a timezone-aware UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def load_scope(path):
    """Validate the scope and enforce the exact lecturer-issued allow-list."""
    with open(path, encoding="utf-8") as handle:
        scope = json.load(handle)
        
    if not isinstance(scope, dict):
        raise ValueError("Scope must be a JSON object")

    required = {
        "schema": "wqe7002-recon-scope-v1",
        "scope_id": EXPECTED_SCOPE_ID,
        "option": "tcp-syn-scan",
        "environment": "isolated-course-lab",
        "interface": EXPECTED_INTERFACE,
    }
    for key, expected in required.items():
        if scope.get(key) != expected:
            raise ValueError(f"Invalid or unauthorised scope field: {key}")

    try:
        target = ipaddress.ip_address(scope["target"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Invalid target IPv4 address") from exc
    if target.version != 4 or str(target) != EXPECTED_TARGET:
        raise ValueError("Target is outside the lecturer-authorised scope")

    ports = scope.get("ports")
    if not isinstance(ports, list) or not 1 <= len(ports) <= MAX_PORTS:
        raise ValueError("Ports must be a list of 1 to 30 entries")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("Invalid TCP port number")
    if len(set(ports)) != len(ports):
        raise ValueError("Duplicate TCP port")
    if tuple(sorted(ports)) != EXPECTED_PORTS:
        raise ValueError("Port list differs from the lecturer-authorised scope")

    rate = scope.get("maximum_rate_pps")
    attempts = scope.get("maximum_attempts")
    timeout = scope.get("timeout_seconds")
    if (type(rate) not in (int, float) or not math.isfinite(rate)
            or not 0 < rate <= MAX_RATE):
        raise ValueError("maximum_rate_pps must be between 0 and 20")
    if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
        raise ValueError("maximum_attempts must be 1 or 2")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or timeout <= 0):
        raise ValueError("timeout_seconds must be a positive finite number")

    # Keep the original configuration intact, except for canonical port order.
    return {**scope, "target": str(target), "ports": sorted(ports)}

def build_syn_probe(target_ip, target_port, source_port, sequence, source_ip=None):
    """Construct a TCP SYN packet without transmitting it."""
    from scapy.all import IP, TCP

    ip_fields = {"dst": target_ip}
    if source_ip is not None:
        ip_fields["src"] = source_ip
    return IP(**ip_fields) / TCP(
        sport=source_port,
        dport=target_port,
        flags="S",
        seq=sequence,
    )

def matching_response(response, probe):
    """Match a TCP SYN/ACK or RST reply to its original SYN probe."""
    from scapy.all import IP, TCP

    if response is None or not response.haslayer(IP) or not response.haslayer(TCP):
        return False
    sent_ip, sent_tcp = probe[IP], probe[TCP]
    recv_ip, recv_tcp = response[IP], response[TCP]

    if (recv_ip.src != sent_ip.dst or recv_ip.dst != sent_ip.src
            or recv_tcp.sport != sent_tcp.dport
            or recv_tcp.dport != sent_tcp.sport):
        return False

    flags = int(recv_tcp.flags)
    expected_ack = (sent_tcp.seq + 1) % (2 ** 32)
    if flags in (0x12, 0x14):  # SYN/ACK or RST/ACK
        return recv_tcp.ack == expected_ack
    if flags == 0x04:  # Bare RST does not contain an ACK to verify.
        return True
    return False

def matching_icmp_response(response, probe):
    """Match an ICMP unreachable error using its quoted original probe."""
    from scapy.all import IP, ICMP, IPerror, TCPerror, TCP

    if (response is None or not response.haslayer(ICMP)
            or int(response[ICMP].type) != 3
            or not response.haslayer(IPerror)
            or not response.haslayer(TCPerror)):
        return False

    quoted_ip, quoted_tcp = response[IPerror], response[TCPerror]
    sent_ip, sent_tcp = probe[IP], probe[TCP]
    return (
        quoted_ip.src == sent_ip.src
        and quoted_ip.dst == sent_ip.dst
        and int(quoted_ip.proto) == 6
        and quoted_tcp.sport == sent_tcp.sport
        and quoted_tcp.dport == sent_tcp.dport
        and quoted_tcp.seq == sent_tcp.seq
    )

def classify_response(response, probe):
    """Classify a matched reply; return None for unrelated traffic."""
    from scapy.all import TCP, ICMP

    if response is None:
        return "filtered-or-no-response", None
    if matching_response(response, probe):
        flags = int(response[TCP].flags)
        return ("open" if flags == 0x12 else "closed"), None
    if matching_icmp_response(response, probe):
        return "filtered-or-no-response", {
            "icmp_type": int(response[ICMP].type),
            "icmp_code": int(response[ICMP].code),
        }
    return None, None

def build_rst_packet(probe, response):
    """Build a RST that terminates a matched SYN/ACK exchange."""
    from scapy.all import IP, TCP

    if not matching_response(response, probe) or int(response[TCP].flags) != 0x12:
        raise ValueError("RST cleanup requires a matching SYN/ACK")
    return IP(src=probe[IP].src, dst=probe[IP].dst) / TCP(
        sport=probe[TCP].sport,
        dport=probe[TCP].dport,
        flags="R",
        seq=(probe[TCP].seq + 1) % (2 ** 32),
    )

def scan_ports(scope, send_probe=None, send_reset=None, source_ip=None):
    """Scan the authorised ports, recording attempts and response evidence.

    Inject send_probe/send_reset and source_ip to test without network access.
    """
    from scapy.all import get_if_addr, send, sr1

    # Validate again so callers cannot bypass the CLI's scope checks.
    scope = validate_scope_object(scope)
    interface = scope["interface"]
    if source_ip is None:
        source_ip = get_if_addr(interface)
    if not ipaddress.ip_address(source_ip).version == 4:
        raise ValueError("Scanner source address must be IPv4")

    if send_probe is None:
        def send_probe(packet, **kwargs):
            return sr1(packet, **kwargs)
    if send_reset is None:
        def send_reset(packet, **kwargs):
            return send(packet, **kwargs)

    interval = 1.0 / scope["maximum_rate_pps"]
    next_send_time = 0.0

    def rate_limit():
        """Space out every outgoing SYN and explicit RST packet."""
        nonlocal next_send_time
        now = time.monotonic()
        if now < next_send_time:
            time.sleep(next_send_time - now)
        next_send_time = time.monotonic() + interval

    results = []
    for port in scope["ports"]:
        status = "filtered-or-no-response"
        evidence = []
        attempts_used = 0
        recovered_by_retry = False
        rst_sent = False

        for attempt in range(1, scope["maximum_attempts"] + 1):
            attempts_used = attempt
            probe = build_syn_probe(
                scope["target"], port,
                secrets.randbelow(20001) + 40000,
                secrets.randbits(32),
                source_ip=source_ip,
            )
            rate_limit()
            response = send_probe(
                probe, iface=interface,
                timeout=scope["timeout_seconds"], verbose=False,
            )
            classification, icmp_info = classify_response(response, probe)
            if icmp_info is not None:
                evidence.append({"attempt": attempt, **icmp_info})

            if classification in ("open", "closed"):
                status = classification
                recovered_by_retry = attempt > 1
                if status == "open":
                    rst = build_rst_packet(probe, response)
                    rate_limit()
                    send_reset(rst, iface=interface, verbose=False)
                    rst_sent = True
                break

        results.append({
            "port": port,
            "protocol": "tcp",
            "status": status,
            "attempts_used": attempts_used,
            "retry_count": attempts_used - 1,
            "recovered_by_retry": recovered_by_retry,
            "rst_sent": rst_sent,
            "icmp_unreachable": evidence,
        })
    return results

def validate_scope_object(scope):
    """Revalidate in-memory scope before any network transmission."""
    import tempfile

    # Use the same validation rules for CLI input and programmatic callers.
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "scope.json"
        path.write_text(json.dumps(scope), encoding="utf-8")
        return load_scope(path)

def write_json(path, data):
    """Write consistently ordered, human-readable JSON."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

def main(argv=None):
    """Run the CLI; dry-run is the default safe operating mode."""
    parser = argparse.ArgumentParser(description="WQE7002 authorised TCP SYN scanner")
    parser.add_argument("--scope", required=True, help="Lecturer-issued scope JSON")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--execute", action="store_true", help="Send authorised probes")
    args = parser.parse_args(argv)

    try:
        scope = load_scope(args.scope)
        started = utc_now()
        report = {
            "tool_version": VERSION,
            "option": scope["option"],
            "scope_id": scope["scope_id"],
            "started_at_utc": started,
            "target": scope["target"],
            "ports": scope["ports"],
            "interface": scope["interface"],
            "maximum_rate_pps": scope["maximum_rate_pps"],
            "maximum_attempts": scope["maximum_attempts"],
            "timeout_seconds": scope["timeout_seconds"],
            "mode": "execute" if args.execute else "dry-run",
        }

        if args.execute:
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                raise PermissionError("--execute requires root privileges")
            report["results"] = scan_ports(scope)
        else:
            # A dry-run must never call the packet transmission functions.
            report["results"] = []
            report["planned_probes"] = [
                {"target": scope["target"], "port": port, "protocol": "tcp"}
                for port in scope["ports"]
            ]

        report["finished_at_utc"] = utc_now()
        write_json(args.output, report)
        print(f"{report['mode']} completed: {args.output}")
        return 0
    except (OSError, ValueError, TypeError, PermissionError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
