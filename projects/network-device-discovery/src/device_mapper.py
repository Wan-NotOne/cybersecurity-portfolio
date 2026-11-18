# device_mapper.py: Main program for ARP-based device discovery.

import argparse
import ipaddress
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Tool version and lecturer-defined safety limits.
VERSION = "0.2.0"
MAX_RATE = 20
MAX_ATTEMPTS = 2

def utc_now():
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")

def load_scope(path):
    """Load and validate the lecturer-authorised scope configuration."""
    with open(path, encoding="utf-8") as handle:
        scope = json.load(handle)

    # Validate the scope structure and required lab identifiers.
    if not isinstance(scope, dict):
        raise ValueError("Scope must be a JSON object")
    if scope.get("schema") != "wqe7002-recon-scope-v1":
        raise ValueError("Unsupported scope schema")
    if scope.get("option") != "device-map":
        raise ValueError("Scope is not authorised for Option A")
    if scope.get("environment") != "isolated-course-lab":
        raise ValueError("Unexpected environment")
    if not isinstance(scope.get("scope_id"), str) or not scope["scope_id"].strip():
        raise ValueError("Missing scope ID")
    if scope.get("interface") != "eth0":
        raise ValueError("Unexpected interface; expected lab eth0")

    # Restrict scanning to a non-global IPv4 network of /28 or narrower.
    network = ipaddress.ip_network(scope["network"], strict=True)
    if network.version != 4 or network.prefixlen < 28 or network.is_global:
        raise ValueError("Scope network must be a non-global IPv4 /28 or narrower")

    # Verify that every authorised host belongs to the permitted network.
    # Reject duplicate addresses and network/broadcast addresses.
    hosts = scope.get("authorised_hosts")
    if not isinstance(hosts, list) or not hosts or any(not isinstance(h, str) for h in hosts):
        raise ValueError("authorised_hosts must be a nonempty list of IP strings")

    addresses = [ipaddress.ip_address(h) for h in hosts]

    if len(set(addresses)) != len(addresses):
        raise ValueError("Duplicate authorised host")

    if any(
        a.version != 4
        or a not in network
        or a in (network.network_address, network.broadcast_address)
        for a in addresses
    ):
        raise ValueError("Host outside authorised usable addresses")

    # Enforce the maximum probe rate, attempts and a valid timeout.
    rate = scope.get("maximum_rate_pps")
    attempts = scope.get("maximum_attempts")
    timeout = scope.get("timeout_seconds")

    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0 < rate <= MAX_RATE:
        raise ValueError("Invalid maximum_rate_pps")

    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= MAX_ATTEMPTS:
        raise ValueError("Invalid maximum_attempts")

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Invalid timeout_seconds")

    # Sort authorised hosts to produce a consistent scanning order.
    scope["authorised_hosts"] = [str(a) for a in sorted(addresses)]
    return scope

def build_arp_probe(target_ip):
    """Construct an Ethernet broadcast ARP request for a target IP."""
    from scapy.all import ARP, Ether
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        pdst=target_ip
    )

def matching_reply(packet, target):
    """Accept only ARP replies whose sender IP matches the target."""
    from scapy.all import ARP
    return (
        packet.haslayer(ARP)
        and packet[ARP].op == 2
        and packet[ARP].psrc == target
    )

def scan_devices(scope):
    """Scan authorised hosts and record ARP observations and retry metrics."""
    from scapy.all import srp
    results = {}

    # Calculate the minimum interval between consecutive ARP probes.
    interval = 1.0 / scope["maximum_rate_pps"]
    last_sent = None

    for target in scope["authorised_hosts"]:
        # Start timing this target for the extension evaluation.
        target_start = time.monotonic()
        observations = []
        attempts_sent = 0

        # Retry only up to the maximum attempts permitted by the scope.
        for _ in range(scope["maximum_attempts"]):

            # Apply rate limiting before sending another probe.
            if last_sent is not None:
                delay = interval - (time.monotonic() - last_sent)
                if delay > 0:
                    time.sleep(delay)

            probe = build_arp_probe(target)
            last_sent = time.monotonic()
            attempts_sent += 1

            # Send an ARP probe and collect replies within the timeout.
            # retry=0 disables Scapy's internal retry mechanism.
            answered, _ = srp(
                probe,
                iface=scope["interface"],
                timeout=scope["timeout_seconds"],
                retry=0,
                verbose=False,
                multi=True,
            )

            # Record matching replies, including their MAC addresses.
            for _, response in answered:
                if matching_reply(response, target):
                    observations.append({
                        "mac": response["ARP"].hwsrc.lower(),
                        "observed_at_utc": utc_now(),
                    })

            # Stop probing this target once a valid reply is observed.
            if observations:
                break

        # Measure the elapsed scan duration for this target.
        duration = time.monotonic() - target_start

        # Deduplicate MAC addresses while preserving all observations.
        unique_macs = sorted({
            item["mac"] for item in observations
        })

        results[target] = {
            "status": "observed" if observations else "not observed",
            "attempts_sent": attempts_sent,
            "observation_count": len(observations),
            "mac_addresses": unique_macs,
            "observations": observations,

            # Extension: measure retry behaviour and scanning cost.
            "retry_count": max(0, attempts_sent - 1),
            "recovered_by_retry": bool(
                observations and attempts_sent > 1
            ),
            "scan_duration_seconds": round(duration, 3),
        }

    return results

def write_json(path, data):
    """Write JSON output using consistent formatting and sorted keys."""
    destination = Path(path)

    # Create the output directory if it does not already exist.
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as handle:
        json.dump(
            data,
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False
        )
        handle.write("\n")

def main(argv=None):
    """Handle CLI arguments, execute the selected mode and save results."""
    parser = argparse.ArgumentParser(
        description="WQE7002 authorised ARP device mapper"
    )

    parser.add_argument(
        "--scope",
        required=True,
        help="Lecturer-provided JSON scope"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="JSON output file"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Explicitly enable ARP transmission"
    )

    args = parser.parse_args(argv)

    # Validate the authorised scope before any network activity.
    scope = load_scope(args.scope)

    print("Scope validation: PASSED")
    print("Scope ID:", scope["scope_id"])
    print("Network:", scope["network"])
    print("Authorised hosts:", scope["authorised_hosts"])

    started = utc_now()

    if not args.execute:
        # Dry-run is the default mode and sends no ARP packets.
        print("\nDRY RUN - No packets sent")

        for target in scope["authorised_hosts"]:
            print("ARP Request ->", target)

        results = {}

    else:
        # Actual scanning requires the explicit --execute flag.
        print("\nEXECUTE MODE - sending authorised ARP probes")

        results = scan_devices(scope)

        for target, result in results.items():
            print(
                target,
                result["status"],
                result["mac_addresses"]
            )

    # Record the experiment metadata, effective limits and observations.
    report = {
        "tool_version": VERSION,
        "option": "device-map",
        "scope_id": scope["scope_id"],
        "mode": "execute" if args.execute else "dry-run",
        "started_at_utc": started,
        "ended_at_utc": utc_now(),
        "effective_parameters": {
            "interface": scope["interface"],
            "network": scope["network"],
            "authorised_hosts": scope["authorised_hosts"],
            "maximum_rate_pps": scope["maximum_rate_pps"],
            "maximum_attempts": scope["maximum_attempts"],
            "timeout_seconds": scope["timeout_seconds"],
        },
        "results": results,
    }

    write_json(args.output, report)

    print("JSON written to:", args.output)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())

    # Report validation and file errors with a non-zero exit status.
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        json.JSONDecodeError
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
