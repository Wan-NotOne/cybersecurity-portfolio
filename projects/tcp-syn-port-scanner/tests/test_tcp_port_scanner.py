# test_tcp_port_scanner.py: Verify scope safety, Scapy packet construction, response matching,

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scapy.all import ICMP, IP, IPerror, TCP, TCPerror
import tcp_port_scanner as scanner

VALID_SCOPE = {
    "schema": "wqe7002-recon-scope-v1",
    "scope_id": "wqe7002-a1-standard-tcp-syn-scan-v1",
    "option": "tcp-syn-scan",
    "environment": "isolated-course-lab",
    "interface": "eth0",
    "target": "172.28.70.10",
    "ports": [22, 80, 443, 8080],
    "maximum_rate_pps": 20,
    "maximum_attempts": 2,
    "timeout_seconds": 1.5,
}

SOURCE_IP = "172.28.70.2"

def make_probe(port=80, seq=1000):
    """Construct a deterministic SYN probe for offline assertions."""
    return scanner.build_syn_probe(
        "172.28.70.10", port, 45000, seq, source_ip=SOURCE_IP
    )

def make_reply(probe, flags="SA", ack=None):
    """Construct a reply with reversed IP addresses and TCP ports."""
    if ack is None:
        ack = (probe[TCP].seq + 1) % (2 ** 32)
    return IP(src=probe[IP].dst, dst=probe[IP].src) / TCP(
        sport=probe[TCP].dport,
        dport=probe[TCP].sport,
        flags=flags,
        seq=5000,
        ack=ack,
    )

class TestScopeValidation(unittest.TestCase):
    """Reject invalid or unauthorised scope configuration."""

    def test_valid_scope_is_accepted(self):
        scope = scanner.validate_scope_object(copy.deepcopy(VALID_SCOPE))
        self.assertEqual(scope["target"], "172.28.70.10")
        self.assertEqual(scope["ports"], [22, 80, 443, 8080])

    def test_unauthorised_target_is_rejected(self):
        scope = copy.deepcopy(VALID_SCOPE)
        scope["target"] = "172.28.70.11"
        with self.assertRaises(ValueError):
            scanner.validate_scope_object(scope)

    def test_modified_or_duplicate_ports_are_rejected(self):
        for ports in ([22, 80, 443, 9999], [22, 80, 80, 8080]):
            with self.subTest(ports=ports):
                scope = copy.deepcopy(VALID_SCOPE)
                scope["ports"] = ports
                with self.assertRaises(ValueError):
                    scanner.validate_scope_object(scope)

    def test_rate_and_attempt_limits_are_enforced(self):
        for field, invalid in (("maximum_rate_pps", 21),
                               ("maximum_attempts", 3)):
            with self.subTest(field=field):
                scope = copy.deepcopy(VALID_SCOPE)
                scope[field] = invalid
                with self.assertRaises(ValueError):
                    scanner.validate_scope_object(scope)

class TestPacketLogic(unittest.TestCase):
    """Validate TCP and ICMP processing without sending packets."""

    def test_syn_probe_has_correct_fields(self):
        probe = make_probe()
        self.assertEqual(probe[IP].dst, "172.28.70.10")
        self.assertEqual(probe[IP].src, SOURCE_IP)
        self.assertEqual(probe[TCP].sport, 45000)
        self.assertEqual(probe[TCP].dport, 80)
        self.assertEqual(int(probe[TCP].flags), 0x02)
        self.assertEqual(probe[TCP].seq, 1000)

    def test_matching_synack_is_open(self):
        probe = make_probe()
        reply = make_reply(probe, "SA")
        self.assertTrue(scanner.matching_response(reply, probe))
        self.assertEqual(scanner.classify_response(reply, probe), ("open", None))

    def test_matching_rst_ack_is_closed(self):
        probe = make_probe()
        reply = make_reply(probe, "RA")
        self.assertTrue(scanner.matching_response(reply, probe))
        self.assertEqual(scanner.classify_response(reply, probe), ("closed", None))

    def test_wrong_ack_and_source_port_are_rejected(self):
        probe = make_probe()
        wrong_ack = make_reply(probe, "SA", ack=9999)
        wrong_port = make_reply(probe, "SA")
        wrong_port[TCP].sport = 443
        for reply in (wrong_ack, wrong_port):
            with self.subTest(reply=reply.summary()):
                self.assertFalse(scanner.matching_response(reply, probe))
                self.assertEqual(scanner.classify_response(reply, probe), (None, None))

    def test_missing_reply_is_not_claimed_open_or_closed(self):
        self.assertEqual(
            scanner.classify_response(None, make_probe()),
            ("filtered-or-no-response", None),
        )

    def test_matching_icmp_unreachable_preserves_type_and_code(self):
        probe = make_probe()
        response = (
            IP(src="172.28.70.1", dst=SOURCE_IP)
            / ICMP(type=3, code=13)
            / IPerror(src=SOURCE_IP, dst="172.28.70.10", proto=6)
            / TCPerror(sport=45000, dport=80, seq=1000)
        )
        self.assertTrue(scanner.matching_icmp_response(response, probe))
        self.assertEqual(
            scanner.classify_response(response, probe),
            ("filtered-or-no-response", {"icmp_type": 3, "icmp_code": 13}),
        )
        response[TCPerror].dport = 443
        self.assertFalse(scanner.matching_icmp_response(response, probe))

    def test_rst_cleanup_uses_correct_reversed_flow(self):
        probe = make_probe()
        reply = make_reply(probe, "SA")
        rst = scanner.build_rst_packet(probe, reply)
        self.assertEqual(rst[IP].src, SOURCE_IP)
        self.assertEqual(rst[IP].dst, "172.28.70.10")
        self.assertEqual(rst[TCP].sport, 45000)
        self.assertEqual(rst[TCP].dport, 80)
        self.assertEqual(int(rst[TCP].flags), 0x04)
        self.assertEqual(rst[TCP].seq, 1001)
        with self.assertRaises(ValueError):
            scanner.build_rst_packet(probe, make_reply(probe, "RA"))

class TestOutputAndDryRun(unittest.TestCase):
    """Verify reproducible JSON formatting and safe default CLI mode."""

    def test_json_output_is_deterministic(self):
        data = {"z": 2, "a": [22, 80]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            scanner.write_json(output, data)
            first = output.read_bytes()
            scanner.write_json(output, data)
            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(json.loads(first), data)

    def test_dry_run_does_not_call_scan_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.json"
            result_path = Path(directory) / "result.json"
            scope_path.write_text(json.dumps(VALID_SCOPE), encoding="utf-8")
            with patch.object(scanner, "scan_ports") as mocked_scan:
                exit_code = scanner.main([
                    "--scope", str(scope_path),
                    "--output", str(result_path),
                ])
            self.assertEqual(exit_code, 0)
            mocked_scan.assert_not_called()
            report = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(report["mode"], "dry-run")
            self.assertEqual(report["results"], [])
            self.assertEqual(
                [item["port"] for item in report["planned_probes"]],
                [22, 80, 443, 8080],
            )

if __name__ == "__main__":
    unittest.main()
