# test_device_mapper.py: Unit tests to verify the program's correctness and safety

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import device_mapper as dm

# A valid lecturer-authorised scope based on the provided
# course-provided-lab-pack/scope-device-map.json file.
# Tests use copies of this scope to avoid affecting other test cases.
SCOPE = {
    "schema": "wqe7002-recon-scope-v1",
    "scope_id": "wqe7002-a1-standard-device-map-v1",
    "option": "device-map",
    "environment": "isolated-course-lab",
    "interface": "eth0",
    "network": "172.28.70.0/28",
    "authorised_hosts": ["172.28.70.3", "172.28.70.10"],
    "maximum_rate_pps": 20,
    "maximum_attempts": 2,
    "timeout_seconds": 1.5,
}

class DeviceMapperTests(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for test files.
        # It is automatically removed after each test.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def scope_file(self, scope):
        # Write a scope configuration to a temporary JSON file.
        path = self.folder / "scope.json"
        path.write_text(json.dumps(scope), encoding="utf-8")
        return path
    
    #Scope Validation
    def test_valid_scope(self):
        # Verify that a valid authorised scope is accepted.
        scope = dm.load_scope(self.scope_file(copy.deepcopy(SCOPE)))

        self.assertEqual(scope["scope_id"], SCOPE["scope_id"])
        self.assertEqual(
            scope["authorised_hosts"],
            SCOPE["authorised_hosts"]
        )
    #Security
    def test_reject_out_of_scope_host(self):
        # Security test: an IP outside the authorised network must be rejected.
        scope = copy.deepcopy(SCOPE)
        scope["authorised_hosts"].append("8.8.8.8")

        with self.assertRaises(ValueError):
            dm.load_scope(self.scope_file(scope))
    #Safety
    def test_reject_excessive_rate_and_attempts(self):
        # Verify that unsafe probe rates and retry limits are rejected.
        for key, value in (
            ("maximum_rate_pps", 21),
            ("maximum_attempts", 3)
        ):
            with self.subTest(key=key):
                scope = copy.deepcopy(SCOPE)
                scope[key] = value

                with self.assertRaises(ValueError):
                    dm.load_scope(self.scope_file(scope))
    
    #Packet Construction
    def test_arp_probe_fields(self):
        # Verify that the tool constructs a broadcast ARP request
        # addressed to the intended target IP.
        from scapy.all import ARP, Ether

        packet = dm.build_arp_probe("172.28.70.3")

        self.assertEqual(
            packet[Ether].dst,
            "ff:ff:ff:ff:ff:ff"
        )
        self.assertEqual(packet[ARP].op, 1)
        self.assertEqual(packet[ARP].pdst, "172.28.70.3")

    #Response Validation
    def test_matching_reply(self):
        # Accept only ARP replies from the expected target IP.
        # Reject replies from other IPs and ARP request packets.
        from scapy.all import ARP, Ether

        good = Ether() / ARP(
            op=2,
            psrc="172.28.70.3",
            hwsrc="02:00:00:00:00:03"
        )
        wrong_ip = Ether() / ARP(
            op=2,
            psrc="172.28.70.10"
        )
        request = Ether() / ARP(
            op=1,
            psrc="172.28.70.3"
        )

        self.assertTrue(
            dm.matching_reply(good, "172.28.70.3")
        )
        self.assertFalse(
            dm.matching_reply(wrong_ip, "172.28.70.3")
        )
        self.assertFalse(
            dm.matching_reply(request, "172.28.70.3")
        )

    #Missing Response
    def test_missing_reply_is_not_observed(self):
        # Simulate a target that does not respond to ARP requests.
        # Mocking prevents real network packets from being sent.
        scope = copy.deepcopy(SCOPE)
        scope["authorised_hosts"] = ["172.28.70.3"]

        with patch(
            "scapy.all.srp",
            return_value=([], [])
        ) as srp:
            with patch.object(dm.time, "sleep"):
                results = dm.scan_devices(scope)

        # The tool should stop after the permitted two attempts.
        self.assertEqual(srp.call_count, 2)
        self.assertEqual(
            results["172.28.70.3"]["status"],
            "not observed"
        )
        self.assertEqual(
            results["172.28.70.3"]["attempts_sent"],
            2
        )
        self.assertEqual(
            results["172.28.70.3"]["observation_count"],
            0
        )

    #Deduplication
    def test_duplicate_replies_preserve_count(self):
        # Simulate two ARP replies containing the same MAC address.
        # The MAC list should be deduplicated, but both observations
        # must still be counted and recorded.
        from scapy.all import ARP, Ether

        scope = copy.deepcopy(SCOPE)
        scope["authorised_hosts"] = ["172.28.70.3"]

        mac = "02:00:00:00:00:03"

        response1 = Ether() / ARP(
            op=2,
            psrc="172.28.70.3",
            hwsrc=mac
        )
        response2 = Ether() / ARP(
            op=2,
            psrc="172.28.70.3",
            hwsrc=mac
        )

        with patch(
            "scapy.all.srp",
            return_value=(
                [(None, response1), (None, response2)],
                []
            )
        ) as srp:
            results = dm.scan_devices(scope)

        item = results["172.28.70.3"]

        self.assertEqual(srp.call_count, 1)
        self.assertEqual(item["status"], "observed")
        self.assertEqual(item["observation_count"], 2)
        self.assertEqual(item["mac_addresses"], [mac])
        self.assertEqual(len(item["observations"]), 2)

    #Reproducibility
    def test_deterministic_json(self):
        # Verify that identical input produces identical JSON output.
        # JSON keys should also appear in a consistent sorted order.
        data = {"z": [1, 2], "a": {"y": 2, "x": 1}}

        first = self.folder / "one.json"
        second = self.folder / "two.json"

        dm.write_json(first, data)
        dm.write_json(second, data)

        self.assertEqual(
            first.read_bytes(),
            second.read_bytes()
        )
        self.assertLess(
            first.read_text().index('"a"'),
            first.read_text().index('"z"')
        )

    #Safe Execution
    def test_dry_run_never_sends(self):
        # Verify that dry-run mode validates the scope and writes
        # a JSON report without calling the scanning function.
        scope_path = self.scope_file(copy.deepcopy(SCOPE))
        output_path = self.folder / "dry-run.json"

        with patch.object(
            dm,
            "scan_devices",
            side_effect=AssertionError("unexpected scan")
        ):
            self.assertEqual(
                dm.main([
                    "--scope", str(scope_path),
                    "--output", str(output_path)
                ]),
                0
            )

        report = json.loads(
            output_path.read_text(encoding="utf-8")
        )

        self.assertEqual(report["mode"], "dry-run")
        self.assertEqual(report["results"], {})


if __name__ == "__main__":
    unittest.main()
