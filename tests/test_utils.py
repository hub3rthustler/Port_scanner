import unittest

import utils


class ValidateTargetTests(unittest.TestCase):
    def test_accepts_ip_addresses_and_hostnames(self):
        valid_targets = (
            "127.0.0.1",
            "::1",
            "localhost",
            "example.technology",
            "example.com.",
            "bücher.de",
        )
        for target in valid_targets:
            with self.subTest(target=target):
                self.assertTrue(utils.validate_target(target))

    def test_rejects_invalid_hostnames(self):
        invalid_targets = (
            "",
            "   ",
            "-example.com",
            "example-.com",
            "example..com",
            "127.1",
            "1.2.3",
            f"{'a' * 64}.com",
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                self.assertFalse(utils.validate_target(target))


class ParsePortRangeTests(unittest.TestCase):
    def test_parses_mixed_ranges_and_removes_duplicates(self):
        self.assertEqual(
            utils.parse_port_range("22,80-82,81,443"),
            [22, 80, 81, 82, 443],
        )

    def test_accepts_boundary_ports(self):
        self.assertEqual(utils.parse_port_range("1,65535"), [1, 65_535])

    def test_rejects_invalid_ports_and_ranges(self):
        invalid_inputs = ("", "0", "65536", "82-80", "80,", "1-2-3", "abc")
        for port_input in invalid_inputs:
            with self.subTest(port_input=port_input):
                self.assertIsNone(utils.parse_port_range(port_input))


if __name__ == "__main__":
    unittest.main()
