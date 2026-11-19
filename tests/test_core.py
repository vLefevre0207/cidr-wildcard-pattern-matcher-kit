import unittest

from cidr_wildcard_pattern_matcher_kit import CIDRWildcardMatcher, PatternError


class MatcherTests(unittest.TestCase):
    def test_wildcard_matches_any_octet(self):
        m = CIDRWildcardMatcher(["192.168.*.*"])
        self.assertTrue(m.matches("192.168.0.0"))
        self.assertTrue(m.matches("192.168.255.255"))
        self.assertFalse(m.matches("192.169.0.1"))
        self.assertFalse(m.matches("10.168.0.1"))

    def test_all_wildcards(self):
        m = CIDRWildcardMatcher(["*.*.*.*"])
        self.assertTrue(m.matches("0.0.0.0"))
        self.assertTrue(m.matches("255.255.255.255"))

    def test_literal_pattern(self):
        m = CIDRWildcardMatcher(["10.0.0.1"])
        self.assertTrue(m.matches("10.0.0.1"))
        self.assertFalse(m.matches("10.0.0.2"))

    def test_cidr_slash_eight(self):
        m = CIDRWildcardMatcher(["10.0.0.0/8"])
        self.assertTrue(m.matches("10.1.2.3"))
        self.assertTrue(m.matches("10.255.255.255"))
        self.assertFalse(m.matches("11.0.0.1"))

    def test_cidr_slash_thirty_two_is_exact(self):
        m = CIDRWildcardMatcher(["192.0.2.7/32"])
        self.assertTrue(m.matches("192.0.2.7"))
        self.assertFalse(m.matches("192.0.2.8"))

    def test_cidr_slash_zero_matches_everything(self):
        m = CIDRWildcardMatcher(["0.0.0.0/0"])
        self.assertTrue(m.matches("1.2.3.4"))
        self.assertTrue(m.matches("255.255.255.255"))

    def test_cidr_non_octet_boundary(self):
        # 192.168.1.0/25 covers .1.0 through .1.127.
        m = CIDRWildcardMatcher(["192.168.1.0/25"])
        self.assertTrue(m.matches("192.168.1.0"))
        self.assertTrue(m.matches("192.168.1.127"))
        self.assertFalse(m.matches("192.168.1.128"))
        self.assertFalse(m.matches("192.168.1.255"))

    def test_multiple_patterns_any_match(self):
        m = CIDRWildcardMatcher(["192.168.*.*", "10.0.0.0/8"])
        self.assertTrue(m.matches("192.168.1.5"))
        self.assertTrue(m.matches("10.1.2.3"))
        self.assertFalse(m.matches("172.16.0.1"))

    def test_invalid_address_raises_value_error(self):
        m = CIDRWildcardMatcher(["*.*.*.*"])
        with self.assertRaises(ValueError):
            m.matches("not-an-ip")
        with self.assertRaises(ValueError):
            m.matches("256.0.0.1")

    def test_pattern_errors(self):
        bad = [
            "",
            "192.168.1",
            "192.168.1.2.3",
            "192.168.1.256",
            "192.168.1.010",
            "192.168.*.x",
            "10.0.0.0/33",
            "10.0.0.0/abc",
            "10.0.0.0/8/8",
            "999.0.0.0/8",
        ]
        for pattern in bad:
            with self.subTest(pattern=pattern):
                with self.assertRaises(PatternError):
                    CIDRWildcardMatcher([pattern])

    def test_leading_zero_rejected_in_cidr_address(self):
        with self.assertRaises(PatternError):
            CIDRWildcardMatcher(["010.0.0.0/8"])

    def test_len_and_repr(self):
        m = CIDRWildcardMatcher(["192.168.*.*", "10.0.0.0/8"])
        self.assertEqual(len(m), 2)
        self.assertIn("2 patterns", repr(m))


if __name__ == "__main__":
    unittest.main()
