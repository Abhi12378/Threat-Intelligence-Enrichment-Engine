import sys
import os
import unittest
import re
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from enrich import (
    determine_threat_type,
    determine_ioc_type,
    calculate_confidence,
    enrich_ioc
)

class TestEnrichmentEngine(unittest.TestCase):

    def setUp(self):
        self.rules = [
            {"keyword": "abcd", "threat_type": "ransomware"},
            {"keyword": "stealer", "threat_type": "infostealer"},
            {"keyword": "maliciousdomain.com", "threat_type": "malicious-domain"},
            {"ip_range": "8.8.8.", "threat_type": "botnet"},
            {"keyword": "@", "threat_type": "phishing-email"}
        ]

        self.feeds = {
            "internal": {"8.8.8.8", "abcd1234efgh5678", "abcd5678ijkl9012"},
            "misp": {"stealer-hub.com", "xyzstealerpayload.com"},
            "public": {"8.8.8.8", "abcd1234efgh5678", "maliciousdomain.com", "1234abcd5678efgh"}
        }

    # ------------------ Threat Type ------------------

    def test_threat_type_keyword_match(self):
        self.assertEqual(determine_threat_type("thisisabcdpayload", self.rules), "ransomware")


    def test_threat_type_ip_range_match(self):
        self.assertEqual(determine_threat_type("8.8.8.1", self.rules), "botnet")

    def test_threat_type_malicious_domain(self):
        self.assertEqual(determine_threat_type("maliciousdomain.com", self.rules), "malicious-domain")

    def test_threat_type_email(self):
        self.assertEqual(determine_threat_type("user@domain.com", self.rules), "phishing-email")

    def test_threat_type_unknown(self):
        self.assertEqual(determine_threat_type("safe-site.biz", self.rules), "unknown")

    # ------------------ IOC Type ------------------

    def test_ioc_type_ipv4(self):
        self.assertEqual(determine_ioc_type("192.168.1.1"), "ipv4-addr")

    def test_ioc_type_domain(self):
        self.assertEqual(determine_ioc_type("example.org"), "domain-name")

    def test_ioc_type_email(self):
        self.assertEqual(determine_ioc_type("admin@site.com"), "email-addr")

    def test_ioc_type_file_hash(self):
        self.assertEqual(determine_ioc_type("abcd1234efgh5678"), "file-hash")

    def test_ioc_type_fallback(self):
        self.assertEqual(determine_ioc_type("###not-an-ioc###"), "file-hash")

    # ------------------ Confidence ------------------

    def test_confidence_full_sources(self):
        score = calculate_confidence(["internal", "misp", "public"], "ransomware")
        self.assertEqual(score, 100)

    def test_confidence_medium_sources(self):
        score = calculate_confidence(["misp", "public"], "infostealer")
        self.assertEqual(score, 45)

    def test_confidence_low_sources(self):
        score = calculate_confidence([], "unknown")
        self.assertEqual(score, 10)

    # ------------------ Enrich IOC ------------------

    def test_enrich_valid_botnet(self):
        enriched = enrich_ioc("8.8.8.8", self.rules, self.feeds, 1)
        self.assertEqual(enriched["value"], "8.8.8.8")
        self.assertEqual(enriched["type"], "ipv4-addr")
        self.assertEqual(enriched["threat_type"], "botnet")
        self.assertEqual(enriched["source"], "internal")
        self.assertTrue(0 <= enriched["confidence"] <= 100)
        self.assertIn("timestamp", enriched)
        self.assertTrue(re.match(r"\d{4}-\d{2}-\d{2}T", enriched["timestamp"]))

    def test_enrich_email_ioc(self):
        enriched = enrich_ioc("attacker@phish.com", self.rules, self.feeds, 10)
        self.assertEqual(enriched["type"], "email-addr")
        self.assertEqual(enriched["threat_type"], "phishing-email")

    def test_enrich_malicious_domain(self):
        enriched = enrich_ioc("maliciousdomain.com", self.rules, self.feeds, 7)
        self.assertEqual(enriched["type"], "domain-name")
        self.assertEqual(enriched["threat_type"], "malicious-domain")
        self.assertEqual(enriched["source"], "public")

    def test_enrich_unknown(self):
        enriched = enrich_ioc("neutral.org", self.rules, self.feeds, 99)
        self.assertEqual(enriched["threat_type"], "unknown")
        self.assertEqual(enriched["source"], "unknown")
        self.assertTrue(enriched["confidence"] <= 30)

    def test_enrich_empty_input(self):
        enriched = enrich_ioc("", self.rules, self.feeds, 99)
        self.assertEqual(enriched["value"], "")
        self.assertEqual(enriched["type"], "file-hash")
        self.assertEqual(enriched["threat_type"], "unknown")
        self.assertEqual(enriched["source"], "unknown")
        self.assertEqual(enriched["confidence"], 10)

if __name__ == "__main__":
    unittest.main()
