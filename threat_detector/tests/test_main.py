import unittest
import sys
import json
import io
from datetime import datetime, timedelta, UTC
from unittest.mock import patch, mock_open
from pathlib import Path

# Include the src module
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src import main as main_module


class TestMain(unittest.TestCase):

    # === determine_ioc_type ===
    def test_determine_ioc_type(self):
        self.assertEqual(main_module.determine_ioc_type("192.168.1.1"), "ipv4-addr")
        self.assertEqual(main_module.determine_ioc_type("abcdef1234"), "file-hash")
        self.assertEqual(main_module.determine_ioc_type("bob@example.com"), "email-addr")
        self.assertEqual(main_module.determine_ioc_type("suspicious-domain.org"), "domain-name")
        self.assertEqual(main_module.determine_ioc_type("..."), "file-hash")

    # === determine_threat_type ===
    def test_determine_threat_type(self):
        rules = [
            {"ip_range": "192.168", "threat_type": "internal"},
            {"keyword": "malicious", "threat_type": "malware"}
        ]
        self.assertEqual(main_module.determine_threat_type("192.168.0.1", rules), "internal")
        self.assertEqual(main_module.determine_threat_type("malicious-domain.com", rules), "malware")
        self.assertEqual(main_module.determine_threat_type("safe.com", rules), "unknown")

    # === calculate_confidence ===
    def test_calculate_confidence(self):
        self.assertEqual(main_module.calculate_confidence(["internal"], "botnet"), 55)
        self.assertEqual(main_module.calculate_confidence(["MISP"], "trojan"), 35)
        self.assertEqual(main_module.calculate_confidence(["public"], "phishing"), 15)
        self.assertEqual(main_module.calculate_confidence(["unknown"], "unknown"), 10)
        self.assertEqual(main_module.calculate_confidence(["internal", "MISP", "public"], "command-and-control"), 95)

    # === get_ist_time ===
    def test_get_ist_time(self):
        utc_now = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)
        ist = main_module.get_ist_time(utc_now)
        delta = ist - utc_now
        self.assertIn(delta, [timedelta(hours=5, minutes=30), timedelta(0)])

    @patch("src.main.ZoneInfo", side_effect=Exception("ZoneInfo failed"))
    @patch("src.main.logger")
    def test_get_ist_time_fallback(self, mock_logger, mock_zoneinfo):
        utc_now = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        result = main_module.get_ist_time(utc_now)
        expected = utc_now + timedelta(hours=5, minutes=30)
        self.assertEqual(result, expected)
        mock_logger.warning.assert_called_once()
        self.assertIn("ZoneInfo not available", mock_logger.warning.call_args[0][0])

    # === Loaders ===
    @patch("builtins.open", new_callable=mock_open, read_data="ioc1\nioc2\n")
    def test_load_internal_feed(self, mock_file):
        result = main_module.load_internal_feed("path.txt")
        self.assertEqual(result, {"ioc1", "ioc2"})

    @patch("builtins.open", new_callable=mock_open, read_data='["abc", "def"]')
    def test_load_misp_feed(self, mock_file):
        result = main_module.load_misp_feed("misp.json")
        self.assertEqual(result, {"abc", "def"})

    @patch("builtins.open", new_callable=mock_open, read_data="ioc\nx.com\ny.com\n")
    def test_load_osint_feed(self, mock_file):
        with patch("csv.DictReader", return_value=[{"ioc": "x.com"}, {"ioc": "y.com"}]):
            result = main_module.load_osint_feed("osint.csv")
            self.assertEqual(result, {"x.com", "y.com"})

    @patch("builtins.open", new_callable=mock_open, read_data='{"patterns":[{"keyword":"x","threat_type":"spy"}]}')
    def test_load_threat_rules(self, mock_file):
        result = main_module.load_threat_rules("rules.json")
        self.assertEqual(result, [{"keyword": "x", "threat_type": "spy"}])

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_load_threat_rules_missing_key(self, mock_file):
        with self.assertRaises(KeyError):
            main_module.load_threat_rules("bad.json")

    @patch("builtins.open", new_callable=mock_open, read_data="not json")
    def test_load_misp_feed_invalid_json(self, mock_file):
        with self.assertRaises(json.JSONDecodeError):
            main_module.load_misp_feed("corrupt.json")

    # === enrich_iocs ===
    @patch("src.main.get_ist_time")
    @patch("src.main.datetime")
    @patch("builtins.open", new_callable=mock_open)
    def test_enrich_iocs(self, mock_file, mock_datetime, mock_ist):
        now = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        mock_datetime.now.return_value = now
        mock_ist.return_value = now + timedelta(hours=5, minutes=30)

        input_data = json.dumps([
            {"ioc": "192.168.1.1"},
            {"ioc": "user@example.com"},
            {"no_ioc": "ignored"}
        ])
        mock_open_obj = mock_open(read_data=input_data)
        mock_file.side_effect = [mock_open_obj.return_value, io.StringIO()]

        feeds = {
            "internal": {"192.168.1.1"},
            "MISP": set(),
            "public": {"user@example.com"}
        }
        rules = [
            {"ip_range": "192.168", "threat_type": "malware"},
            {"keyword": "@example.com", "threat_type": "phishing"}
        ]

        with patch("json.dump") as mock_dump:
            main_module.enrich_iocs("input.json", "output.json", feeds, rules)
            enriched = mock_dump.call_args[0][0]
            self.assertEqual(len(enriched), 2)
            self.assertEqual(enriched[0]["type"], "ipv4-addr")
            self.assertEqual(enriched[1]["type"], "email-addr")

    # === main() ===
    @patch("src.main.load_internal_feed", return_value={"a"})
    @patch("src.main.load_misp_feed", return_value={"b"})
    @patch("src.main.load_osint_feed", return_value={"c"})
    @patch("src.main.load_threat_rules", return_value=[{"keyword": "b", "threat_type": "test"}])
    @patch("src.main.enrich_iocs")
    @patch("src.main.Path.mkdir")
    @patch("src.main.logger")
    def test_main_function_runs(
        self, mock_logger, mock_mkdir, mock_enrich, mock_rules, mock_osint, mock_misp, mock_internal
    ):
        main_module.main()
        mock_internal.assert_called_once()
        mock_misp.assert_called_once()
        mock_osint.assert_called_once()
        mock_rules.assert_called_once()
        mock_enrich.assert_called_once()
        mock_logger.info.assert_called_with("IOC enrichment complete.")

    @patch("src.main.load_internal_feed", side_effect=FileNotFoundError)
    def test_main_raises_when_file_missing(self, mock_internal):
        with self.assertRaises(FileNotFoundError):
            main_module.main()


if __name__ == "__main__":
    unittest.main()
