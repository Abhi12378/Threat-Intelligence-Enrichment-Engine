import unittest
import json
from unittest.mock import patch, mock_open
from io import StringIO
import csv

from pathlib import Path
import sys

# Add src directory to path if needed
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src import feeds_loader


class TestFeedsLoader(unittest.TestCase):

    # === load_internal_feed ===

    @patch("builtins.open", new_callable=mock_open, read_data="ioc1\nioc2\n")
    def test_load_internal_feed_positive(self, mock_file):
        result = feeds_loader.load_internal_feed("dummy.txt")
        self.assertEqual(result, {"ioc1", "ioc2"})

    @patch("builtins.open", new_callable=mock_open, read_data="")
    def test_load_internal_feed_empty_file(self, mock_file):
        result = feeds_loader.load_internal_feed("empty.txt")
        self.assertEqual(result, set())

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_load_internal_feed_file_not_found(self, mock_file):
        with self.assertRaises(FileNotFoundError):
            feeds_loader.load_internal_feed("missing.txt")

    # === load_misp_feed ===

    @patch("builtins.open", new_callable=mock_open, read_data='["hash1", "hash2"]')
    def test_load_misp_feed_positive(self, mock_file):
        result = feeds_loader.load_misp_feed("misp.json")
        self.assertEqual(result, {"hash1", "hash2"})

    @patch("builtins.open", new_callable=mock_open, read_data="bad json")
    def test_load_misp_feed_invalid_json(self, mock_file):
        with self.assertRaises(json.JSONDecodeError):
            feeds_loader.load_misp_feed("invalid.json")

    # === load_osint_feed ===

    @patch("builtins.open", new_callable=mock_open, read_data="ioc\nabc.com\nxyz.org\n")
    def test_load_osint_feed_positive(self, mock_file):
        with patch("csv.DictReader", return_value=[{"ioc": "abc.com"}, {"ioc": "xyz.org"}]):
            result = feeds_loader.load_osint_feed("osint.csv")
            self.assertEqual(result, {"abc.com", "xyz.org"})

    @patch("builtins.open", new_callable=mock_open, read_data="ioc\n\n\n")
    def test_load_osint_feed_empty_entries(self, mock_file):
        with patch("csv.DictReader", return_value=[{"ioc": ""}, {"ioc": ""}]):
            result = feeds_loader.load_osint_feed("empty.csv")
            self.assertEqual(result, set())

    @patch("builtins.open", side_effect=OSError("read error"))
    def test_load_osint_feed_oserror(self, mock_file):
        with self.assertRaises(OSError):
            feeds_loader.load_osint_feed("bad.csv")

    # === load_threat_rules ===

    @patch("builtins.open", new_callable=mock_open, read_data='{"patterns": [{"keyword": "mal", "threat_type": "malware"}]}')
    def test_load_threat_rules_positive(self, mock_file):
        result = feeds_loader.load_threat_rules("rules.json")
        self.assertEqual(result, [{"keyword": "mal", "threat_type": "malware"}])

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_load_threat_rules_missing_patterns(self, mock_file):
        with self.assertRaises(KeyError):
            feeds_loader.load_threat_rules("empty.json")

    # === load_all_feeds ===

    @patch("src.feeds_loader.load_internal_feed", return_value={"ip1"})
    @patch("src.feeds_loader.load_misp_feed", return_value={"hash1"})
    @patch("src.feeds_loader.load_osint_feed", return_value={"domain1"})
    def test_load_all_feeds_combined(self, mock_osint, mock_misp, mock_internal):
        result = feeds_loader.load_all_feeds("a.txt", "b.json", "c.csv")
        expected = {
            "internal": {"ip1"},
            "misp": {"hash1"},
            "osint": {"domain1"}
        }
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
