import unittest
import logging
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add the project root to sys.path so Python finds the 'src' folder
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.logger import setup_logger




class TestLoggerSetup(unittest.TestCase):

    def setUp(self):
        # Reset logger handlers before each test
        logger = logging.getLogger("ioc_enrichment")
        logger.handlers = []

    def test_logger_sets_correct_level(self):
        logger = setup_logger("test.log")
        self.assertEqual(logger.level, logging.DEBUG)

    def test_logger_adds_handlers_once(self):
        logger = setup_logger("test.log")
        handler_count_first = len(logger.handlers)
        logger = setup_logger("test.log")  # should not add more handlers
        handler_count_second = len(logger.handlers)
        self.assertEqual(handler_count_first, 2)
        self.assertEqual(handler_count_first, handler_count_second)

    @patch("logging.FileHandler")
    def test_logger_filehandler_called_with_logfile(self, mock_filehandler):
        setup_logger("custom.log")
        mock_filehandler.assert_called_once_with("custom.log")

    def test_logger_output_format(self):
        logger = setup_logger("temp.log")
        formatter = logger.handlers[0].formatter
        self.assertIsNotNone(formatter)
        self.assertIn("%(levelname)s", formatter._fmt)

    @patch("logging.FileHandler", side_effect=PermissionError("No write access"))
    def test_logger_file_permission_error(self, mock_filehandler):
        with self.assertRaises(PermissionError):
            setup_logger("/protected/log.log")

if __name__ == "__main__":
    unittest.main()
