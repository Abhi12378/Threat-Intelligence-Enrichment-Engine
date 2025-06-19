import unittest
import json
import io
import sys
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

# Ensure src is in path
from src import utils


class TestUtils(unittest.TestCase):

    # === load_json ===

    @patch("builtins.open", new_callable=mock_open, read_data='{"key": "value"}')
    def test_load_json_valid_file(self, mock_file):
        result = utils.load_json("dummy.json")
        self.assertEqual(result, {"key": "value"})

    @patch("builtins.open", new_callable=mock_open, read_data='{bad json}')
    def test_load_json_invalid_syntax(self, mock_file):
        with self.assertRaises(json.JSONDecodeError):
            utils.load_json("corrupt.json")

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_load_json_file_not_found(self, mock_file):
        with self.assertRaises(FileNotFoundError):
            utils.load_json("missing.json")

    # === save_json ===

    @patch("builtins.open", new_callable=mock_open)
    def test_save_json_valid(self, mock_file):
        data = {"user": "saai"}
        utils.save_json(data, "output.json")
        mock_file.assert_called_with("output.json", "w")
        handle = mock_file()
        handle.write.assert_called()

    @patch("builtins.open", side_effect=PermissionError)
    def test_save_json_permission_error(self, mock_file):
        with self.assertRaises(PermissionError):
            utils.save_json({"x": 1}, "readonly.json")

    # === ensure_dirs_exist ===

    @patch("pathlib.Path.mkdir")
    def test_ensure_dirs_exist_creates(self, mock_mkdir):
        paths = ["dir1", "dir2"]
        utils.ensure_dirs_exist(paths)
        self.assertEqual(mock_mkdir.call_count, 2)
        mock_mkdir.assert_any_call(parents=True, exist_ok=True)

    @patch("pathlib.Path.mkdir", side_effect=OSError("disk full"))
    def test_ensure_dirs_exist_oserror(self, mock_mkdir):
        with self.assertRaises(OSError):
            utils.ensure_dirs_exist(["diskfull"])

if __name__ == "__main__":
    unittest.main()
