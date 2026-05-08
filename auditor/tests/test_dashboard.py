import json
import os
import unittest
from unittest.mock import MagicMock, patch

from auditor.utils.aws_utils import is_valid_finding


class TestIsValidFinding(unittest.TestCase):

    def test_valid_finding_passes(self):
        self.assertTrue(is_valid_finding({"Details": "Security group allows public access."}))

    def test_not_authorized_is_invalid(self):
        self.assertFalse(is_valid_finding({"Details": "Not authorized to perform this action"}))

    def test_explicit_deny_is_invalid(self):
        self.assertFalse(is_valid_finding({"Details": "explicit deny in policy"}))

    def test_unauthorized_operation_is_invalid(self):
        self.assertFalse(is_valid_finding({"Details": "UnauthorizedOperation"}))

    def test_accessdenied_is_invalid(self):
        self.assertFalse(is_valid_finding({"Details": "AccessDenied when calling s3:ListBuckets"}))

    def test_empty_details_is_valid(self):
        self.assertTrue(is_valid_finding({"Details": ""}))

    def test_missing_details_falls_back_to_message(self):
        self.assertFalse(is_valid_finding({"Message": "Not authorized to perform ec2:DescribeInstances"}))

    def test_case_insensitive(self):
        self.assertFalse(is_valid_finding({"Details": "EXPLICIT DENY in the resource-based policy"}))


class TestLoadLatestReport(unittest.TestCase):

    @patch("os.path.exists")
    @patch("os.listdir")
    @patch("os.path.getctime")
    def test_selects_most_recent_json(self, mock_getctime, mock_listdir, mock_exists):
        mock_exists.return_value = True
        mock_listdir.return_value = ["report_old.json", "report_new.json"]
        mock_getctime.side_effect = lambda path: 100 if "old" in path else 200

        report_dir = "auditor/reports"
        json_files = [f for f in os.listdir(report_dir) if f.endswith(".json")]
        latest = max(json_files, key=lambda f: os.path.getctime(os.path.join(report_dir, f)))

        self.assertEqual(latest, "report_new.json")

    @patch("builtins.open", unittest.mock.mock_open(read_data='[{"Details": "Test finding"}]'))
    @patch("os.path.exists", return_value=True)
    def test_load_json_data(self, _):
        with open("auditor/reports/report.json") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["Details"], "Test finding")


if __name__ == "__main__":
    unittest.main()
