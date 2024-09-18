import unittest
from unittest.mock import patch, MagicMock, call
import pathlib
import os
import argparse
import walle

# Assuming the following classes are defined elsewhere
# UserId, UserMail, UserIdMail, Malware, Severity, etc.
# I'll mock them here for the purpose of testing


class TestJobClass(unittest.TestCase):

    def setUp(self):
        self.mock_user_id = MagicMock()
        self.mock_user_mail = MagicMock()
        self.mock_tool_id = "tool_123"
        self.mock_galaxy_id = 1
        self.mock_runner_id = 1
        self.mock_runner_name = "runner_1"
        self.mock_object_store_id = 1
        self.mock_jwd = pathlib.Path("/mock/jwd")
        self.mock_files = []

        self.job = walle.Job(
            user_id=self.mock_user_id,
            user_name="test_user",
            user_mail=self.mock_user_mail,
            tool_id=self.mock_tool_id,
            galaxy_id=self.mock_galaxy_id,
            runner_id=self.mock_runner_id,
            runner_name=self.mock_runner_name,
            object_store_id=self.mock_object_store_id,
            jwd=self.mock_jwd,
            files=self.mock_files,
        )

    @patch("pathlib.Path.exists")
    def test_set_jwd_success(self, mock_exists):
        # Test when the jwd path exists
        mock_exists.return_value = True
        result = self.job.set_jwd("/new/jwd")
        self.assertTrue(result)
        self.assertEqual(self.job.jwd, pathlib.Path("/new/jwd"))

    @patch("pathlib.Path.exists")
    def test_set_jwd_failure(self, mock_exists):
        # Test when the jwd path does not exist
        mock_exists.return_value = False
        result = self.job.set_jwd("/new/jwd")
        self.assertFalse(result)
        self.assertNotEqual(self.job.jwd, pathlib.Path("/new/jwd"))

    @patch("os.walk")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("builtins.open", new_callable=MagicMock)
    def test_get_files(
        self, mock_open, mock_is_file, mock_exists, mock_stat, mock_walk
    ):
        # Set up the mocks
        mock_exists.return_value = True
        mock_is_file.return_value = True
        mock_walk.return_value = [
            ("/mock/jwd", ("subdir",), ("file1", "file2")),
        ]
        mock_stat.return_value = MagicMock()

        # Mocking file_in_size_range and file_accessed_in_range
        with patch("file_in_size_range", return_value=True), patch(
            "file_accessed_in_range", return_value=True
        ):
            args = argparse.Namespace(min_size=0, max_size=1000, since=0)
            result = self.job.get_files(args)
            self.assertTrue(result)

    @patch("file_in_size_range")
    @patch("file_accessed_in_range")
    @patch("pathlib.Path.exists")
    def test_get_files_no_files_found(
        self, mock_exists, mock_file_in_size_range, mock_file_accessed_in_range
    ):
        mock_exists.return_value = True
        mock_file_in_size_range.return_value = False
        mock_file_accessed_in_range.return_value = False

        args = argparse.Namespace(min_size=0, max_size=1000, since=0)
        result = self.job.get_files(args)
        self.assertFalse(result)

    @patch("logging.Logger.info")
    def test_report_id_and_user_name(self, mock_logger_info):
        result = self.job.report_id_and_user_name()
        mock_logger_info.assert_called_once_with(self.mock_user_id, "test_user")
        self.assertEqual(result, {self.mock_user_id: self.mock_user_mail})

    @patch("logging.Logger.debug")
    @patch("get_iso_time_utc_add_months")
    def test_report_matching_malware(self, mock_get_iso_time, mock_logger_debug):
        mock_malware = MagicMock()
        mock_malware.severity.name = "High"
        mock_malware.malware_class = "ClassA"
        mock_malware.program = "ProgramA"
        mock_malware.version = "1.0"

        # Add a mock file to the job
        self.job.files = [pathlib.Path("/mock/file")]

        # Call the method
        self.job.report_matching_malware(0, mock_malware)

        mock_get_iso_time.assert_called_once_with(0)
        mock_logger_debug.assert_called_once_with(
            mock_get_iso_time.return_value,
            "High",
            self.mock_user_id,
            "test_user",
            self.mock_user_mail,
            self.mock_tool_id,
            self.mock_galaxy_id,
            self.mock_runner_id,
            self.mock_runner_name,
            self.mock_object_store_id,
            "ClassA",
            "ProgramA",
            "1.0",
            pathlib.Path("/mock/file"),
        )

    def test_mark_for_deletion_case_severity_high(self):
        mock_severity = MagicMock()
        result = self.job.mark_for_deletion(case_severity=5, severity_level=3)
        self.assertEqual(result, {self.mock_user_id: self.mock_user_mail})

    def test_mark_for_deletion_case_severity_low(self):
        mock_severity = MagicMock()
        result = self.job.mark_for_deletion(case_severity=2, severity_level=3)
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
