import unittest
from unittest.mock import patch
from datetime import datetime, timedelta
import pathlib
import tempfile
from walle import NotificationHistory

SLACK_NOTIFY_PERIOD_DAYS = 7


class TestNotificationHistory(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.record = NotificationHistory(self.temp_file.name)

    def tearDown(self):
        pathlib.Path(self.temp_file.name).unlink(missing_ok=True)

    def test_contains_new_entry(self):
        jwd = "unique_id_1"
        self.assertFalse(
            self.record.contains(jwd), "New entry should initially return False"
        )
        self.assertTrue(self.record.contains(jwd), "Duplicate entry should return True")

    def test_contains_existing_entry(self):
        jwd = "existing_id"
        with open(self.temp_file.name, "a") as f:
            f.write(f"{datetime.now()}\t{jwd}\n")
        self.assertTrue(self.record.contains(jwd), "Existing entry should return True")

    @patch("walle.SLACK_NOTIFY_PERIOD_DAYS", new=SLACK_NOTIFY_PERIOD_DAYS)
    def test_truncate_old_records(self):
        old_jwd = "old_entry"
        recent_jwd = "recent_entry"
        old_date = datetime.now() - timedelta(days=SLACK_NOTIFY_PERIOD_DAYS + 1)
        recent_date = datetime.now()

        with open(self.temp_file.name, "a") as f:
            f.write(f"{old_date.isoformat()}\t{old_jwd}\n")
            f.write(f"{recent_date.isoformat()}\t{recent_jwd}\n")

        self.record._truncate_records()
        self.assertFalse(self.record.contains(old_jwd), "Old entry should be purged")
        self.assertTrue(self.record.contains(recent_jwd), "Recent entry should remain")

    def test_purge_invalid_records(self):
        with open(self.temp_file.name, "w") as f:
            f.write("invalid_date\tinvalid_path\n")

        with patch("walle.logger.warning") as mock_warning:
            self.record._read_records()
            mock_warning.assert_called()

        self.assertFalse(self.record._get_jwds(), "Invalid records should be purged")


if __name__ == "__main__":
    unittest.main()
