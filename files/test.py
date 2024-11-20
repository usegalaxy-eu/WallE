import unittest
from datetime import datetime, timedelta
import pathlib
import tempfile
from walle import NotificationHistory, GalaxyAPI, Severity
import json

SLACK_NOTIFY_PERIOD_DAYS = 7

from unittest.mock import patch, Mock

ONLY_ONE_INSTANCE = "The other must be an instance of the Severity class"


class TestSeverity(unittest.TestCase):
    def setUp(self):
        self.low = Severity(1, "Low")
        self.medium = Severity(2, "Medium")
        self.high = Severity(3, "High")

    def test_equality_same_values(self):
        # Arrange
        other_low = Severity(1, "Low")

        # Act & Assert
        self.assertEqual(self.low, other_low)

    def test_equality_different_values(self):
        # Arrange
        other_medium = Severity(2, "Medium")

        # Act & Assert
        self.assertNotEqual(self.low, other_medium)

    def test_equality_raises_value_error(self):
        # Arrange
        invalid_comparison = "Not a Severity"

        # Act & Assert
        with self.assertRaises(ValueError) as context:
            self.low == invalid_comparison
        self.assertEqual(str(context.exception), ONLY_ONE_INSTANCE)

    def test_less_than_or_equal_success(self):
        # Act & Assert
        self.assertTrue(self.low <= self.medium)
        self.assertTrue(self.low <= self.low)
        self.assertFalse(self.medium <= self.low)

    def test_less_than_or_equal_raises_value_error(self):
        # Arrange
        invalid_comparison = "Not a Severity"

        # Act & Assert
        with self.assertRaises(ValueError) as context:
            self.low <= invalid_comparison
        self.assertEqual(str(context.exception), ONLY_ONE_INSTANCE)

    def test_greater_than_or_equal_success(self):
        # Act & Assert
        self.assertTrue(self.medium >= self.low)
        self.assertTrue(self.high >= self.high)
        self.assertFalse(self.low >= self.medium)

    def test_greater_than_or_equal_raises_value_error(self):
        # Arrange
        invalid_comparison = "Not a Severity"

        # Act & Assert
        with self.assertRaises(ValueError) as context:
            self.low >= invalid_comparison
        self.assertEqual(str(context.exception), ONLY_ONE_INSTANCE)


class TestGalaxyAPI(unittest.TestCase):
    def setUp(self):
        self.api = GalaxyAPI(
            base_url="http://example.com",
            api_key="test_key",
            delete_subject="Account Deletion",
            delete_message="Your account has been deleted.",
        )

    @patch("walle.requests.post")
    def test_notify_user_success(self, mock_post):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        encoded_user_id = "encoded123"

        # Act
        result = self.api.notify_user(encoded_user_id)

        # Assert
        self.assertTrue(result)
        # Validate JSON body
        expected_json = {
            "recipients": {"user_ids": ["encoded123"], "group_ids": [], "role_ids": []},
            "notification": {
                "source": "WALLE",
                "category": "message",
                "variant": "urgent",
                "content": {
                    "subject": "Account Deletion",
                    "message": "Your account has been deleted.",
                    "category": "message",
                },
            },
        }
        # Validate JSON structure
        try:
            # Extract the actual JSON passed to the mock
            actual_json = mock_post.call_args.kwargs["json"]
            # Check if it matches expected JSON structure
            self.assertEqual(
                json.dumps(actual_json, sort_keys=True),
                json.dumps(expected_json, sort_keys=True),
            )
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON structure: {e}")

        # Ensure mock was called with correct arguments
        mock_post.assert_called_once_with(
            url="http://example.com/api/notifications",
            headers={"x-api-key": "test_key"},
            json=expected_json,
        )

    @patch("walle.requests.post")
    def test_notify_user_failure(self, mock_post):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response
        encoded_user_id = "encoded123"

        # Act
        result = self.api.notify_user(encoded_user_id)

        # Assert
        self.assertFalse(result)

    @patch("walle.requests.delete")
    def test_delete_user_success(self, mock_delete):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response
        encoded_user_id = "encoded123"

        # Act
        result = self.api.delete_user(encoded_user_id)

        # Assert
        self.assertTrue(result)
        mock_delete.assert_called_once_with(
            url="http://example.com/api/users/encoded123",
            headers={"x-api-key": "test_key"},
        )

    @patch("walle.requests.delete")
    def test_delete_user_failure(self, mock_delete):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 404
        mock_delete.return_value = mock_response
        decoded_id = "123"

        # Act
        result = self.api.delete_user(decoded_id)

        # Assert
        self.assertFalse(result)

    @patch("walle.requests.get")
    def test_encode_galaxy_user_id_success(self, mock_get):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"encoded_id": "encoded123"}
        mock_get.return_value = mock_response
        decoded_id = "123"

        # Act
        result = self.api.encode_galaxy_user_id(decoded_id)

        # Assert
        self.assertEqual(result, "encoded123")
        mock_get.assert_called_once_with(
            url="http://example.com/api/configuration/encode/123",
            headers={"x-api-key": "test_key"},
        )

    @patch("walle.requests.get")
    def test_encode_galaxy_user_id_failure(self, mock_get):
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        decoded_id = "decoded456"

        # Act
        result = self.api.encode_galaxy_user_id(decoded_id)

        # Assert
        self.assertEqual(result, "")

    @patch("walle.GalaxyAPI.notify_user")
    @patch("walle.GalaxyAPI.delete_user")
    @patch("walle.GalaxyAPI.encode_galaxy_user_id")
    def test_encode_id_notify_and_delete_user_success(
        self, mock_encode, mock_delete, mock_notify
    ):
        # Arrange
        mock_encode.return_value = "encoded123"
        mock_notify.return_value = True
        mock_delete.return_value = True
        user_id = "decoded456"

        # Act
        self.api.encode_id_notify_and_delete_user(user_id)

        # Assert
        mock_encode.assert_called_once_with(decoded_id=user_id)
        mock_notify.assert_called_once_with("encoded123")
        mock_delete.assert_called_once_with("encoded123")

    @patch("walle.GalaxyAPI.notify_user")
    @patch("walle.GalaxyAPI.encode_galaxy_user_id")
    def test_encode_id_notify_and_delete_user_notify_failure(
        self, mock_encode, mock_notify
    ):
        # Arrange
        mock_encode.return_value = "encoded123"
        mock_notify.return_value = False
        user_id = "decoded456"

        # Act
        self.api.encode_id_notify_and_delete_user(user_id)

        # Assert
        mock_encode.assert_called_once_with(decoded_id=user_id)
        mock_notify.assert_called_once_with("encoded123")


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
        self.record._write_record(jwd)
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
