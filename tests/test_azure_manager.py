"""Unit tests for the Azure Blob Storage management module."""

import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from tableau_dr.azure_manager import AzureManager
from tableau_dr.exceptions import SecurityValidationError, ValidationError


class TestAzureManager(unittest.TestCase):

    @patch("tableau_dr.azure_manager.BlobServiceClient")
    @patch("tableau_dr.azure_manager.DefaultAzureCredential")
    def setUp(self, mock_credential, mock_blob_service):
        self.mock_service = mock_blob_service.return_value
        self.mock_container = MagicMock()
        self.mock_service.get_container_client.return_value = self.mock_container

        self.azure_mgr = AzureManager(
            account_name="testaccount",
            container_name="testcontainer",
            max_retries=2,
            backoff_factor=0.5,
        )

    def test_upload_file_success(self, tmp_path):
        dummy_file = tmp_path / "test_artifact.txt"
        dummy_file.write_text("dummy payload content")
        
        mock_blob_client = MagicMock()
        self.mock_container.get_blob_client.return_value = mock_blob_client

        blob_path = self.azure_mgr.upload_file(
            local_path=dummy_file,
            blob_path="backups/test_artifact.txt",
            sha256_checksum="dummyhash123",
        )

        self.assertEqual(blob_path, "backups/test_artifact.txt")
        mock_blob_client.upload_blob.assert_called_once()

    def test_verify_remote_blob_success(self):
        mock_blob_client = MagicMock()
        mock_props = MagicMock()
        mock_props.size = 1024
        mock_props.metadata = {"sha256": "abcdef1234567890"}
        mock_blob_client.get_blob_properties.return_value = mock_props
        self.mock_container.get_blob_client.return_value = mock_blob_client

        result = self.azure_mgr.verify_remote_blob(
            blob_path="backups/file.tsbak",
            expected_size_bytes=1024,
            expected_sha256="ABCDEF1234567890",
            verify_content_stream=False,
        )
        self.assertTrue(result)

    def test_verify_remote_blob_size_mismatch(self):
        mock_blob_client = MagicMock()
        mock_props = MagicMock()
        mock_props.size = 2048
        mock_blob_client.get_blob_properties.return_value = mock_props
        self.mock_container.get_blob_client.return_value = mock_blob_client

        with self.assertRaises(SecurityValidationError):
            self.azure_mgr.verify_remote_blob(
                blob_path="backups/file.tsbak",
                expected_size_bytes=1024,
                expected_sha256="ABCDEF1234567890",
            )


if __name__ == "__main__":
    unittest.main()