import os
import unittest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

from modules.database_management import credential_service


class DatabaseCredentialTests(unittest.TestCase):
    def setUp(self):
        self.encryption_key = Fernet.generate_key().decode("ascii")
        self.env_patch = patch.dict(
            os.environ,
            {"DATABASE_CREDENTIALS_ENCRYPTION_KEY": self.encryption_key},
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_passwords_are_encrypted_and_round_trip(self):
        password = "test-database-password"
        ciphertext = credential_service._encrypt_password(password)

        self.assertNotEqual(ciphertext, password)
        self.assertNotIn(password, ciphertext)
        self.assertEqual(credential_service._decrypt_password(ciphertext), password)

    def test_wrong_encryption_key_fails_without_returning_ciphertext(self):
        ciphertext = credential_service._encrypt_password("test-database-password")
        with patch.dict(
            os.environ,
            {"DATABASE_CREDENTIALS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")},
        ):
            with self.assertRaisesRegex(RuntimeError, "could not be decrypted"):
                credential_service._decrypt_password(ciphertext)

    def test_missing_encryption_key_fails_explicitly(self):
        with patch.dict(os.environ, {"DATABASE_CREDENTIALS_ENCRYPTION_KEY": ""}):
            with self.assertRaisesRegex(RuntimeError, "must be configured"):
                credential_service._encrypt_password("test-database-password")

    def test_saving_connection_persists_ciphertext_not_plaintext(self):
        password = "test-database-password"
        database = MagicMock()
        cursor = database.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = {"id": 17}
        public_record = {"id": 17, "databaseAlias": "Test DB"}

        with patch.object(credential_service, "store", return_value=database), patch.object(
            credential_service, "get_database", return_value=public_record,
        ) as get_database:
            result = credential_service.save_database(
                "Test DB",
                {
                    "host": "db.example.test", "port": 5432, "database": "test_db",
                    "username": "app_user", "password": password, "sslmode": "require",
                },
                environment="TEST",
            )

        query, parameters = cursor.execute.call_args.args
        self.assertIn("password_ciphertext", query)
        self.assertNotIn(password, parameters)
        self.assertEqual(
            credential_service._decrypt_password(parameters[7]),
            password,
        )
        get_database.assert_called_once_with(17)
        self.assertEqual(result, public_record)

    def test_saved_password_is_decrypted_only_for_server_connection_use(self):
        ciphertext = credential_service._encrypt_password("test-database-password")
        database = MagicMock()
        cursor = database.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = {"password_ciphertext": ciphertext}

        with patch.object(credential_service, "store", return_value=database):
            password = credential_service.get_database_password(17)

        self.assertEqual(password, "test-database-password")

    def test_database_list_reads_only_explicitly_saved_connections(self):
        database = MagicMock()
        cursor = database.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = []

        with patch.object(credential_service, "store", return_value=database):
            records = credential_service.list_databases()

        query = cursor.execute.call_args.args[0]
        self.assertIn("FROM tbl_database_credentials", query)
        self.assertNotIn("APP_DATABASE_URL", query)
        self.assertEqual(records, [])

    def test_delete_database_removes_only_the_saved_connection_record(self):
        database = MagicMock()
        connection = database.__enter__.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = {"id": 17}

        with patch.object(credential_service, "store", return_value=database):
            credential_service.delete_database(17)

        query, parameters = cursor.execute.call_args.args
        self.assertIn("DELETE FROM tbl_database_credentials", query)
        self.assertEqual(parameters, (17,))
        connection.commit.assert_called_once_with()

    def test_public_database_record_never_includes_password(self):
        record = credential_service._row_to_public({
            "id": 17, "database_alias": "Test DB", "host": "db.example.test",
            "port": 5432, "database_name": "test_db", "username": "app_user",
            "environment": "TEST", "sslmode": "require",
            "password_ciphertext": "secret-ciphertext",
        })

        self.assertNotIn("password", record)
        self.assertNotIn("password_ciphertext", record)


if __name__ == "__main__":
    unittest.main()
