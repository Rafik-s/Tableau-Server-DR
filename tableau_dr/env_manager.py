from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

class AzureEnvManager:
    def __init__(self, key_vault_name, storage_account_name):
        self.credential = DefaultAzureCredential()
        self.kv_url = f"https://{key_vault_name}.vault.azure.net/"
        self.blob_url = f"https://{storage_account_name}.blob.core.windows.net/"
        self.secret_client = SecretClient(vault_url=self.kv_url, credential=self.credential)

    def get_secret(self, secret_name):
        return self.secret_client.get_secret(secret_name).value

    def get_blob_service_client(self):
        return BlobServiceClient(account_url=self.blob_url, credential=self.credential)