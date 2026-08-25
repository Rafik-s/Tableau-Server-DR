import datetime
import os
from defaults import DEFAULT_CONFIG_PATH, DEFAULT_BACKUP_DIR, DEFAULT_EXPORT_DIR
from tableau_dr.config_parser_class import ConfigParser
from tableau_dr.tab_server_connector import TSMConnector
from tableau_dr.utils import log, run_azcopy

def run_backup(config_path=DEFAULT_CONFIG_PATH):
    log("Parsing configuration...")
    config = ConfigParser(config_path)
    azure_cfg = config.get_azure_config()
    
    tsm = TSMConnector()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"tableau_backup_{timestamp}"
    
    log("Running TSM cleanup...")
    tsm.cleanup()
    
    log("Exporting TSM settings...")
    os.makedirs(DEFAULT_EXPORT_DIR, exist_ok=True)
    settings_file = os.path.join(DEFAULT_EXPORT_DIR, f"settings_{timestamp}.json")
    tsm.export_settings(settings_file)
    
    log("Generating TSM backup...")
    tsm.create_backup(backup_name)
    
    log("Uploading artifacts to Azure Blob Storage...")
    container_url = f"https://{azure_cfg['storage_account_name']}.blob.core.windows.net/{azure_cfg['storage_container']}/{timestamp}"
    backup_file_path = os.path.join(DEFAULT_BACKUP_DIR, f"{backup_name}.tsbak")
    
    run_azcopy(backup_file_path, f"{container_url}/tableau_backup.tsbak")
    run_azcopy(settings_file, f"{container_url}/settings.json")
    
    log("Backup procedure complete.")

if __name__ == "__main__":
    run_backup()