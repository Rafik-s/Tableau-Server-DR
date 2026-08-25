from defaults import DEFAULT_CONFIG_PATH, DEFAULT_BACKUP_DIR
from tableau_dr.config_parser_class import ConfigParser
from tableau_dr.tab_server_connector import TSMConnector
from tableau_dr.utils import log

def run_switchover(backup_file_name, config_path=DEFAULT_CONFIG_PATH):
    log("Starting DR Switchover / Restore...")
    config = ConfigParser(config_path)
    sec_cfg = config.get_security_config()
    
    tsm = TSMConnector()
    
    log("Configuring SSL and SAML...")
    ssl_info = sec_cfg.get("ssl", {})
    tsm.run_tsm_cmd(["security", "external-ssl", "enable", "--cert-file", ssl_info["cert_file_path"], "--key-file", ssl_info["key_file_path"]])
    
    log("Applying TSM pending changes...")
    tsm.apply_changes()
    
    log(f"Restoring backup file: {backup_file_name}...")
    tsm.restore_backup(backup_file_name)
    
    log("Starting Tableau Server on DR node...")
    tsm.run_tsm_cmd(["start"])
    log("Switchover successful!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_switchover(sys.argv[1])
    else:
        print("Usage: python execute_switchover.py <backup_filename.tsbak>")