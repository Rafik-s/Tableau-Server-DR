# Tableau-Server-DR
# Tableau Server Modern TSM Disaster Recovery (Azure)

tableau-server-tsm-dr/
│
├── config/
│   └── config.yaml.example          # Sample configuration file
│
     ├── tableau_dr/
        │
        ├── __init__.py
        ├── exceptions.py
        ├── config.py
        ├── logger.py
        ├── security.py
        ├── validation.py
        ├── tab_server_connector.py
        ├── azure_manager.py
        ├── backup_manager.py
        └── execute_backup.py
│
├── .gitignore
├── defaults.py                      # Default configuration constants and file paths
├── execute_switchover.py            # Main entry point for DR failover / switchover execution
├── README.md
├── 
├── requirements.txt                 # Python dependencies
├── 
└── validate_prepare_env.ps1         # PowerShell script to validate WinRM, Azure CLI, and TSM permissions



Automated backup, replication, and disaster recovery framework designed for **Tableau Server 2020.1+ through 2025.x** running on Windows Server with Azure Cloud infrastructure.

## Features
* TSM native automation (`tsm maintenance backup`, `tsm settings export`)
* Direct integration with Azure Blob Storage via `AzCopy` and Managed Identities
* Retains SSL and SAML authentication settings for DR failover
* No direct Postgres streaming required; fully compliant with modern Tableau architecture

## Quickstart
1. Install dependencies: `pip install -r requirements.txt`
2. Run validation script: `.\validate_prepare_env.ps1`
3. Copy `config/config.yaml.example` to `config/config.yaml` and update settings.
4. Execute scheduled backup: `python tableau_dr.py`
5. Execute failover on DR node: `python execute_switchover.py <backup_filename.tsbak>`

