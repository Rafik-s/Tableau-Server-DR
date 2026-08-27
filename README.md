# Tableau-Server-DR
# Tableau Server Modern TSM Disaster Recovery (Azure)

Tableau-Server-DR/
│
├── tableau_dr/
│   ├── __init__.py
│   │
│   ├── config.py
│   ├── exceptions.py
│   ├── logger.py
│   │
│   ├── tab_server_connector.py
│   ├── security.py
│   ├── validation.py
│   │
│   ├── azure_manager.py
│   ├── backup_manager.py
│   │
│   ├── fencing.py
│   ├── recovery_manager.py
│   ├── health_check.py
│   └── dr_orchestrator.py
│
├── execute_backup.py
├── execute_switchover.py
│
├── config/
│   └── config.yaml.example
│
├── tests/
│   ├── test_config.py
│   ├── test_security.py
│   ├── test_tsm_connector.py
│   ├── test_azure_manager.py
│   ├── test_backup_manager.py
│   ├── test_fencing.py
│   ├── test_recovery_manager.py
│   └── test_health_check.py
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── requirements.txt
├── README.md
├── SECURITY.md
├── LICENSE
└── .gitignore


Target Archiechuture

                    ┌──────────────────────┐
                    │ execute_backup.py    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ BackupManager        │
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
          Preflight          TSM           Security
                │              │              │
                └──────────────┼──────────────┘
                               ▼
                        Local Artifacts
                               │
                               ▼
                         SHA-256 Hash
                               │
                               ▼
                           Manifest
                               │
                               ▼
                       Azure Blob SDK
                               │
                               ▼
                       Remote Verification
                               │
                    ┌──────────┴──────────┐
                    │                     │
                  PASS                  FAIL
                    │                     │
                    ▼                     ▼
             Local Cleanup          Preserve Files



                  execute_switchover.py
                           │
                           ▼
                     DR Orchestrator
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
         Fencing Gate             Operator Approval
              │
              ▼
       Manifest Verification
              │
              ▼
       Artifact Verification
              │
              ▼
          DR Stop
              │
              ▼
          Restore
              │
              ▼
       Settings Import
              │
              ▼
      SSL/SAML Rebinding
              │
              ▼
           Start
              │
              ▼
        Health Checks
              │
              ▼
          RPO/RTO
              │
              ▼
       RecoveryResult



# Enterprise Tableau Server Disaster Recovery Framework

An enterprise-grade, automated Disaster Recovery (DR) and business continuity framework for Tableau Server deployments. Built for high availability, zero data loss (low RPO/RTO), and strict split-brain prevention using Azure Cloud infrastructure and TSM CLI automation.

## Key Architectural Features

* **State-Machine Recovery Engine:** Strict 10-stage sequential failover workflow with isolated state transitions.
* **Production Fencer:** Prevents active-active/split-brain states by validating network and HTTP isolation before initiating DR restore.
* **Cryptographic Integrity Verification:** Standardized SHA-256 digest validation for backups, settings, and manifests via Azure Storage Blob metadata and stream re-hashing.
* **Non-Interactive Execution:** Process-isolated TSM executions detaching `stdin` to prevent hung automation pipelines.
* **Multi-Layer Health Engine:** Post-restoration health verification across TSM processes, SSL gateways, Vizportal APIs, and Tableau licensing states.
* **RPO/RTO Audit Metrics:** Automatic calculation and reporting of recovery point age and overall time to restore.

---

## Directory Layout

```text
Tableau-Server-DR/
├── tableau_dr/             # Core Python framework package
│   ├── config.py           # Strict YAML schema validation
│   ├── tab_server_connector.py # Safe TSM CLI subprocess wrapper
│   ├── backup_manager.py   # Isolated backup pipeline & manifest generation
│   ├── fencing.py          # Production network isolation validator
│   ├── recovery_manager.py # State-machine driven failover engine
│   ├── health_check.py     # Post-restore verification engine
│   └── azure_manager.py    # Azure SDK Blob Storage driver
├── execute_backup.py       # Production CLI backup driver
├── execute_switchover.py   # Disaster recovery failover CLI driver
├── config/                 # Configuration templates
├── tests/                  # Pytest automated testing suite
└── .github/workflows/      # CI/CD pipelines

