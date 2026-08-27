### 2. `SECURITY.md`

```markdown
# Security Policy

## Supported Versions

Only the latest release of the Tableau Server Disaster Recovery Framework receives active security updates and patches.

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

---

## Security Boundaries & Design Considerations

This framework interacts directly with administrative subsystem binaries (`tsm.cmd` / `tsm`) and cloud key vaults. To maintain security integrity:

1. **Credential Exposure:** Never check in `config/config.yaml` or any credentials. Use environment variables or `DefaultAzureCredential` managed identities.
2. **Command Sanitization:** All internal process execution arguments pass through `TSMConnector` sanitization logic to strip sensitive CLI flags (`--password`, `--passphrase`) from standard output logging.
3. **Restricted File System Permissions:** Temporary staging directories containing decrypted SSL certificates or TSM exported settings should have ACLs limited exclusively to the Tableau Service Account user.

---

## Reporting a Vulnerability

If you discover a security vulnerability within this repository, please **do not raise a public GitHub issue**.

Instead, report the security vulnerability privately:
1. Email: `security-contact@your-domain.com` (or create a private GitHub Security Advisory).
2. Include steps to reproduce the issue along with any log outputs.

You will receive an initial response within 48 hours confirming receipt, followed by periodic updates regarding remediation.


