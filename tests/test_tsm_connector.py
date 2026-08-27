from tableau_dr.tab_server_connector import TSMConnector

def test_tsm_sanitization():
    cmd = ["tsm", "login", "-u", "admin", "-p", "SuperSecret123"]
    sanitized = TSMConnector._sanitize_command_list(cmd)
    assert "***REDACTED***" in sanitized
    assert "SuperSecret123" not in sanitized