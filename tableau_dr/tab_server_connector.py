import subprocess
import datetime

class TSMConnector:
    @staticmethod
    def run_tsm_cmd(cmd_list):
        result = subprocess.run(["tsm"] + cmd_list, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            raise RuntimeError(f"TSM Error: {result.stderr}")
        return result.stdout

    def cleanup(self):
        return self.run_tsm_cmd(["maintenance", "cleanup", "--app-data-only"])

    def create_backup(self, backup_filename):
        return self.run_tsm_cmd(["maintenance", "backup", "-f", backup_filename, "-d"])

    def export_settings(self, export_path):
        return self.run_tsm_cmd(["settings", "export", "-f", export_path])

    def restore_backup(self, backup_filename):
        return self.run_tsm_cmd(["maintenance", "restore", "--file", backup_filename])

    def apply_changes(self):
        return self.run_tsm_cmd(["pending-changes", "apply", "--ignore-prompt"])