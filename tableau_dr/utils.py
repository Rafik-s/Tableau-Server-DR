import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log(msg):
    logging.info(msg)

def run_azcopy(source, destination):
    cmd = ["azcopy", "copy", source, destination, "--recursive=true"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"AzCopy Error: {result.stderr}")
    return result.stdout