import os
import sys
import urllib.request
import shutil
import subprocess
from pathlib import Path

# ===== CONFIG =====
DB_NAME = "neo4j"
NEO4J_VERSION = "5.26.2"
NEO4J_PASSWORD = "password"  
ZENODO_URL = "https://zenodo.org/records/16814371/files/neo4j.dump?download=1"
DUMP_FILE = "neo4j.dump"


VOL_DATA = "neo4j_data"
VOL_LOGS = "neo4j_logs"
VOL_IMPORT = "neo4j_import"

def run(cmd):
    print(f"\n[RUN] {cmd}")
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        sys.exit(f"ERROR: command failed (exit {rc})")

def ensure_tool(name):
    if shutil.which(name) is None:
        sys.exit(f"ERROR: '{name}' is not installed or not in PATH.")

def download_dump():
    if Path(DUMP_FILE).exists():
        print(f"[INFO] {DUMP_FILE} already exists, skipping download.")
        return
    print(f"[INFO] Downloading dump from Zenodo -> {DUMP_FILE}")
    try:
        urllib.request.urlretrieve(ZENODO_URL, DUMP_FILE)
    except Exception as e:
        sys.exit(f"ERROR: download failed: {e}")

def load_into_volume():

    print("[INFO] Loading dump into named Docker volume (data)...")
    backup_mount = f"-v \"{os.getcwd()}:/backup\""
    run(
        f"docker run --rm "
        f"-v {VOL_DATA}:/data "
        f"{backup_mount} "
        f"neo4j:{NEO4J_VERSION} "
        f"/var/lib/neo4j/bin/neo4j-admin database load {DB_NAME} "
        f"--from-path=/backup --overwrite-destination=true"
    )

def start_server_container():
    print("[INFO] Starting Neo4j server container...")
    
    run("docker rm -f neo4j >NUL 2>&1" if os.name == "nt" else "docker rm -f neo4j >/dev/null 2>&1 || true")

    run(
        "docker run -d --name neo4j "
        "-p 7474:7474 -p 7687:7687 "
        f"-e NEO4J_AUTH=neo4j/{NEO4J_PASSWORD} "
        "-e NEO4J_PLUGINS='[\"apoc\",\"graph-data-science\"]' "
        f"-v {VOL_DATA}:/data "
        f"-v {VOL_LOGS}:/logs "
        f"-v {VOL_IMPORT}:/import "
        f"neo4j:{NEO4J_VERSION}"
    )
    print("\n[INFO] Neo4j is starting. UI: http://localhost:7474")
    print(f"[INFO] Login: neo4j / {NEO4J_PASSWORD}")

def main():
    ensure_tool("docker")

    download_dump()
    if not Path(DUMP_FILE).exists() or Path(DUMP_FILE).stat().st_size == 0:
        sys.exit("ERROR: dump file missing or empty after download.")


    load_into_volume()


    start_server_container()


    try:
        Path(DUMP_FILE).unlink()
        print(f"[INFO] Removed {DUMP_FILE} to save space.")
    except Exception:
        pass

if __name__ == "__main__":
    main()

