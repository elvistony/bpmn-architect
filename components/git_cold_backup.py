import os
import shutil
import sqlite3
import subprocess
import traceback
from components.config import (
    DIAGRAM_STORAGE_PATH, DB_CONNECTION_STRING, 
    GIT_BACKUP_ENABLED, GIT_COMMIT_FORMAT, GIT_COMMIT_SYNTAX,
    BASE_DIR
)

def run_backup():
    if str(GIT_BACKUP_ENABLED).lower() != 'true':
        print("Git backup is disabled in config.")
        return

    staging_dir = BASE_DIR / "staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    print("Copying .bpmn files...")
    for file_path in DIAGRAM_STORAGE_PATH.glob("*.bpmn"):
        try:
            shutil.copy2(file_path, staging_dir / file_path.name)
        except Exception as e:
            print(f"Failed to copy {file_path.name}: {e}")

    try:
        db_path = DB_CONNECTION_STRING.replace("sqlite:///", "")
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            with open(staging_dir / 'diagrams_schema.sql', 'w') as f:
                for line in conn.iterdump():
                    f.write('%s\n' % line)
            
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT last_edited_by FROM diagrams ORDER BY updated_at DESC LIMIT 1")
                row = cursor.fetchone()
                last_edited_by = row[0] if row and row[0] else "System"
            except sqlite3.OperationalError:
                last_edited_by = "System"
            conn.close()
        else:
            last_edited_by = "System"
            print("DB not found.")
    except Exception as e:
        print(f"Failed to dump db: {e}")
        last_edited_by = "System"

    commit_msg = GIT_COMMIT_FORMAT.replace("<last_edited_by>", last_edited_by)
    commit_cmd = GIT_COMMIT_SYNTAX.replace("<commit_msg>", commit_msg)
    
    print(f"Running git commit syntax: {commit_cmd}")
    try:
        # Running from BASE_DIR since the app repository is likely the root
        subprocess.run(commit_cmd, shell=True, check=True, cwd=BASE_DIR)
        print("Backup successful.")
    except subprocess.CalledProcessError as e:
        print(f"Backup failed: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    run_backup()
