import os
import shutil
from pathlib import Path

# backup storage
BACKUP_DIR = Path("data/backups")

# create folder automatically
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# CREATE BACKUP
# ==========================================
def backup_file(file_path):

    try:

        file_path = Path(file_path)

        # skip if file missing
        if not file_path.exists():
            return False

        # skip already locked files
        if str(file_path).endswith(".locked"):
            return False

        backup_name = file_path.name + ".backup"

        backup_path = BACKUP_DIR / backup_name

        shutil.copy2(file_path, backup_path)

        print(f"💾 Backup created: {backup_path}")

        return True

    except Exception as e:

        print(f"[BACKUP ERROR] {e}")

        return False


# ==========================================
# RESTORE FILE
# ==========================================
def restore_file(file_path):

    try:

        file_path = Path(file_path)

        original_name = file_path.name.replace(".locked", "")

        backup_path = BACKUP_DIR / (original_name + ".backup")

        if not backup_path.exists():

            print("⚠ No backup found")

            return False

        # restore original file
        shutil.copy2(backup_path, original_name)

        print(f"♻ File restored: {original_name}")

        return True

    except Exception as e:

        print(f"[RESTORE ERROR] {e}")

        return False
