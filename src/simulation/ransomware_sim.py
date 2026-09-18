import os
import time
from pathlib import Path


# ✅ FIX: always resolve project root correctly
BASE_DIR = Path(__file__).resolve().parents[2]
TARGET_FOLDER = BASE_DIR / "tests"


def encrypt_simulation(file_path):
    """
    SAFE SIMULATION ONLY:
    - does NOT use real encryption
    - just renames file + corrupts content visually
    """

    try:
        with open(file_path, "r", errors="ignore") as f:
            data = f.read()

        # fake "encryption"
        fake_data = "ENCRYPTED::" + data[::-1]

        with open(file_path, "w") as f:
            f.write(fake_data)

        os.rename(file_path, str(file_path) + ".locked")

        print(f"[RANSOMWARE SIM] Encrypted: {file_path}")

    except Exception as e:
        print(f"[ERROR] {e}")


def run():

    print("🧨 Ransomware Simulation Started (SAFE MODE)")
    print("Target folder:", TARGET_FOLDER)

    if not TARGET_FOLDER.exists():
        print("Tests folder not found!")
        return

    while True:

        files = list(TARGET_FOLDER.glob("*"))

        for file in files:
            if file.is_file() and not file.name.endswith(".locked"):
                encrypt_simulation(file)

        time.sleep(3)


if __name__ == "__main__":
    run()
