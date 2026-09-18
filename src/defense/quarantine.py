# src/defense/quarantine.py

import os
import shutil


class Quarantine:

    def __init__(self, logger=None):
        self.logger = logger

        # safer absolute path
        self.quarantine_dir = os.path.join("data", "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    # =====================================
    # QUARANTINE FILE (MAIN METHOD)
    # =====================================
    def quarantine_file(self, path_or_alert):

        # ---------------------------------
        # Handle both input types
        # ---------------------------------
        if isinstance(path_or_alert, dict):
            path = path_or_alert.get("path")
        else:
            path = path_or_alert

        if not path:
            if self.logger:
                self.logger.warning("[QUARANTINE] No file path found")
            return

        if not os.path.exists(path):
            if self.logger:
                self.logger.warning(f"[QUARANTINE] File missing: {path}")
            return

        try:
            filename = os.path.basename(path)

            destination = os.path.join(
                self.quarantine_dir,
                filename
            )

            shutil.move(path, destination)

            if self.logger:
                self.logger.critical(
                    f"[QUARANTINE] File moved: {destination}"
                )

            print(f"\n🦠 FILE QUARANTINED: {filename}\n")

        except Exception as e:
            if self.logger:
                self.logger.error(f"[QUARANTINE ERROR] {e}")
