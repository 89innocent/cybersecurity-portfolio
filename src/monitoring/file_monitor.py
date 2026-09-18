import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.core.event_store import add_event
from src.detection.rule_engine import analyze
from src.defense.quarantine import Quarantine
from src.defense.backup_manager import backup_file, restore_file
from src.defense.email_alert import send_alert

# 🚫 Folders to ignore
EXCLUDED_DIRS = [
    "data/logs",
    "data/quarantine",
    "venv",
    "__pycache__",
    "data/backups"
]


class FileHandler(FileSystemEventHandler):

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.quarantine = Quarantine(logger)

    def is_excluded(self, path):
        return any(ex in path for ex in EXCLUDED_DIRS)

    # =====================================================
    # FILE CREATED
    # =====================================================
    def on_created(self, event):

        if event.is_directory or self.is_excluded(event.src_path):
            return

        event_data = {
            "type": "created",
            "path": event.src_path
        }

        result = analyze(event_data)

        severity = result.get("severity", "LOW")
        event_type = "File Created"

        path_lower = event.src_path.lower()

        suspicious_keywords = [
            "keylog",
            "payload",
            "inject",
            "backdoor",
            "rat",
            "stealer",
            "exploit",
            "malware",
            "shell",
            "trojan"
        ]

        suspicious_extensions = [
            ".exe",
            ".dll",
            ".bat",
            ".ps1",
            ".vbs",
            ".scr",
            ".sh"
        ]

        if any(word in path_lower for word in suspicious_keywords):
            severity = "HIGH"
            event_type = "Keylogger Behavior"

        if any(path_lower.endswith(ext) for ext in suspicious_extensions):
            severity = "HIGH"
            event_type = "Malware Dropper Detected"

        if severity != "HIGH":
            try:
                backup_file(event.src_path)
            except Exception as e:
                self.logger.error(f"Backup failed: {e}")

        msg = f"{event_type}: {event.src_path} | {severity}"

        print(msg)
        self.logger.warning(msg)

        add_event(
            event_type,
            severity,
            event.src_path,
            time.strftime("%Y-%m-%d %H:%M:%S"),
            {"pid": 0}
        )

        if severity == "HIGH":

            try:
                send_alert(
                    "🚨 SOC HIGH ALERT",
                    f"""
Threat Detected!

Type: {event_type}

Target:
{event.src_path}

Severity:
{severity}

Time:
{time.strftime("%Y-%m-%d %H:%M:%S")}
"""
                )
            except Exception as e:
                self.logger.error(f"Email alert failed: {e}")

            try:
                self.quarantine.quarantine_file(event.src_path)

            except Exception as e:
                self.logger.error(f"Quarantine failed: {e}")

    # =====================================================
    # FILE MODIFIED
    # =====================================================
    def on_modified(self, event):

        if event.is_directory or self.is_excluded(event.src_path):
            return

        event_data = {
            "type": "modified",
            "path": event.src_path
        }

        result = analyze(event_data)

        severity = result.get("severity", "LOW")
        event_type = "File Modified"

        path_lower = event.src_path.lower()

        try:

            # ==========================================
            # RANSOMWARE DETECTION
            # ==========================================
            if path_lower.endswith(".locked"):

                severity = "HIGH"
                event_type = "Ransomware Activity"

            else:

                try:
                    with open(event.src_path, "r", errors="ignore") as f:

                        content = f.read()

                        if "ENCRYPTED::" in content:
                            severity = "HIGH"
                            event_type = "Ransomware Activity"

                except Exception:
                    pass

            # ==========================================
            # KEYLOGGER / MALWARE DETECTION
            # ==========================================
            suspicious_keywords = [
                "keylog",
                "payload",
                "inject",
                "backdoor",
                "rat",
                "stealer",
                "exploit",
                "malware",
                "shell",
                "trojan"
            ]

            suspicious_extensions = [
                ".exe",
                ".dll",
                ".bat",
                ".ps1",
                ".vbs",
                ".scr",
                ".sh"
            ]

            if any(word in path_lower for word in suspicious_keywords):

                severity = "HIGH"
                event_type = "Keylogger Behavior"

            if any(path_lower.endswith(ext) for ext in suspicious_extensions):

                severity = "HIGH"
                event_type = "Malware Dropper Detected"

            # ==========================================
            # 💾 BACKUP CLEAN FILES ONLY
            # ==========================================
            if severity != "HIGH":

                try:
                    backup_file(event.src_path)

                except Exception as e:
                    self.logger.error(f"Backup failed: {e}")

            msg = f"{event_type}: {event.src_path} | {severity}"

            print(msg)
            self.logger.warning(msg)

            add_event(
                event_type,
                severity,
                event.src_path,
                time.strftime("%Y-%m-%d %H:%M:%S"),
                {"pid": 0}
            )

            # 🚨 AUTO QUARANTINE
            if severity == "HIGH":

                try:
                    send_alert(
                        "🚨 SOC HIGH ALERT",
                        f"""
Threat Detected!

Type: {event_type}

Target:
{event.src_path}

Severity:
{severity}

Time:
{time.strftime("%Y-%m-%d %H:%M:%S")}
"""
                    )
                except Exception as e:
                    self.logger.error(f"Email alert failed: {e}")

                try:
                    self.quarantine.quarantine_file(event.src_path)

                except Exception as e:
                    self.logger.error(f"Quarantine failed: {e}")

        except Exception as e:
            self.logger.error(f"Monitor error: {e}")

    # =====================================================
    # FILE MOVED / RENAMED
    # =====================================================
    def on_moved(self, event):

        if event.is_directory or self.is_excluded(event.dest_path):
            return

        destination = event.dest_path.lower()

        if destination.endswith(".locked"):

            severity = "HIGH"
            event_type = "Ransomware Activity"

            try:
                restore_file(event.dest_path)

            except Exception as e:
                self.logger.error(f"Restore failed: {e}")

            msg = f"{event_type}: {event.dest_path} | {severity}"

            print(msg)
            self.logger.warning(msg)

            add_event(
                event_type,
                severity,
                event.dest_path,
                time.strftime("%Y-%m-%d %H:%M:%S"),
                {"pid": 0}
            )

            try:
                send_alert(
                    "🚨 SOC HIGH ALERT",
                    f"""
Threat Detected!

Type: {event_type}

Target:
{event.dest_path}

Severity:
{severity}

Time:
{time.strftime("%Y-%m-%d %H:%M:%S")}
"""
                )
            except Exception as e:
                self.logger.error(f"Email alert failed: {e}")

            try:
                self.quarantine.quarantine_file(event.dest_path)

            except Exception as e:
                self.logger.error(f"Quarantine failed: {e}")


# =====================================================
# START MONITOR
# =====================================================
def start_file_monitor(path, logger):

    observer = Observer()
    handler = FileHandler(logger)

    observer.schedule(handler, path=path, recursive=True)
    observer.start()

    print(f"Monitoring files in: {path}")

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()
