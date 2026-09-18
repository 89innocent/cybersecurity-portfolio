# src/defense/system_lockdown.py

import os
import time


class SystemLockdown:
    """
    Emergency SOC Lockdown System

    Features:
    - blocks repeated lockdown execution
    - logs critical incidents
    - publishes events to dashboard
    - creates lockdown evidence log
    - optional simulation mode
    """

    def __init__(self, logger, event_bus=None, simulation=True):
        self.logger = logger
        self.event_bus = event_bus
        self.simulation = simulation

        self.locked = False

        # create logs directory
        os.makedirs("logs", exist_ok=True)

    # =====================================
    # MAIN LOCKDOWN
    # =====================================
    def activate(self, alert):

        if self.locked:
            self.logger.warning("[LOCKDOWN] System already locked")
            return

        self.locked = True

        # ==========================
        # LOGGING
        # ==========================
        self.logger.critical("=" * 60)
        self.logger.critical("🚨 SYSTEM LOCKDOWN ACTIVATED")
        self.logger.critical(f"REASON: {alert}")
        self.logger.critical("=" * 60)

        # ==========================
        # DASHBOARD EVENT
        # ==========================
        if self.event_bus:
            self.event_bus.publish("security_event", {
                "type": "system_lockdown",
                "severity": "HIGH",
                "time": time.strftime("%H:%M:%S"),
                "path": "SYSTEM LOCKDOWN ACTIVATED"
            })

        # ==========================
        # SAVE FORENSIC RECORD
        # ==========================
        self.save_lockdown_report(alert)

        # ==========================
        # SIMULATION MODE
        # ==========================
        if self.simulation:
            print("\n🚨 SYSTEM IS NOW IN LOCKDOWN MODE")
            print("⚠ Malware activity contained")
            print("⚠ External operations restricted")
            print("⚠ SOC incident response triggered\n")

        else:
            # Real defensive actions
            self.real_lockdown()

    # =====================================
    # SAVE INCIDENT REPORT
    # =====================================
    def save_lockdown_report(self, alert):

        filename = "logs/system_lockdown.log"

        with open(filename, "a") as f:
            f.write("\n")
            f.write("=" * 60 + "\n")
            f.write(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"ALERT: {alert}\n")
            f.write("STATUS: LOCKDOWN ACTIVATED\n")
            f.write("=" * 60 + "\n")

    # =====================================
    # REAL LOCKDOWN ACTIONS
    # =====================================
    def real_lockdown(self):

        self.logger.critical("[LOCKDOWN] Applying emergency restrictions")

        try:
            # Example placeholder actions
            os.system("pkill -f python")
        except Exception as e:
            self.logger.error(f"[LOCKDOWN ERROR] {e}")

    # =====================================
    # RELEASE LOCKDOWN
    # =====================================
    def release(self):

        self.locked = False

        self.logger.info("[LOCKDOWN] System lockdown released")

        if self.event_bus:
            self.event_bus.publish("security_event", {
                "type": "lockdown_released",
                "severity": "LOW",
                "time": time.strftime("%H:%M:%S"),
                "path": "System lockdown released"
            })
