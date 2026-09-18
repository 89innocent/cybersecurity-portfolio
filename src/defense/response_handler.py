# src/defense/response_handler.py

class ResponseHandler:

    def __init__(self, logger, firewall, quarantine, lockdown):

        self.logger = logger
        self.firewall = firewall
        self.quarantine = quarantine
        self.lockdown = lockdown

    # =====================================
    # MAIN RESPONSE ENGINE
    # =====================================
    def handle(self, alert):

        severity = str(alert.get("severity", "low")).lower()

        self.logger.warning(
            f"[RESPONSE HANDLER] Processing alert: {alert}"
        )

        # =====================================
        # LOW SEVERITY
        # =====================================
        if severity == "low":

            self.logger.info(
                "[RESPONSE] Low severity → logging only"
            )

        # =====================================
        # MEDIUM SEVERITY
        # =====================================
        elif severity == "medium":

            self.logger.warning(
                "[RESPONSE] Medium severity → quarantine"
            )

            self.quarantine.quarantine(alert)

        # =====================================
        # HIGH SEVERITY
        # =====================================
        elif severity == "high":

            self.logger.critical(
                "[RESPONSE] High severity → firewall + quarantine"
            )

            self.firewall.block(alert)

            self.quarantine.quarantine(alert)

        # =====================================
        # CRITICAL SEVERITY
        # =====================================
        elif severity == "critical":

            self.logger.critical(
                "[RESPONSE] CRITICAL → SYSTEM LOCKDOWN"
            )

            self.firewall.block(alert)

            self.quarantine.quarantine(alert)

            self.lockdown.activate(alert)

        # =====================================
        # UNKNOWN
        # =====================================
        else:

            self.logger.warning(
                f"[RESPONSE] Unknown severity: {severity}"
            )
