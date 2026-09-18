# src/defense/firewall_controller.py

class FirewallController:

    def __init__(self, logger):

        self.logger = logger

        self.blocked = set()

    # =====================================
    # BLOCK MALICIOUS TARGET
    # =====================================
    def block(self, alert):

        target = self.extract_target(alert)

        if not target:

            self.logger.warning(
                "[FIREWALL] No target found"
            )

            return

        # avoid duplicates
        if target in self.blocked:

            self.logger.info(
                f"[FIREWALL] Already blocked: {target}"
            )

            return

        self.blocked.add(target)

        self.logger.critical(
            f"[FIREWALL] BLOCKED TARGET: {target}"
        )

        # =====================================
        # SIMULATION MODE
        # =====================================
        print(f"\n🔥 FIREWALL BLOCKED: {target}\n")

    # =====================================
    # EXTRACT SUSPICIOUS TARGET
    # =====================================
    def extract_target(self, alert):

        # network IP
        if "remote_ip" in alert:
            return alert["remote_ip"]

        # suspicious path
        if "path" in alert:
            return alert["path"]

        # title fallback
        if "title" in alert:
            return alert["title"]

        return None
