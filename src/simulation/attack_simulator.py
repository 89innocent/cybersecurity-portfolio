import threading


class AttackSimulator:

    def __init__(self, logger):
        self.logger = logger
        self.running = False

    def start(self):
        """
        DISABLED FAKE ATTACK SIMULATION
        System now relies only on:
        - real file monitoring
        - ransomware_sim.py
        - process monitor
        - real detections
        """

        self.running = False

        self.logger.info(
            "AttackSimulator disabled - using real system monitoring only"
        )

    def stop(self):
        self.running = False

    def run(self):
        pass
