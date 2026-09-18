# src/monitoring/network_monitor.py

import time
import psutil


class NetworkMonitor:

    def __init__(self, event_bus, logger=None, interval=5):

        self.event_bus = event_bus
        self.logger = logger
        self.interval = interval

        # avoid duplicate spam
        self.seen_connections = set()

        # suspicious ports
        self.suspicious_ports = [
            4444,
            5555,
            6666,
            1337,
            8080
        ]

    # =====================================
    # START MONITOR
    # =====================================
    def start(self):

        if self.logger:
            self.logger.info("[NETWORK MONITOR] Started")

        while True:

            try:
                self.scan()

            except Exception as e:

                if self.logger:
                    self.logger.error(
                        f"[NETWORK MONITOR ERROR] {e}"
                    )

            time.sleep(self.interval)

    # =====================================
    # NETWORK SCAN
    # =====================================
    def scan(self):

        connections = psutil.net_connections()

        for conn in connections:

            try:

                if not conn.raddr:
                    continue

                local_ip = conn.laddr.ip
                local_port = conn.laddr.port

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                status = conn.status

                # unique connection key
                key = (
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status
                )

                # skip duplicates
                if key in self.seen_connections:
                    continue

                self.seen_connections.add(key)

                event = {
                    "type": "network_connection",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": status
                }

                # =====================================
                # LOGGING
                # =====================================
                if self.logger:
                    self.logger.info(
                        f"[NETWORK] {local_ip}:{local_port} "
                        f"-> {remote_ip}:{remote_port} "
                        f"[{status}]"
                    )

                # =====================================
                # EVENT BUS
                # =====================================
                self.event_bus.publish(
                    "network_event",
                    event
                )

                # =====================================
                # SUSPICIOUS PORT DETECTION
                # =====================================
                if remote_port in self.suspicious_ports:

                    alert = {
                        "title": "Suspicious Network Port",
                        "description": (
                            f"Connection to suspicious "
                            f"port {remote_port}"
                        ),
                        "severity": "high",
                        "source": "NetworkMonitor"
                    }

                    if self.logger:
                        self.logger.warning(
                            f"[SUSPICIOUS NETWORK] {alert}"
                        )

                    self.event_bus.publish(
                        "alert_event",
                        alert
                    )

            except Exception:
                continue
