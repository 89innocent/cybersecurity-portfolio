import threading
import time

from src.core.config_loader import load_config
from src.utils.logger import setup_logger

from src.monitoring.file_monitor import start_file_monitor
from src.monitoring.process_monitor import start_process_monitor

from src.defense.system_lockdown import SystemLockdown
from src.defense.response_handler import ResponseHandler
from src.defense.firewall_controller import FirewallController
from src.defense.quarantine import Quarantine

from src.monitoring.network_monitor import NetworkMonitor
from src.monitoring.file_monitor import start_file_monitor

# ==============================
# IMPORT DASHBOARD APP
# ==============================
from src.dashboard.app import app

# ==============================
# IMPORT ATTACK SIMULATOR
# ==============================
from src.simulation.attack_simulator import AttackSimulator


def main():

    # ==============================
    # LOAD CONFIG
    # ==============================
    config = load_config()

    # ==============================
    # LOGGER
    # ==============================
    logger = setup_logger(config["log_file"])

    # ==============================
    # SYSTEM LOCKDOWN
    # ==============================
    lockdown = SystemLockdown(
        logger=logger,
        event_bus=None,
        simulation=True
    )

    # ==============================
    # ATTACK SIMULATOR (NEW)
    # ==============================
    simulator = AttackSimulator(logger)
    simulator.start()

    # ==============================
    # STARTUP
    # ==============================
    logger.info("System started")

    print("\n🛡 Malware Defense System Running...")
    print(f"APP: {config['app_name']}\n")

    # ==============================
    # START FILE MONITOR
    # ==============================
    file_thread = threading.Thread(
        target=start_file_monitor,
        args=(config["monitor_path"], logger),
        daemon=True
    )

    # ==============================
    # START PROCESS MONITOR
    # ==============================
    process_thread = threading.Thread(
        target=start_process_monitor,
        args=(logger,),
        daemon=True
    )

    # ==============================
    # START DASHBOARD
    # ==============================
    dashboard_thread = threading.Thread(
        target=lambda: app.run(
            debug=False,
            host="0.0.0.0",
            port=5000,
            use_reloader=False,
            threaded=True
        ),
        daemon=True
    )

    # ==============================
    # START THREADS
    # ==============================
    file_thread.start()
    process_thread.start()
    dashboard_thread.start()

    print("🌐 Dashboard running on:")
    print("http://127.0.0.1:5000\n")

    # ==============================
    # MAIN LOOP
    # ==============================
    try:

        while True:

            time.sleep(5)

            # ======================================
            # EXAMPLE AUTO LOCKDOWN TEST
            # ======================================
            suspicious_detected = False

            if suspicious_detected:

                alert = {
                    "title": "Ransomware Detected",
                    "severity": "critical",
                    "source": "Behavior Engine"
                }

                lockdown.activate(alert)

    except KeyboardInterrupt:

        simulator.stop()
        logger.warning("System stopped by user")

        print("\nSystem shutting down...\n")


if __name__ == "__main__":
    main()
