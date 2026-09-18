import logging
from pathlib import Path

def setup_logger(log_file="data/logs/system.log"):
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    return logging.getLogger("malware_defense")
