import os
import time
import random
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_FILE = BASE_DIR / "tests" / ".keylogger_buffer.log"


def fake_keylogger_activity():

    print("🎹 Safe Keylogger Simulation Started")
    print("⚠ SAFE MODE: No real keyboard capture is performed")

    suspicious_words = [
        "password",
        "login",
        "admin",
        "token",
        "session",
        "credential",
        "banking",
        "email",
        "secret",
        "username"
    ]

    while True:

        fake_keystroke = random.choice(suspicious_words)

        with open(LOG_FILE, "a") as f:
            f.write(fake_keystroke + "\n")

        print(f"[SIMULATION] Captured fake input: {fake_keystroke}")

        time.sleep(2)


if __name__ == "__main__":
    fake_keylogger_activity()
