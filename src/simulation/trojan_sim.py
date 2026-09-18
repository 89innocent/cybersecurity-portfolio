# src/simulation/trojan_sim.py

import os
import time

print("🦠 Simulating Trojan Activity...")

# Suspicious filename
filename = "trojan_payload.exe"

# Fake malware content
payload = """
FAKE TROJAN PAYLOAD
keylog()
inject()
backdoor()
stealer()
"""

# Create fake malware file
with open(filename, "w") as f:
    f.write(payload)

print(f"Created: {filename}")

time.sleep(2)

# Modify file to trigger monitor again
with open(filename, "a") as f:
    f.write("\nMORE MALICIOUS DATA")

print("Modified fake trojan file.")

print("✅ Simulation complete.")
