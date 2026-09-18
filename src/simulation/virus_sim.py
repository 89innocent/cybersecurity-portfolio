# src/simulation/virus_sim.py

import time

print("🦠 Simulating Virus Activity...")

# Suspicious virus filename
filename = "virus_infected.exe"

# Fake virus content
virus_code = """
FAKE VIRUS PAYLOAD

self_replicate()
infect_files()
payload_execute()
stealer()
trojan()
keylog()

"""

# Create fake infected file
with open(filename, "w") as f:
    f.write(virus_code)

print(f"Created infected file: {filename}")

time.sleep(2)

# Simulate infection update
with open(filename, "a") as f:
    f.write("\nINFECTING MORE FILES...")

print("Virus activity simulated.")

print("✅ Fake virus simulation complete.")
