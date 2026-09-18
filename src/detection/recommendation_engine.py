def get_recommendation(event_type, severity):

    recommendations = {

        "Ransomware Activity": [
            "Quarantine infected files",
            "Restore latest backup",
            "Block file modification temporarily",
            "Monitor encryption behavior"
        ],

        "Keylogger Behavior": [
            "Terminate suspicious process",
            "Inspect keyboard hook activity",
            "Scan startup persistence",
            "Review active sessions"
        ],

        "Malware Dropper Detected": [
            "Quarantine executable file",
            "Block execution permissions",
            "Run malware scan",
            "Inspect child processes"
        ],

        "Brute Force Attack": [
            "Temporarily lock account",
            "Enable login rate limiting",
            "Review authentication logs",
            "Block suspicious source"
        ],

        "Privilege Escalation Attempt": [
            "Inspect sudo/root activity",
            "Terminate suspicious session",
            "Review privilege assignments",
            "Audit system changes"
        ],

        "Port Scanning Activity": [
            "Enable firewall filtering",
            "Block suspicious IP",
            "Inspect open ports",
            "Monitor network traffic"
        ],

        "File Modified": [
            "Monitor file activity",
            "Verify file integrity"
        ],

        "File Created": [
            "Verify file source",
            "Monitor new file behavior"
        ]
    }

    return recommendations.get(
        event_type,
        ["Monitor system activity"]
    )
