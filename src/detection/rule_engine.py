def analyze(event):
    """
    Improved SOC-style rule engine
    """

    name = event.get("name", "").lower()
    path = event.get("path", "").lower()
    event_type = event.get("type", "")

    score = 0

    # =========================
    # 🔥 RULE 1: suspicious keywords
    # =========================
    suspicious_keywords = [
        "miner", "hack", "inject", "reverse", "exploit",
        "backdoor", "trojan", "keylog", "shell"
    ]

    for word in suspicious_keywords:
        if word in name or word in path:
            score += 50

    # =========================
    # 🔥 RULE 2: ransomware behavior
    # =========================
    if path.endswith(".encrypted"):
        score += 80  # very dangerous

    if any(x in path for x in ["encrypt", "locked", "ransom"]):
        score += 70

    # =========================
    # 🔥 RULE 3: system anomaly hints
    # =========================
    if "/tmp" in path or "/dev/" in path:
        score += 30

    # =========================
    # 🔥 RULE 4: suspicious process patterns
    # =========================
    if len(name) > 25:
        score += 20

    if name.endswith(".py"):
        score += 10

    # =========================
    # 🔥 RULE 5: rapid file changes (behavior hint)
    # =========================
    if event_type == "modified":
        score += 5

    # =========================
    # FINAL CLASSIFICATION
    # =========================
    if score >= 80:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "severity": severity,
        "score": score
    }
