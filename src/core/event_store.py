from datetime import datetime
from threading import Lock

events = []
lock = Lock()

MAX_EVENTS = 1000  # prevent memory overflow


# =====================================
# 📦 ADD EVENT (WITH FULL DATE-TIME STAMP)
# =====================================
def add_event(event_type, severity="INFO", path="N/A", timestamp=None, extra=None):
    """Store all security/system events safely with complete timestamps"""

    severity = (severity or "INFO").upper()

    # Capture both structural Date and Time for PDF filters
    if not timestamp:
        now = datetime.now()
        timestamp = now.strftime("%H:%M:%S")
        date_stamp = now.strftime("%Y-%m-%d")
    else:
        timestamp = timestamp
        date_stamp = datetime.now().strftime("%Y-%m-%d")

    event = {
        "time": timestamp,
        "date": date_stamp,
        "type": event_type,
        "path": path,
        "severity": severity
    }

    if extra:
        event["extra"] = extra

    with lock:
        events.append(event)

        # prevent memory overflow
        if len(events) > MAX_EVENTS:
            events.pop(0)


# =====================================
# 📊 GET EVENTS (DASHBOARD READY)
# =====================================
def get_events(limit=50):
    """Return latest events first (dashboard-ready)"""
    with lock:
        return list(reversed(events[-limit:]))


# =====================================
# 📊 ALL EVENTS FOR PDF FILTER GENERATION
# =====================================
def get_all_raw_events():
    """Retrieve the entire event logs for structural sorting rules"""
    with lock:
        return list(events)


# =====================================
# 📈 ANALYSIS RATE
# =====================================
def analysis_rate():
    """Number of collected events"""
    with lock:
        return len(events)


# =====================================
# 📊 DASHBOARD STATS
# =====================================
def get_stats():
    """Severity breakdown for SOC dashboard"""
    with lock:
        stats = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        }

        for e in events:
            sev = e.get("severity", "LOW").upper()
            if sev in stats:
                stats[sev] += 1

        return stats
