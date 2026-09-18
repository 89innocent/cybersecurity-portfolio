from collections import defaultdict
from datetime import datetime, timedelta


class IncidentCorrelator:

    def __init__(self):
        # stores grouped incidents
        self.incidents = defaultdict(list)

    def correlate(self, events):

        grouped = {}

        for e in events:

            key = self._generate_key(e)

            if key not in grouped:
                grouped[key] = {
                    "incident_id": key,
                    "type": e.get("type", "Unknown"),
                    "severity": e.get("severity", "LOW"),
                    "events": [],
                    "start_time": e.get("time"),
                    "end_time": e.get("time"),
                    "count": 0
                }

            grouped[key]["events"].append(e)
            grouped[key]["count"] += 1

            # update time range
            grouped[key]["start_time"] = min(
                grouped[key]["start_time"],
                e.get("time")
            )
            grouped[key]["end_time"] = max(
                grouped[key]["end_time"],
                e.get("time")
            )

            # escalate severity dynamically
            grouped[key]["severity"] = self._escalate(
                grouped[key]["severity"],
                e.get("severity")
            )

        return list(grouped.values())

    def _generate_key(self, event):

        # CORE CORRELATION LOGIC
        # groups events by type + path (or target)

        return f"{event.get('type')}_{event.get('path')}"

    def _escalate(self, current, new):

        order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3
        }

        return current if order[current] >= order[new] else new
