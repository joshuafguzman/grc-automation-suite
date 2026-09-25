#!/usr/bin/env python3
"""Calculate incident-response regulatory notification deadlines."""

import json
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IRTimelineCalculator")


class IncidentTimelineCalculator:
    def __init__(self, incident_title, incident_type, discovery_timestamp_iso=None):
        self.title = incident_title
        self.incident_type = incident_type.upper()
        self.discovery_time = datetime.fromisoformat(discovery_timestamp_iso.replace("Z", "+00:00")) if discovery_timestamp_iso else datetime.utcnow()
        self.deadlines = []

    @staticmethod
    def calculate_business_days(start_date, num_days):
        current, added = start_date, 0
        while added < num_days:
            current += timedelta(days=1)
            if current.weekday() < 5:
                added += 1
        return current

    def evaluate_compliance_clocks(self):
        if self.incident_type in {"CUI_BREACH", "DEFENSE_SYSTEM_COMPROMISE", "MALWARE"}:
            self.deadlines.append(self._deadline("DoD DFARS 252.204-7012 / DIBNet", 72, "CRITICAL"))
        if self.incident_type in {"PII_BREACH", "CUI_BREACH"}:
            self.deadlines.append(self._deadline("Maryland Personal Information Protection Act (MPIPA)", 45 * 24, "HIGH"))
        deadline = self.calculate_business_days(self.discovery_time, 4)
        self.deadlines.append({"regulation": "SEC Cybersecurity Disclosure Rule (Form 8-K)", "statutory_window": "4 Business Days", "deadline_utc": deadline.isoformat(), "priority": "HIGH"})

    def _deadline(self, regulation, hours, priority):
        deadline = self.discovery_time + timedelta(hours=hours)
        return {"regulation": regulation, "statutory_window": f"{hours} Hours", "deadline_utc": deadline.strftime("%Y-%m-%d %H:%M:%S UTC"), "priority": priority}

    def export_json(self, output_path="incident_response_clock.json"):
        with open(output_path, "w", encoding="utf-8") as output:
            json.dump({"incident_metadata": {"title": self.title, "incident_type": self.incident_type}, "regulatory_notification_schedule": self.deadlines}, output, indent=2)

    def print_timeline(self):
        for item in self.deadlines:
            print(f"[{item['priority']}] {item['regulation']} -> {item['deadline_utc']}")


if __name__ == "__main__":
    calculator = IncidentTimelineCalculator("Potential CUI Exfiltration on Contractor Endpoint", "CUI_BREACH")
    calculator.evaluate_compliance_clocks()
    calculator.export_json()
    calculator.print_timeline()
