#!/usr/bin/env python3
"""Generate a DoD/CMMC POA&M register from baseline vulnerability findings."""

import csv
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NessusToPOAM")

SLA_DAYS = {"CRITICAL": 15, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
CONTROL_MAPPING = {
    "patch": ("NIST SP 800-53 SI-2", "CMMC 3.14.1 (Flaw Remediation)"),
    "ssl": ("NIST SP 800-53 SC-8", "CMMC 3.13.8 (Data in Transit)"),
    "tls": ("NIST SP 800-53 SC-8", "CMMC 3.13.8 (Data in Transit)"),
    "smb": ("NIST SP 800-53 CM-7", "CMMC 3.4.7 (Least Functionality)"),
    "cve": ("NIST SP 800-53 RA-5", "CMMC 3.11.2 (Vulnerability Scanning)"),
    "default": ("NIST SP 800-53 CM-6", "CMMC 3.4.2 (Security Configuration)"),
}


class POAMGenerator:
    def __init__(self, scanner_csv_path=None):
        self.scanner_path = scanner_csv_path
        self.poam_items = []
        self.generation_date = datetime.utcnow()

    def load_mock_findings(self):
        return [
            {"plugin_name": "Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link)", "cve": "CVE-2024-21413", "host": "WS-HUNTVALLEY-042.corp.local", "ip": "10.14.22.42", "severity": "CRITICAL", "cvss": "9.8", "solution": "Apply Microsoft February 2024 security update KB5034763."},
            {"plugin_name": "cURL and libcurl SOCKS5 Heap Buffer Overflow", "cve": "CVE-2023-38545", "host": "AP-DOCKER-01.dmz.local", "ip": "172.16.8.10", "severity": "HIGH", "cvss": "8.8", "solution": "Upgrade cURL and libcurl to version 8.4.0 or higher."},
            {"plugin_name": "SSL / TLS Insecure Renegotiation Protocol Flaw", "cve": "N/A", "host": "GW-VPN-01.edge.local", "ip": "10.10.1.1", "severity": "MEDIUM", "cvss": "5.8", "solution": "Disable insecure SSL/TLS renegotiation on the server profile."},
            {"plugin_name": "Microsoft Windows SMBv1 Protocol Supported", "cve": "N/A", "host": "FS-STORAGE-02.corp.local", "ip": "10.14.20.15", "severity": "HIGH", "cvss": "7.5", "solution": "Disable SMBv1 across the domain via Group Policy Object (GPO)."},
        ]

    def map_controls(self, title):
        title = title.lower()
        for key, mapping in CONTROL_MAPPING.items():
            if key != "default" and key in title:
                return mapping
        return CONTROL_MAPPING["default"]

    def process_findings(self):
        for poam_id, finding in enumerate(self.load_mock_findings(), 1001):
            severity = finding["severity"].upper()
            nist, cmmc = self.map_controls(finding["plugin_name"])
            detected = self.generation_date.strftime("%Y-%m-%d")
            due = (self.generation_date + timedelta(days=SLA_DAYS.get(severity, 90))).strftime("%Y-%m-%d")
            self.poam_items.append({
                "POAM_ID": f"POAM-2026-{poam_id}",
                "Weakness_Name": f"{finding['plugin_name']} ({finding['cve']})",
                "Affected_Asset": f"{finding['host']} ({finding['ip']})",
                "Severity": severity, "CVSS_Score": finding["cvss"],
                "NIST_SP_800_53_Control": nist, "CMMC_2_0_Practice": cmmc,
                "Original_Detection_Date": detected, "Scheduled_Completion_Date": due,
                "Remediation_Status": "Open (In Progress)",
                "Action_Plan_Milestone": f"1. Test fix in staging. 2. {finding['solution']} 3. Perform validation rescan.",
                "Point_of_Contact": "Cybersecurity GRC Analyst",
            })

    def export_csv(self, output_path="dod_cmmc_poam_register.csv"):
        if not self.poam_items:
            logger.warning("No items to export.")
            return
        with open(output_path, "w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=self.poam_items[0])
            writer.writeheader()
            writer.writerows(self.poam_items)

    def print_summary(self):
        for item in self.poam_items:
            print(f"[{item['POAM_ID']}] ({item['Severity']}) {item['Weakness_Name']}")
            print(f"  Asset: {item['Affected_Asset']} | Target Completion: {item['Scheduled_Completion_Date']}")


if __name__ == "__main__":
    generator = POAMGenerator()
    generator.process_findings()
    generator.export_csv()
    generator.print_summary()
