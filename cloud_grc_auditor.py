#!/usr/bin/env python3
"""
Cloud GRC Compliance Auditor (cloud_grc_auditor.py)
Automated baseline cloud compliance scanner mapping to:
- CIS AWS Foundations Benchmark
- NIST SP 800-53 Rev 5 (IA-2, SC-7, SC-28)
- NIST SP 800-171 / CMMC 2.0 (3.5.3, 3.13.1)

Author: Joshua Guzman
"""

import sys
import csv
import json
import logging
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[!] Error: 'boto3' library not installed. Install via: pip install boto3")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CloudGRCAuditor")

class CloudGRCAuditor:
    def __init__(self, region_name="us-east-1"):
        self.region = region_name
        self.findings = []
        self.timestamp = datetime.utcnow().isoformat() + "Z"

        try:
            self.session = boto3.Session(region_name=self.region)
            self.iam = self.session.client("iam")
            self.s3 = self.session.client("s3")
            self.ec2 = self.session.client("ec2")
            logger.info(f"Initialized CloudGRCAuditor targeting region: {self.region}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            sys.exit(1)

    def log_finding(self, resource_type, resource_id, finding_msg, severity, control_ref, remediation):
        finding = {
            "timestamp": self.timestamp,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "finding": finding_msg,
            "severity": severity,
            "control_reference": control_ref,
            "remediation_guidance": remediation
        }
        self.findings.append(finding)
        logger.warning(f"[{severity}] {resource_type} '{resource_id}': {finding_msg}")

    def audit_iam_mfa(self):
        """Audits all IAM users with console access to verify MFA enforcement."""
        logger.info("Auditing IAM Users for MFA compliance (NIST SP 800-53 IA-2 / CMMC 3.5.3)...")
        try:
            users = self.iam.list_users().get("Users", [])
            for user in users:
                user_name = user["UserName"]
                
                # Check if user has console access password
                try:
                    self.iam.get_login_profile(UserName=user_name)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console = False
                    else:
                        continue

                if has_console:
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                    if not mfa_devices:
                        self.log_finding(
                            resource_type="IAM User",
                            resource_id=user_name,
                            finding_msg="Console access enabled without Multi-Factor Authentication (MFA)",
                            severity="HIGH",
                            control_ref="NIST SP 800-53 IA-2 | CMMC 3.5.3",
                            remediation="Enforce virtual or hardware MFA via IAM policy or assign AWS Identity Center (SSO)."
                        )
        except Exception as e:
            logger.error(f"IAM MFA Audit failed: {e}")

    def audit_s3_encryption_and_public_access(self):
        """Audits S3 buckets for server-side encryption and public access blocks."""
        logger.info("Auditing S3 Buckets for Encryption & Public Access (NIST SP 800-53 SC-28 / SC-7)...")
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            for b in buckets:
                b_name = b["Name"]

                # 1. Default Encryption check
                try:
                    enc = self.s3.get_bucket_encryption(Bucket=b_name)
                except ClientError as e:
                    if e.response["Error"]["Code"] in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"]:
                        self.log_finding(
                            resource_type="S3 Bucket",
                            resource_id=b_name,
                            finding_msg="Default server-side encryption (SSE-S3 / KMS) is NOT configured",
                            severity="HIGH",
                            control_ref="NIST SP 800-53 SC-28 | NIST SP 800-171 3.13.11",
                            remediation="Enable Amazon S3 managed keys (SSE-S3) or AWS KMS default encryption."
                        )

                # 2. Public Access Block check
                try:
                    pab = self.s3.get_public_access_block(Bucket=b_name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    if not all([config.get("BlockPublicAcls"), config.get("IgnorePublicAcls"), 
                                config.get("BlockPublicPolicy"), config.get("RestrictPublicBuckets")]):
                        self.log_finding(
                            resource_type="S3 Bucket",
                            resource_id=b_name,
                            finding_msg="S3 Public Access Block is incomplete or disabled",
                            severity="HIGH",
                            control_ref="NIST SP 800-53 SC-7 | CMMC 3.13.1",
                            remediation="Enable all 4 S3 Block Public Access controls on the bucket."
                        )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        self.log_finding(
                            resource_type="S3 Bucket",
                            resource_id=b_name,
                            finding_msg="No S3 Public Access Block configuration exists",
                            severity="HIGH",
                            control_ref="NIST SP 800-53 SC-7 | CMMC 3.13.1",
                            remediation="Apply S3 Public Access Block configuration immediately."
                        )
        except Exception as e:
            logger.error(f"S3 Audit failed: {e}")

    def audit_security_groups(self):
        """Audits EC2 Security Groups for unrestricted ingress on management ports."""
        logger.info("Auditing Security Groups for over-permissive ingress (NIST SP 800-53 AC-17 / SC-7)...")
        sensitive_ports = {22: "SSH", 3389: "RDP", 23: "Telnet", 8080: "HTTP-Alt"}
        try:
            sgs = self.ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_ranges = [ip.get("CidrIp") for ip in rule.get("IpRanges", [])]

                    if "0.0.0.0/0" in ip_ranges:
                        for port, service in sensitive_ports.items():
                            if from_port is not None and to_port is not None:
                                if from_port <= port <= to_port:
                                    self.log_finding(
                                        resource_type="Security Group",
                                        resource_id=f"{sg_id} ({sg_name})",
                                        finding_msg=f"Unrestricted 0.0.0.0/0 ingress open to {service} (Port {port})",
                                        severity="CRITICAL",
                                        control_ref="NIST SP 800-53 AC-17 | CMMC 3.1.12",
                                        remediation=f"Restrict Port {port} access to authorized corporate VPN CIDRs or AWS Systems Manager Session Manager."
                                    )
        except Exception as e:
            logger.error(f"Security Group Audit failed: {e}")

    def export_csv(self, filename="grc_remediation_action_items.csv"):
        """Exports all detected findings to a structured CSV audit file."""
        if not self.findings:
            logger.info("No compliance violations detected. CSV export skipped.")
            return

        keys = ["timestamp", "severity", "resource_type", "resource_id", "control_reference", "finding", "remediation_guidance"]
        with open(filename, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.findings)
        logger.info(f"Exported {len(self.findings)} findings to '{filename}'.")

    def run_all(self):
        print("="*70)
        print(" CLOUD GRC COMPLIANCE AUDITOR (NIST & CIS CONTROLS)")
        print(f" Execution Timestamp: {self.timestamp}")
        print(f" AWS Region: {self.region}")
        print("="*70)

        self.audit_iam_mfa()
        self.audit_s3_encryption_and_public_access()
        self.audit_security_groups()

        print("\n" + "="*70)
        print(" AUDIT SUMMARY & SCORECARD")
        print("="*70)
        print(f" Total Findings Identified: {len(self.findings)}")
        high_critical = [f for f in self.findings if f['severity'] in ['HIGH', 'CRITICAL']]
        print(f" High/Critical Priority Items: {len(high_critical)}")

        self.export_csv()
        print("="*70)

if __name__ == "__main__":
    auditor = CloudGRCAuditor()
    auditor.run_all()

