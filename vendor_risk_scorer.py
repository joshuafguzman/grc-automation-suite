#!/usr/bin/env python3
"""Score third-party inherent and residual risk."""

import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("VendorRiskScorer")


class VendorRiskScorer:
    def __init__(self, vendor_profile):
        self.profile = vendor_profile
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.assessment = {}

    def calculate_inherent_risk(self):
        score = 20
        score += {"CUI": 40, "PII": 30, "FINANCIAL": 30, "CONFIDENTIAL": 30, "INTERNAL": 15}.get(self.profile.get("data_classification", "PUBLIC").upper(), 0)
        score += {"DIRECT_PRODUCTION_ACCESS": 30, "API_INTEGRATION": 20, "HOSTED_SAAS_CLOUD": 15, "LOCAL_DESKTOP_TOOL": 10}.get(self.profile.get("access_level", "NONE").upper(), 0)
        return min(score, 100)

    def calculate_control_mitigations(self):
        credits = sum({"SOC_2_TYPE_II": 20, "ISO_27001": 15, "FEDRAMP_AUTHORIZED": 25}.get(cert, 0) for cert in self.profile.get("certifications", []))
        credits += 10 * sum(bool(self.profile.get(key)) for key in ("mfa_enforced_for_admin", "encryption_at_rest_and_transit", "annual_penetration_test_provided"))
        return credits

    def evaluate_vendor(self):
        inherent = self.calculate_inherent_risk()
        mitigations = self.calculate_control_mitigations()
        residual = max(inherent - mitigations, 10)
        tier, recommendation = (("TIER_1_HIGH_RISK", "REQUIRES_CISO_EXCEPTION_APPROVAL") if residual >= 65 else ("TIER_2_MODERATE_RISK", "APPROVED_WITH_STANDARD_MONITORING") if residual >= 35 else ("TIER_3_LOW_RISK", "APPROVED_FOR_ENTERPRISE_USE"))
        self.assessment = {"vendor_name": self.profile.get("vendor_name"), "evaluation_date_utc": self.timestamp, "inherent_risk_score": inherent, "control_mitigation_credits": mitigations, "residual_risk_score": residual, "risk_tier": tier, "governance_recommendation": recommendation}
        return self.assessment

    def export_report(self, output_path="vendor_risk_assessment_report.json"):
        with open(output_path, "w", encoding="utf-8") as output:
            json.dump(self.assessment, output, indent=2)

    def print_summary(self):
        print(json.dumps(self.assessment, indent=2))


if __name__ == "__main__":
    scorer = VendorRiskScorer({"vendor_name": "CloudLogix Data Pipeline Solutions", "data_classification": "CUI", "access_level": "API_INTEGRATION", "certifications": ["SOC_2_TYPE_II", "ISO_27001"], "mfa_enforced_for_admin": True, "encryption_at_rest_and_transit": True, "annual_penetration_test_provided": True})
    scorer.evaluate_vendor()
    scorer.export_report()
    scorer.print_summary()
