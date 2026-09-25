# Cloud & Enterprise GRC Automation Suite

An enterprise-ready Python automation toolkit for compliance auditing, continuous monitoring, and Plan of Action & Milestones (POA&M) generation across cloud and hybrid environments.

Developed by **Joshua Guzman** | Associate Cyber Security Analyst & GRC Specialist

## Tool suite

| Script | Target environment | Primary deliverable |
| --- | --- | --- |
| `cloud_grc_auditor.py` | AWS | NIST/CIS/CMMC findings and `grc_remediation_action_items.csv` |
| `nessus_to_poam.py` | Tenable/Nessus | `dod_cmmc_poam_register.csv` |
| `evidence_integrity_verifier.py` | Local evidence repository | SHA-256 integrity manifest |
| `ir_notification_timeline.py` | Incident response | Regulatory notification schedule |
| `vendor_risk_scorer.py` | Third-party risk | Vendor residual-risk report |
| `workday_tracker.py` | GRC operations | Daily standup and accomplishment logs |

## Quick start

Python 3.9+ is recommended. AWS credentials with read-only audit permissions are required only by `cloud_grc_auditor.py`.

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
pip install -r requirements.txt
```

Run the standalone tools with `python <script-name>`. Review generated reports and regulatory deadlines with your organization’s legal and compliance teams before relying on them.

## GitHub Pages

`index.html` is a static portfolio page. The included `deploy.yml` workflow publishes it to GitHub Pages on pushes to `main`.

## License

Distributed under the MIT License for educational, professional development, and enterprise GRC demonstration purposes.
