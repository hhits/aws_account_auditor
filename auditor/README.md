Here is a professional `README.md` for your AWS Audit Dashboard project, customized for your current setup and future plans:

---

```markdown
# 🔍 AWS Account Auditor Dashboard

**AWS Account Auditor** is a security and compliance auditing platform developed by [H&H IT Solutions](https://hhitsolutions.com). It provides automated, multi-account AWS audits across security, IAM, network exposure, cost optimization, and compliance best practices—visualized in a user-friendly dashboard.

---

## 🚀 Features

- ✅ **Multi-Account Support** via cross-account `AuditRole` assumption
- 🛡️ **Audit Modules**:
  - IAM Best Practices
  - Network Exposure
  - Security Groups & Public AMIs
  - Cost Optimization
  - GuardDuty & CloudTrail Checks
  - EBS Encryption
- 📊 **Interactive Dashboard** built with Streamlit + Plotly
- 🔒 **Permission-Aware** – Filters out access-denied findings in final reports
- 🧠 **Standardized Finding Schema** across all modules
- 📁 **JSON + CSV Exports** of filtered findings
- 🖼️ **Branding Support** (Custom logo, company info)
- 📉 **Visual Analytics**:
  - Severity by Region/Account
  - Historical Trend Charts
- 🌐 Coming Soon:
  - Multi-User Authentication
  - Audit Trigger from Web UI
  - Scheduled Audits and Notifications

---

## 📁 Project Structure

```

aws\_account\_auditor/
│
├── auditor/
│   ├── modules/              # Individual audit modules
│   ├── reports/              # Output JSON reports
│   ├── assets/               # Branding assets like logo.png
│   ├── config.yaml           # Audit config (accounts, regions)
│   ├── main.py               # CLI entry point to run audits
│   ├── dashboard.py          # Streamlit-based dashboard
│   └── auth.py               # (Planned) user auth and session mgmt
│
├── requirements.txt
└── README.md

````

---

## ⚙️ Installation

### 1. Clone the repo:

```bash
git clone https://github.com/hhitsolutions/aws-account-auditor.git
cd aws-account-auditor
````

### 2. Setup a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 3. Configure accounts

Edit `auditor/config.yaml` to define:

* AWS accounts to audit
* Allowed regions
* Role ARN to assume (e.g., `AuditRole`)
* Exclusions

---

## 🚦 Running the Auditor

### Run audit across all configured accounts:

```bash
python3 -m auditor.main
```

### Launch the dashboard:

```bash
streamlit run auditor/dashboard.py
```

---

## 📦 Output

Each audit creates a timestamped `.json` file in `auditor/reports/`.

The dashboard:

* Automatically loads the latest report
* Allows filtering by account, region, service, severity, etc.
* Offers download buttons for filtered findings

---

## 🔐 IAM & SCP Setup

Ensure the following:

* `AuditRole` is deployed via StackSet to each target account
* The role allows `sts:AssumeRole` from the management account
* SCPs do not block `ec2:Describe*`, `iam:Get*`, `config:Describe*`, etc.

We recommend attaching this sample SCP to enable read-only audit access:

📄 See `docs/sample_scp_audit_policy.json`

---

## 📈 Future Roadmap

* [ ] Multi-user login with role-based permissions
* [ ] Trigger audits from web UI
* [ ] Audit scheduling + Slack/email alerts
* [ ] SaaS-ready deployment with tenant isolation
* [ ] Cost summaries by tag/project

---

## 🧑‍💼 Maintained By

**H\&H IT Solutions LLC**
“Cybersecurity Made Simple”
📧 [support@hhitsolutions.com](mailto:support@hhitsolutions.com)
🌐 [https://hhitsolutions.com](https://hhitsolutions.com)

---

## 🛑 Disclaimer

This tool is intended for **internal use only** and should not be used on accounts without proper authorization.