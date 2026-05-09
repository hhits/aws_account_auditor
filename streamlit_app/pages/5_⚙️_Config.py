import sys, os
_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import streamlit as st
import db

st.set_page_config(page_title="Config · AWS Auditor", page_icon="⚙️", layout="wide")

st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
</style>
""", unsafe_allow_html=True)

db.restore_session()
if not db.is_logged_in():
    st.switch_page("app.py")

with st.sidebar:
    st.markdown("### 🛡️ AWS Auditor")
    st.markdown(f"**{st.session_state.get('user_email','')}**")
    st.divider()
    if st.button("Sign out", use_container_width=True):
        db.logout(); st.rerun()

st.markdown("""
<div style="background:linear-gradient(135deg,#0f172a,#1e293b);color:white;padding:2rem;border-radius:16px;margin-bottom:1rem">
  <h1 style="margin:0">⚙️ AWS Configuration</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">Set up your AWS role chain and audit preferences</p>
</div>""", unsafe_allow_html=True)

config = db.get_config()

# ── Role chain setup ──────────────────────────────────────────────────────────
st.subheader("1. Role Chain")
st.markdown("""
The auditor uses a **two-hop role assumption** chain:
1. Your app credentials → **Deployer role** (management account)
2. Deployer → **Audit role** (each target account)
""")

with st.form("config_form"):
    deployer_role_arn = st.text_input(
        "Deployer Role ARN",
        value=config.get("deployer_role_arn", "") if config else "",
        placeholder="arn:aws:iam::123456789012:role/AuditDeployer",
        help="Role in your management account. App credentials must be able to assume this.",
    )
    deployer_external_id = st.text_input(
        "Deployer External ID (optional)",
        value=config.get("deployer_external_id", "") if config else "",
        placeholder="my-external-id",
    )
    audit_role_name = st.text_input(
        "Audit Role Name",
        value=config.get("audit_role_name", "AuditRole") if config else "AuditRole",
        placeholder="AuditRole",
        help="Role name deployed to every target account (must be consistent).",
    )
    audit_role_external_id = st.text_input(
        "Audit Role External ID (optional)",
        value=config.get("audit_role_external_id", "") if config else "",
        placeholder="audit-access",
    )

    st.subheader("2. Regions")
    regions_str = st.text_input(
        "Regions (comma-separated)",
        value=", ".join(config.get("regions", ["us-east-1"])) if config else "us-east-1",
        placeholder="us-east-1, us-west-2, eu-west-1",
    )

    st.subheader("3. Account Discovery")
    use_orgs = st.checkbox(
        "Auto-discover accounts from AWS Organizations",
        value=config.get("use_organizations", False) if config else False,
        help="When enabled, ignores the manual account list below and fetches all active accounts from your org.",
    )

    st.subheader("4. Enabled Audit Modules")
    MODULES = {
        "iam": "IAM Best Practices",
        "network": "Network Exposure",
        "cost": "Cost Optimization",
        "exposure": "Public Exposure (S3, AMIs)",
        "cloudtrail": "CloudTrail & GuardDuty",
        "security_hub": "Security Hub Findings",
        "cis_compliance": "CIS Compliance Checks",
    }
    enabled = config.get("enabled_audits", list(MODULES.keys())) if config else list(MODULES.keys())
    selected_modules = []
    cols = st.columns(2)
    for i, (key, label) in enumerate(MODULES.items()):
        if cols[i % 2].checkbox(label, value=key in enabled, key=f"mod_{key}"):
            selected_modules.append(key)

    saved = st.form_submit_button("💾 Save Configuration", type="primary", use_container_width=True)

if saved:
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]
    if not deployer_role_arn:
        st.error("Deployer Role ARN is required.")
    elif not regions:
        st.error("At least one region is required.")
    else:
        db.save_config({
            "deployer_role_arn": deployer_role_arn,
            "deployer_external_id": deployer_external_id,
            "audit_role_name": audit_role_name,
            "audit_role_external_id": audit_role_external_id,
            "regions": regions,
            "use_organizations": use_orgs,
            "enabled_audits": selected_modules,
        })
        st.success("Configuration saved!")
        st.rerun()

st.divider()

# ── Account list (manual) ─────────────────────────────────────────────────────
if not (config and config.get("use_organizations")):
    st.subheader("5. Target Accounts")
    st.caption("Add the AWS account IDs you want to audit. Skip this if using Organizations auto-discovery.")

    accounts = db.list_accounts()
    if accounts:
        for acct in accounts:
            col_id, col_name, col_del = st.columns([2, 2, 1])
            col_id.code(acct["account_id"])
            col_name.markdown(acct.get("account_name", "—"))
            if col_del.button("🗑", key=f"del_acct_{acct['id']}", use_container_width=True):
                db.remove_account(acct["id"])
                st.rerun()

    with st.form("add_account"):
        c1, c2, c3 = st.columns([2, 2, 1])
        new_id   = c1.text_input("Account ID", placeholder="123456789012")
        new_name = c2.text_input("Name (optional)", placeholder="Production")
        add_btn  = c3.form_submit_button("Add", use_container_width=True)
    if add_btn:
        if not new_id or not new_id.strip().isdigit() or len(new_id.strip()) != 12:
            st.error("Account ID must be a 12-digit number.")
        else:
            db.add_account(new_id.strip(), new_name.strip())
            st.success(f"Added account {new_id.strip()}")
            st.rerun()

st.divider()

# ── Danger zone ───────────────────────────────────────────────────────────────
with st.expander("🗑 Danger Zone", expanded=False):
    st.warning("These actions are irreversible.")
    if st.button("Delete all configuration and accounts", type="secondary"):
        db.delete_config()
        st.error("Configuration deleted.")
        st.rerun()
