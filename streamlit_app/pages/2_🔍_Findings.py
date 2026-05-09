import sys, os
_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import streamlit as st
import db, ai_client

st.set_page_config(page_title="Findings · AWS Auditor", page_icon="🔍", layout="wide")

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
  <h1 style="margin:0">🔍 Findings Explorer</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">Browse, filter and remediate audit findings</p>
</div>""", unsafe_allow_html=True)

# ── Job selector ──────────────────────────────────────────────────────────────
jobs = [j for j in db.list_audits() if j["status"] == "completed"]
if not jobs:
    st.info("No completed audits yet. Run an audit from the Dashboard.")
    st.stop()

selected_id = st.session_state.get("selected_job", jobs[0]["id"])
job_options = {j["id"]: f"{j.get('created_at','')[:19].replace('T',' ')} ({j.get('total_findings',0)} findings)" for j in jobs}
chosen = st.selectbox("Select audit", options=list(job_options.keys()),
                      format_func=lambda x: job_options[x],
                      index=list(job_options.keys()).index(selected_id) if selected_id in job_options else 0)
st.session_state["selected_job"] = chosen

# ── Load findings ─────────────────────────────────────────────────────────────
findings = db.get_findings(chosen)

# ── Filter bar ────────────────────────────────────────────────────────────────
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
SEV_COLOR = {"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}

col1, col2, col3, col4 = st.columns(4)
with col1:
    severities = ["All"] + SEV_ORDER
    sel_sev = st.selectbox("Severity", severities, key="filter_sev")
with col2:
    statuses = ["All"] + sorted({f.get("status","") for f in findings} - {""})
    sel_status = st.selectbox("Status", statuses, key="filter_status")
with col3:
    services = ["All"] + sorted({f.get("service","") for f in findings} - {""})
    sel_svc = st.selectbox("Service", services, key="filter_svc")
with col4:
    search = st.text_input("Search", placeholder="keyword…", key="filter_search")

# Apply filters
filtered = findings
if sel_sev != "All":
    filtered = [f for f in filtered if f.get("severity") == sel_sev]
if sel_status != "All":
    filtered = [f for f in filtered if f.get("status") == sel_status]
if sel_svc != "All":
    filtered = [f for f in filtered if f.get("service") == sel_svc]
if search:
    kw = search.lower()
    filtered = [f for f in filtered if kw in (f.get("check_name","") + f.get("details","") + f.get("recommendation","")).lower()]

# Sort by severity
sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
filtered.sort(key=lambda f: sev_rank.get(f.get("severity",""), 99))

st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
st.divider()

# ── Ollama status ─────────────────────────────────────────────────────────────
ai_ok, ai_msg = ai_client.is_available()

# ── Finding cards ─────────────────────────────────────────────────────────────
for f in filtered:
    sev = f.get("severity", "Low")
    color = SEV_COLOR.get(sev, "#64748b")
    status = f.get("status", "")
    status_icon = {"FAIL": "❌", "WARNING": "⚠️", "PASS": "✅", "ERROR": "🔧", "SKIPPED": "⏭"}.get(status, "❓")

    with st.expander(f"{status_icon} **[{sev}]** {f.get('service','')} — {f.get('check_name','')}", expanded=False):
        meta_col, _ = st.columns([3, 1])
        with meta_col:
            st.markdown(f"""
| Field | Value |
|---|---|
| Account | `{f.get('account_id','')}` |
| Region | `{f.get('region','')}` |
| Status | {status} |
| Severity | <span style="color:{color};font-weight:700">{sev}</span> |
""", unsafe_allow_html=True)

        st.markdown("**Details**")
        st.markdown(f.get("details", "—"))

        if f.get("recommendation"):
            st.markdown("**Recommendation**")
            st.info(f.get("recommendation"))

        # Compliance tags
        compliance = f.get("compliance") or {}
        if compliance:
            tags = " ".join(
                f"`{fw}: {', '.join(ctrls) if isinstance(ctrls, list) else ctrls}`"
                for fw, ctrls in compliance.items() if ctrls
            )
            st.markdown(f"**Controls:** {tags}")

        # AI Remediation
        if status in ("FAIL", "WARNING"):
            existing_rem = f.get("ai_remediation")
            if existing_rem:
                st.markdown("**🤖 AI Remediation**")
                with st.expander("View remediation", expanded=False):
                    if existing_rem.get("explanation"):
                        st.info(f"**Why it matters:** {existing_rem['explanation']}")
                    if existing_rem.get("risk_if_not_fixed"):
                        st.warning(f"⚠️ **Risk if not fixed:** {existing_rem['risk_if_not_fixed']}")
                    if existing_rem.get("steps"):
                        st.markdown("**Remediation steps:**")
                        for i, step in enumerate(existing_rem["steps"], 1):
                            st.markdown(f"{i}. {step}")
                    if existing_rem.get("estimated_effort"):
                        st.caption(f"⏱ Estimated effort: {existing_rem['estimated_effort']}")
                    tabs_rem = []
                    tab_labels = []
                    if existing_rem.get("cli_script"):
                        tab_labels.append("🖥 AWS CLI")
                    if existing_rem.get("cloudformation_snippet"):
                        tab_labels.append("☁️ CloudFormation")
                    if existing_rem.get("terraform_snippet"):
                        tab_labels.append("🏗 Terraform")
                    if tab_labels:
                        tabs_rem = st.tabs(tab_labels)
                        idx = 0
                        if existing_rem.get("cli_script"):
                            with tabs_rem[idx]:
                                st.code(existing_rem["cli_script"], language="bash")
                            idx += 1
                        if existing_rem.get("cloudformation_snippet"):
                            with tabs_rem[idx]:
                                st.code(existing_rem["cloudformation_snippet"], language="yaml")
                            idx += 1
                        if existing_rem.get("terraform_snippet"):
                            with tabs_rem[idx]:
                                st.code(existing_rem["terraform_snippet"], language="hcl")
            elif ai_ok:
                if st.button("🤖 Generate Remediation", key=f"rem_{f['id']}"):
                    with st.spinner("Generating remediation…"):
                        rem = ai_client.generate_remediation(f)
                        ok, err = db.save_finding_remediation(f["id"], rem)
                        if ok:
                            st.success("Remediation generated!")
                            st.rerun()
                        else:
                            st.error(err)
            else:
                st.caption("💡 Start Ollama locally to enable AI remediation")
