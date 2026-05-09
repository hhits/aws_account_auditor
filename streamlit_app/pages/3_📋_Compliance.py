import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import plotly.graph_objects as go
from streamlit_app.lib import db

st.set_page_config(page_title="Compliance · AWS Auditor", page_icon="📋", layout="wide")

st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
.fw-card { border-radius:12px; padding:1.2rem; margin-bottom:0.5rem; background:white; border:1px solid #e5e7eb; }
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
  <h1 style="margin:0">📋 Compliance Posture</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">CIS · PCI-DSS · SOC 2 · HIPAA · NIST 800-53</p>
</div>""", unsafe_allow_html=True)

# ── Job selector ──────────────────────────────────────────────────────────────
jobs = [j for j in db.list_audits() if j["status"] == "completed"]
if not jobs:
    st.info("No completed audits yet.")
    st.stop()

selected_id = st.session_state.get("selected_job", jobs[0]["id"])
job_options = {j["id"]: f"{j.get('created_at','')[:19].replace('T',' ')}" for j in jobs}
chosen = st.selectbox("Select audit", options=list(job_options.keys()),
                      format_func=lambda x: job_options[x],
                      index=list(job_options.keys()).index(selected_id) if selected_id in job_options else 0)

findings = db.get_findings(chosen)

# ── Compute compliance scores from findings ───────────────────────────────────
FRAMEWORKS = {
    "CIS": {"color": "#3b82f6", "label": "CIS AWS v1.5"},
    "PCI": {"color": "#8b5cf6", "label": "PCI-DSS v4.0"},
    "SOC2": {"color": "#06b6d4", "label": "SOC 2 TSC"},
    "HIPAA": {"color": "#f59e0b", "label": "HIPAA"},
    "NIST": {"color": "#10b981", "label": "NIST 800-53"},
}

def compute_scores(findings: list[dict]) -> dict[str, dict]:
    scores: dict[str, dict] = {fw: {"pass": 0, "fail": 0, "controls": set()} for fw in FRAMEWORKS}
    for f in findings:
        compliance = f.get("compliance") or {}
        status = f.get("status", "")
        is_pass = status == "PASS"
        for fw in FRAMEWORKS:
            ctrls = compliance.get(fw, [])
            if isinstance(ctrls, str):
                ctrls = [ctrls]
            for ctrl in ctrls:
                scores[fw]["controls"].add(ctrl)
                if is_pass:
                    scores[fw]["pass"] += 1
                else:
                    scores[fw]["fail"] += 1
    result = {}
    for fw, data in scores.items():
        total = data["pass"] + data["fail"]
        result[fw] = {
            "pass": data["pass"],
            "fail": data["fail"],
            "total": total,
            "score": round(data["pass"] / total * 100, 1) if total else 0,
            "controls": sorted(data["controls"]),
        }
    return result

scores = compute_scores(findings)

# ── Radar chart ───────────────────────────────────────────────────────────────
fw_labels = [FRAMEWORKS[fw]["label"] for fw in FRAMEWORKS]
fw_scores = [scores[fw]["score"] for fw in FRAMEWORKS]
fig = go.Figure(go.Scatterpolar(
    r=fw_scores + [fw_scores[0]],
    theta=fw_labels + [fw_labels[0]],
    fill="toself",
    line_color="#3b82f6",
    fillcolor="rgba(59,130,246,0.15)",
    name="Compliance Score",
))
fig.update_layout(
    polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
    showlegend=False, height=350, margin=dict(t=20, b=20, l=20, r=20),
    paper_bgcolor="white",
)

col_radar, col_scores = st.columns([1, 2])
with col_radar:
    st.subheader("Overall Posture")
    st.plotly_chart(fig)

with col_scores:
    st.subheader("Framework Scores")
    for fw, meta in FRAMEWORKS.items():
        s = scores[fw]
        pct = s["score"]
        bar_color = "#22c55e" if pct >= 80 else "#f97316" if pct >= 60 else "#dc2626"
        st.markdown(f"""
<div class="fw-card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <span style="font-weight:600;color:#1e293b">{meta['label']}</span>
    <span style="font-weight:700;color:{bar_color};font-size:1.2rem">{pct}%</span>
  </div>
  <div style="background:#f1f5f9;border-radius:99px;height:8px">
    <div style="background:{bar_color};width:{pct}%;height:8px;border-radius:99px;transition:width 0.3s"></div>
  </div>
  <div style="margin-top:6px;color:#64748b;font-size:0.8rem">{s['pass']} pass · {s['fail']} fail · {s['total']} total findings</div>
</div>""", unsafe_allow_html=True)

st.divider()

# ── Failing controls per framework ────────────────────────────────────────────
st.subheader("Failing Findings by Framework")
tab_labels = [FRAMEWORKS[fw]["label"] for fw in FRAMEWORKS]
tabs = st.tabs(tab_labels)

for i, (fw, meta) in enumerate(FRAMEWORKS.items()):
    with tabs[i]:
        fail_findings = [
            f for f in findings
            if f.get("status") not in ("PASS", "SKIPPED")
            and (f.get("compliance") or {}).get(fw)
        ]

        if not fail_findings:
            st.success(f"No failing findings for {meta['label']}!")
            continue

        st.caption(f"{len(fail_findings)} failing findings")

        SEV_ORDER = ["Critical", "High", "Medium", "Low"]
        fail_findings.sort(key=lambda f: SEV_ORDER.index(f.get("severity","Low")) if f.get("severity") in SEV_ORDER else 99)
        SEV_COLOR = {"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}

        for f in fail_findings:
            sev = f.get("severity","Low")
            color = SEV_COLOR.get(sev, "#64748b")
            controls = f.get("compliance", {}).get(fw, [])
            if isinstance(controls, str):
                controls = [controls]
            ctrl_str = ", ".join(controls)
            with st.expander(f"**[{sev}]** {f.get('service','')} — {f.get('check_name','')} `{ctrl_str}`"):
                st.markdown(f.get("details","—"))
                if f.get("recommendation"):
                    st.info(f.get("recommendation"))
