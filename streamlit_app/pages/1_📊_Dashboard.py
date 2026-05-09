import sys, os
_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import time
import streamlit as st
import plotly.graph_objects as go
import db, audit_runner, ai_client

st.set_page_config(page_title="Dashboard · AWS Auditor", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
[data-testid="stSidebar"] .stButton button { background:#1e293b; border:1px solid #334155; color:#e2e8f0; border-radius:8px; }

.metric-card {
  background: white;
  border-radius: 14px;
  padding: 1.2rem 1.4rem;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  border-top: 4px solid #e5e7eb;
  height: 100%;
}
.metric-card.critical { border-top-color: #dc2626; }
.metric-card.high     { border-top-color: #f97316; }
.metric-card.medium   { border-top-color: #eab308; }
.metric-card.low      { border-top-color: #22c55e; }
.metric-card.total    { border-top-color: #3b82f6; }
.metric-label { font-size: 0.78rem; font-weight: 600; text-transform: uppercase;
                letter-spacing: .05em; color: #64748b; margin-bottom: 4px; }
.metric-value { font-size: 2.4rem; font-weight: 800; color: #0f172a; line-height: 1; }
.metric-sub   { font-size: 0.75rem; color: #94a3b8; margin-top: 4px; }

.audit-row {
  background: white; border-radius: 12px; padding: 1rem 1.2rem;
  margin-bottom: .5rem; border: 1px solid #e5e7eb;
  display: flex; align-items: center; gap: 1rem;
}
.status-badge {
  display:inline-block; padding:3px 10px; border-radius:99px;
  font-size:.75rem; font-weight:600;
}
.badge-completed { background:#dcfce7; color:#16a34a; }
.badge-running   { background:#dbeafe; color:#2563eb; }
.badge-pending   { background:#fef9c3; color:#ca8a04; }
.badge-failed    { background:#fee2e2; color:#dc2626; }

.ai-banner {
  background: linear-gradient(135deg, #0f172a, #1e3a5f);
  border-radius: 12px; padding: .8rem 1.2rem;
  color: white; font-size: .85rem; margin-bottom: 1rem;
}
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

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:white;
            padding:2rem 2rem 1.5rem;border-radius:16px;margin-bottom:1.5rem">
  <h1 style="margin:0;font-size:1.9rem;font-weight:800;display:flex;align-items:center;gap:10px">
    🛡️ AWS Audit Dashboard
  </h1>
  <p style="margin:.5rem 0 0;color:#94a3b8;font-size:.95rem">
    Multi-account · Security · Compliance · Cost · AI-Powered
  </p>
</div>""", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────────────────────────
jobs   = db.list_audits()
config = db.get_config()

# ── AI availability banner ────────────────────────────────────────────────────
ai_ok, ai_msg = ai_client.is_available()
if ai_ok:
    provider = "Groq" if "Groq" in ai_msg else "Ollama"
    st.markdown(f'<div class="ai-banner">🤖 <b>AI Active</b> — {ai_msg} &nbsp;|&nbsp; Go to the <b>AI</b> page for analysis &amp; chat</div>',
                unsafe_allow_html=True)

# ── Action bar ────────────────────────────────────────────────────────────────
has_running = any(j["status"] in ("pending", "running") for j in jobs)

col_left, col_right = st.columns([4, 1])
with col_right:
    if not config:
        st.warning("⚙️ Configure AWS first")
        can_run = False
    else:
        can_run = not has_running

    if st.button("▶ Run New Audit", disabled=not can_run, type="primary", use_container_width=True):
        accounts   = db.list_accounts()
        account_ids = [a["account_id"] for a in accounts]
        job = db.create_audit_job()
        audit_runner.start_audit(job["id"], db.current_user_id(), config, account_ids)
        st.success(f"Audit started!")
        time.sleep(1); st.rerun()

    if has_running:
        st.info("🔄 Audit running…")
        time.sleep(5); st.rerun()

# ── Summary metrics from latest completed job ─────────────────────────────────
latest = next((j for j in jobs if j["status"] == "completed"), None)
if latest:
    summary = db.get_summary(latest["id"])
    sev     = summary.get("by_severity", {})
    total   = summary["total"]

    crit = sev.get("Critical", 0)
    high = sev.get("High", 0)
    med  = sev.get("Medium", 0)
    low  = sev.get("Low", 0)

    # Risk level
    risk_label = "Critical" if crit > 0 else "High" if high > 0 else "Medium" if med > 0 else "Low"
    risk_color = {"Critical":"#dc2626","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}[risk_label]

    c1, c2, c3, c4, c5 = st.columns(5)
    cards = [
        (c1, "total",    "Total Findings", total,  f"last audit"),
        (c2, "critical", "🔴 Critical",     crit,   "immediate action"),
        (c3, "high",     "🟠 High",          high,   "fix soon"),
        (c4, "medium",   "🟡 Medium",        med,    "plan to fix"),
        (c5, "low",      "🟢 Low",           low,    "monitor"),
    ]
    for col, cls, label, val, sub in cards:
        col.markdown(f"""
<div class="metric-card {cls}">
  <div class="metric-label">{label}</div>
  <div class="metric-value">{val}</div>
  <div class="metric-sub">{sub}</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────────────────────
    col_bar, col_svc = st.columns(2)

    with col_bar:
        st.markdown("#### Findings by Severity")
        sev_data   = {k: sev.get(k, 0) for k in ["Critical", "High", "Medium", "Low"]}
        sev_colors = ["#dc2626", "#f97316", "#eab308", "#22c55e"]
        fig = go.Figure(go.Bar(
            x=list(sev_data.keys()),
            y=list(sev_data.values()),
            marker_color=sev_colors,
            text=list(sev_data.values()),
            textposition="outside",
            textfont=dict(size=14, color="#0f172a"),
        ))
        fig.update_layout(
            showlegend=False,
            margin=dict(t=10, b=0, l=0, r=0), height=260,
            plot_bgcolor="white", paper_bgcolor="white",
            xaxis=dict(showgrid=False, tickfont=dict(size=13)),
            yaxis=dict(showgrid=True, gridcolor="#f1f5f9", zeroline=False),
        )
        st.plotly_chart(fig)

    with col_svc:
        st.markdown("#### Top Services")
        svc = summary.get("by_service", {})
        if svc:
            top = dict(sorted(svc.items(), key=lambda x: x[1], reverse=True)[:8])
            colors = ["#3b82f6" if v < max(top.values()) else "#0f172a" for v in top.values()]
            fig2 = go.Figure(go.Bar(
                x=list(top.values()), y=list(top.keys()), orientation="h",
                marker_color=colors,
                text=list(top.values()), textposition="outside",
                textfont=dict(size=12),
            ))
            fig2.update_layout(
                showlegend=False,
                margin=dict(t=10, b=0, l=0, r=0), height=260,
                plot_bgcolor="white", paper_bgcolor="white",
                xaxis=dict(showgrid=True, gridcolor="#f1f5f9"),
                yaxis=dict(showgrid=False, tickfont=dict(size=12)),
            )
            st.plotly_chart(fig2, width="stretch")

    # ── Overall risk indicator ─────────────────────────────────────────────────
    st.markdown(f"""
<div style="background:{risk_color}18;border:1.5px solid {risk_color}40;
            border-radius:10px;padding:.8rem 1.2rem;margin-bottom:1rem;
            display:flex;align-items:center;gap:12px">
  <span style="width:12px;height:12px;border-radius:50%;background:{risk_color};
               display:inline-block;flex-shrink:0"></span>
  <span style="font-weight:700;color:{risk_color}">Overall Risk: {risk_label}</span>
  <span style="color:#64748b;font-size:.85rem">·
    {crit} critical · {high} high · {med} medium · {low} low findings
  </span>
</div>""", unsafe_allow_html=True)

# ── Recent audits ─────────────────────────────────────────────────────────────
st.markdown("#### Recent Audits")

STATUS_BADGE = {
    "completed": ("✅ Completed", "badge-completed"),
    "running":   ("🔄 Running",   "badge-running"),
    "pending":   ("⏳ Pending",   "badge-pending"),
    "failed":    ("❌ Failed",    "badge-failed"),
}

if not jobs:
    st.info("No audits yet — click **Run New Audit** to get started.")
else:
    for job in jobs:
        ts    = job.get("created_at", "")[:19].replace("T", " ")
        label, badge_cls = STATUS_BADGE.get(job["status"], (job["status"], "badge-pending"))
        accts = job.get("accounts_audited") or []
        total = job.get("total_findings", 0)

        col_a, col_b, col_c, col_d, col_e = st.columns([3, 2, 1, 1, 2])
        with col_a: st.markdown(f"**{ts}**")
        with col_b: st.markdown(f'<span class="status-badge {badge_cls}">{label}</span>', unsafe_allow_html=True)
        with col_c: st.markdown(f"{len(accts)} acct{'s' if len(accts)!=1 else ''}")
        with col_d: st.markdown(f"**{total}** findings")
        with col_e:
            c1, c2 = st.columns(2)
            if job["status"] == "completed":
                if c1.button("View", key=f"view_{job['id']}", use_container_width=True, type="primary"):
                    st.session_state["selected_job"] = job["id"]
                    st.switch_page("pages/2_🔍_Findings.py")
            if job["status"] in ("completed", "failed"):
                if c2.button("🗑", key=f"del_{job['id']}", use_container_width=True):
                    db.delete_audit_job(job["id"]); st.rerun()
        if job.get("error_message"):
            st.caption(f"⚠ {job['error_message'][:100]}")
        st.divider()
