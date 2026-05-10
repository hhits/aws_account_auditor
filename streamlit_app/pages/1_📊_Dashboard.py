import sys, os
_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
_LOGO = os.path.normpath(os.path.join(_LIB, "..", "..", "auditor", "assets", "logo.png"))
import time
import streamlit as st
import plotly.graph_objects as go
import db, audit_runner, ai_client

st.set_page_config(page_title="Dashboard · AWS Auditor", page_icon="🛡️", layout="wide")

if os.path.exists(_LOGO) and hasattr(st, "logo"):
    st.logo(_LOGO, size="large")

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#f6f8fb; }
.stMainBlockContainer.block-container {
  max-width: 1540px;
  padding-top: 2.2rem;
  padding-left: 3.2rem;
  padding-right: 3.2rem;
}
[data-testid="stSidebar"] { background:#0f172a; border-right:1px solid #1e293b; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
[data-testid="stSidebarNav"] { padding-top:.75rem; }
[data-testid="stSidebarNav"] ul { padding-top:.35rem; }
[data-testid="stSidebar"] .stButton button {
  background:#1e293b; border:1px solid #334155; color:#e2e8f0;
  border-radius:8px; min-height:42px; font-weight:650;
}
[data-testid="stSidebar"] .stButton button:hover { border-color:#60a5fa; background:#263449; }
[data-testid="stSidebar"] [data-testid="stImage"] img {
  background:#fff; border-radius:10px; padding:14px;
}
[data-testid="stHeader"] { background:transparent; }
.block-container h4 {
  color:#172033;
  font-size:1.1rem;
  letter-spacing:-.01em;
}

.dashboard-hero {
  background:
    radial-gradient(circle at 82% 20%, rgba(56,189,248,.18), transparent 32%),
    linear-gradient(135deg,#0f172a 0%,#173457 100%);
  color:white;
  padding:1.25rem 1.45rem;
  border-radius:10px;
  margin-bottom:.85rem;
  border:1px solid rgba(255,255,255,.08);
  box-shadow:0 16px 38px rgba(15,23,42,.13);
}
.dashboard-title {
  margin:0;
  font-size:1.65rem;
  font-weight:800;
  line-height:1.1;
  display:flex;
  align-items:center;
  gap:10px;
  letter-spacing:0;
}
.dashboard-subtitle {
  margin:.45rem 0 0;
  color:#cbd5e1;
  font-size:.9rem;
}

.metric-card {
  background: white;
  border-radius: 8px;
  padding: 1rem 1.05rem;
  box-shadow: 0 10px 24px rgba(15,23,42,.06);
  border: 1px solid #e5e7eb;
  border-left: 4px solid #e5e7eb;
  height: 100%;
}
.metric-card.critical { border-left-color: #dc2626; }
.metric-card.high     { border-left-color: #f97316; }
.metric-card.medium   { border-left-color: #eab308; }
.metric-card.low      { border-left-color: #22c55e; }
.metric-card.total    { border-left-color: #3b82f6; }
.metric-label { font-size: 0.78rem; font-weight: 600; text-transform: uppercase;
                letter-spacing: .05em; color: #64748b; margin-bottom: 8px; }
.metric-value { font-size: 2rem; font-weight: 800; color: #0f172a; line-height: 1; }
.metric-sub   { font-size: 0.76rem; color: #94a3b8; margin-top: 8px; }

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
  background:#fff;
  border:1px solid #dbeafe;
  border-left:4px solid #2563eb;
  border-radius:8px; padding:.65rem .9rem;
  color:#172033; font-size:.86rem; margin-bottom:.8rem;
  box-shadow:0 8px 22px rgba(15,23,42,.05);
}
.chart-panel {
  background:#fff;
  border:1px solid #e5e7eb;
  border-radius:8px;
  padding:.75rem .95rem .35rem;
  box-shadow:0 10px 24px rgba(15,23,42,.05);
}
.risk-banner {
  border-radius:8px;
  padding:.78rem 1rem;
  margin:.85rem 0 1rem;
  display:flex;
  align-items:center;
  gap:12px;
}
@media (max-width: 900px) {
  .stMainBlockContainer.block-container { padding-left:1rem; padding-right:1rem; }
  .dashboard-title { font-size:1.35rem; }
  .metric-value { font-size:1.7rem; }
}
</style>
""", unsafe_allow_html=True)

db.restore_session()
if not db.is_logged_in():
    st.switch_page("app.py")

with st.sidebar:
    if os.path.exists(_LOGO) and not hasattr(st, "logo"):
        st.image(_LOGO, use_container_width=True)
    elif not os.path.exists(_LOGO):
        st.markdown("### 🛡️ AWS Auditor")
    st.markdown(f"**{st.session_state.get('user_email','')}**")
    st.divider()
    if st.button("Sign out", use_container_width=True):
        db.logout(); st.rerun()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="dashboard-hero">
  <h1 class="dashboard-title">
    🛡️ AWS Audit Dashboard
  </h1>
  <p class="dashboard-subtitle">
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
    st.markdown(f'<div class="ai-banner">🤖 <b>AI Active</b> — {ai_msg} &nbsp;|&nbsp; Open the <b>AI</b> page for analysis and chat</div>',
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

    st.markdown("<div style='height:.4rem'></div>", unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────────────────────
    col_bar, col_svc = st.columns(2)

    with col_bar:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
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
            margin=dict(t=8, b=0, l=0, r=0), height=260,
            plot_bgcolor="white", paper_bgcolor="white",
            font=dict(family="Arial, sans-serif", color="#64748b"),
            xaxis=dict(showgrid=False, tickfont=dict(size=12, color="#64748b")),
            yaxis=dict(showgrid=True, gridcolor="#eef2f7", zeroline=False, tickfont=dict(color="#64748b")),
        )
        st.plotly_chart(fig, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_svc:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
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
                margin=dict(t=8, b=0, l=0, r=0), height=260,
                plot_bgcolor="white", paper_bgcolor="white",
                font=dict(family="Arial, sans-serif", color="#64748b"),
                xaxis=dict(showgrid=True, gridcolor="#eef2f7", zeroline=False, tickfont=dict(color="#64748b")),
                yaxis=dict(showgrid=False, tickfont=dict(size=12, color="#64748b")),
            )
            st.plotly_chart(fig2, width="stretch")
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Overall risk indicator ─────────────────────────────────────────────────
    st.markdown(f"""
<div style="background:{risk_color}18;border:1.5px solid {risk_color}40;
            " class="risk-banner">
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
