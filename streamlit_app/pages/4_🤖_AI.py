import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from streamlit_app.lib import db, ai_client

st.set_page_config(page_title="AI Analysis · AWS Auditor", page_icon="🤖", layout="wide")

st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
.chat-user { background:#eff6ff; border-radius:12px; padding:0.75rem 1rem; margin:0.25rem 0; border-left:3px solid #3b82f6; }
.chat-ai   { background:#f0fdf4; border-radius:12px; padding:0.75rem 1rem; margin:0.25rem 0; border-left:3px solid #22c55e; }
</style>
""", unsafe_allow_html=True)

if not db.is_logged_in():
    st.switch_page("app.py")

with st.sidebar:
    st.markdown("### 🛡️ AWS Auditor")
    st.markdown(f"**{st.session_state.get('user_email','')}**")
    st.divider()
    if st.button("Sign out", use_container_width=True):
        db.logout(); st.rerun()

st.markdown("""
<div style="background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;padding:2rem;border-radius:16px;margin-bottom:1rem">
  <h1 style="margin:0">🤖 AI Security Analyst</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">Powered by Groq (cloud · free) or Ollama (local)</p>
</div>""", unsafe_allow_html=True)

# ── AI status ─────────────────────────────────────────────────────────────────
# Debug: show whether the key is being read
_key_preview = ai_client._groq_key()
if _key_preview:
    st.caption(f"🔑 Groq key detected: `{_key_preview[:8]}...`")
ai_ok, ai_msg = ai_client.is_available()
if ai_ok:
    icon = "☁️" if "Groq" in ai_msg else "💻"
    st.success(f"✅ AI connected — {icon} {ai_msg}")
else:
    st.warning(f"⚠️ {ai_msg}")
    with st.expander("How to enable AI"):
        st.markdown("""
**Option 1 — Groq (free, works on Streamlit Cloud):**
1. Create a free account at [console.groq.com](https://console.groq.com)
2. Generate an API key
3. Add to Streamlit secrets:
```toml
GROQ_API_KEY = "gsk_..."
```

**Option 2 — Ollama (local only):**
```bash
ollama serve
ollama pull llama3.2
```
""")

# ── Job selector ──────────────────────────────────────────────────────────────
jobs = [j for j in db.list_audits() if j["status"] == "completed"]
if not jobs:
    st.info("No completed audits yet.")
    st.stop()

selected_id = st.session_state.get("selected_job", jobs[0]["id"])
job_options = {j["id"]: f"{j.get('created_at','')[:19].replace('T',' ')} ({j.get('total_findings',0)} findings)" for j in jobs}
chosen = st.selectbox("Select audit", options=list(job_options.keys()),
                      format_func=lambda x: job_options[x],
                      index=list(job_options.keys()).index(selected_id) if selected_id in job_options else 0)
st.session_state["selected_job"] = chosen
findings = db.get_findings(chosen)
acct_ids = list({f.get("account_id","") for f in findings if f.get("account_id")})

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_analysis, tab_chat, tab_report = st.tabs(["📊 Analysis", "💬 Chat", "📄 Executive Report"])

# ── Analysis tab ──────────────────────────────────────────────────────────────
with tab_analysis:
    existing = db.get_ai_analysis(chosen)

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        label = "🔄 Refresh Analysis" if existing else "▶ Run AI Analysis"
        run_btn = st.button(label, disabled=not ai_ok, type="primary", use_container_width=True)

    if run_btn:
        with st.spinner("Analyzing findings with AI (this may take 30–90s)…"):
            result = ai_client.analyze_findings(findings, acct_ids)
            db.save_ai_analysis(chosen, db.current_user_id(), result)
            existing = result
            st.success("Analysis complete!")

    if existing:
        risk = existing.get("risk_level", "Unknown")
        risk_color = {"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}.get(risk, "#64748b")

        st.markdown(f"""
<div style="background:{risk_color}15;border:2px solid {risk_color};border-radius:12px;padding:1.2rem;margin-bottom:1rem">
  <div style="color:{risk_color};font-weight:700;font-size:1.1rem">Overall Risk: {risk}</div>
  <div style="margin-top:0.4rem;color:#1e293b">{existing.get('headline','')}</div>
</div>""", unsafe_allow_html=True)

        col_risks, col_wins = st.columns(2)
        with col_risks:
            st.subheader("⚠️ Top Risks")
            for r in existing.get("top_risks", []):
                st.markdown(f"- {r}")
        with col_wins:
            st.subheader("✅ Quick Wins")
            for w in existing.get("quick_wins", []):
                st.markdown(f"- {w}")

        if existing.get("summary"):
            st.subheader("Summary")
            st.markdown(existing["summary"])

        if existing.get("narrative"):
            st.subheader("Detailed Analysis")
            st.markdown(existing["narrative"])
    else:
        st.info("Click **Run AI Analysis** to get AI-powered insights about your findings.")

# ── Chat tab ──────────────────────────────────────────────────────────────────
with tab_chat:
    if not ai_ok:
        st.warning("Ollama is required for chat. Start it locally first.")
    else:
        if "chat_history" not in st.session_state:
            st.session_state["chat_history"] = []
        if "chat_job" not in st.session_state or st.session_state["chat_job"] != chosen:
            st.session_state["chat_history"] = []
            st.session_state["chat_job"] = chosen

        # Suggested questions
        if not st.session_state["chat_history"]:
            st.markdown("**Suggested questions:**")
            suggestions = [
                "What are the most critical findings I should fix first?",
                "Summarize the IAM security posture",
                "What network exposure risks exist?",
                "Which findings affect PCI-DSS compliance?",
                "What are the top cost optimization opportunities?",
                "Generate a remediation priority list",
            ]
            cols = st.columns(3)
            for i, q in enumerate(suggestions):
                if cols[i % 3].button(q, key=f"sug_{i}", use_container_width=True):
                    st.session_state["chat_history"].append({"role": "user", "content": q})
                    with st.spinner("Thinking…"):
                        reply = ai_client.chat(q, findings, st.session_state["chat_history"][:-1])
                    st.session_state["chat_history"].append({"role": "assistant", "content": reply})
                    st.rerun()

        # Render history
        for msg in st.session_state["chat_history"]:
            if msg["role"] == "user":
                st.markdown(f'<div class="chat-user">👤 {msg["content"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="chat-ai">🤖 {msg["content"]}</div>', unsafe_allow_html=True)

        # Input
        with st.form("chat_form", clear_on_submit=True):
            user_input = st.text_input("Ask about your findings…", placeholder="e.g. What IAM risks do I have?")
            col_send, col_clear = st.columns([3, 1])
            send = col_send.form_submit_button("Send", use_container_width=True, type="primary")
            clear = col_clear.form_submit_button("Clear", use_container_width=True)

        if send and user_input.strip():
            st.session_state["chat_history"].append({"role": "user", "content": user_input})
            with st.spinner("Thinking…"):
                reply = ai_client.chat(user_input, findings, st.session_state["chat_history"][:-1])
            st.session_state["chat_history"].append({"role": "assistant", "content": reply})
            st.rerun()

        if clear:
            st.session_state["chat_history"] = []
            st.rerun()

        st.caption("🔒 All analysis happens locally via Ollama — no data leaves your machine.")

# ── Executive Report tab ──────────────────────────────────────────────────────
with tab_report:
    if not ai_ok:
        st.warning("Ollama is required for report generation.")
    else:
        existing_analysis = db.get_ai_analysis(chosen)
        existing_report = existing_analysis.get("executive_report") if existing_analysis else None

        if st.button("📄 Generate Executive Report", disabled=not ai_ok, type="primary"):
            with st.spinner("Generating board-level report (60–120s)…"):
                summary = db.get_summary(chosen)

                # Simple compliance scores from findings
                fw_scores: dict = {}
                for fw in ["CIS", "PCI", "SOC2", "HIPAA", "NIST"]:
                    p = sum(1 for f in findings if f.get("status") == "PASS" and fw in (f.get("compliance") or {}))
                    fail = sum(1 for f in findings if f.get("status") != "PASS" and fw in (f.get("compliance") or {}))
                    total = p + fail
                    fw_scores[fw] = {"score": round(p / total * 100) if total else 0, "pass": p, "fail": fail}

                report_md = ai_client.generate_executive_report(summary, findings, fw_scores, acct_ids)
                analysis_data = existing_analysis or {}
                analysis_data["executive_report"] = report_md
                db.save_ai_analysis(chosen, db.current_user_id(), analysis_data)
                existing_report = report_md
                st.success("Report generated!")

        if existing_report:
            st.download_button(
                "⬇ Download Markdown",
                data=existing_report,
                file_name="aws_audit_executive_report.md",
                mime="text/markdown",
            )
            st.divider()
            st.markdown(existing_report)
        else:
            st.info("Click **Generate Executive Report** to create a board-ready compliance report.")
