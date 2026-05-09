import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from streamlit_app.lib import db, ai_client

st.set_page_config(page_title="Settings · AWS Auditor", page_icon="🛠️", layout="wide")

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
  <h1 style="margin:0">🛠️ Settings & Diagnostics</h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8">Account info, AI model, and data management</p>
</div>""", unsafe_allow_html=True)

# ── Account info ──────────────────────────────────────────────────────────────
st.subheader("Account")
st.markdown(f"**Email:** {st.session_state.get('user_email', '—')}")
st.markdown(f"**User ID:** `{st.session_state.get('user_id', '—')}`")

st.divider()

# ── AI / Ollama settings ──────────────────────────────────────────────────────
st.subheader("🤖 AI Provider")
ai_ok, ai_msg = ai_client.is_available()

if ai_ok:
    icon = "☁️" if "Groq" in ai_msg else "💻"
    st.success(f"{icon} AI connected — {ai_msg}")
else:
    st.warning(f"AI unavailable: {ai_msg}")

with st.expander("Setup instructions", expanded=not ai_ok):
    st.markdown("""
### Option 1 — Groq (recommended · free · works on Streamlit Cloud)

1. Sign up free at **[console.groq.com](https://console.groq.com)**
2. Create an API key
3. Add to Streamlit secrets (App settings → Secrets):
```toml
GROQ_API_KEY = "gsk_..."
```
Default model: `llama-3.1-8b-instant`. Override with:
```toml
GROQ_MODEL = "llama-3.3-70b-versatile"
```

---

### Option 2 — Ollama (local only · no API key needed)

```bash
# Install
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3.2

# Start
ollama serve
```
Override model:
```bash
export OLLAMA_MODEL=mistral
streamlit run streamlit_app/app.py
```
""")

st.divider()

# ── Data management ───────────────────────────────────────────────────────────
st.subheader("🗑 Data Management")

jobs = db.list_audits()
completed = [j for j in jobs if j["status"] == "completed"]
failed    = [j for j in jobs if j["status"] == "failed"]
pending   = [j for j in jobs if j["status"] in ("pending", "running")]

st.markdown(f"""
| Status | Count |
|---|---|
| Completed | {len(completed)} |
| Failed | {len(failed)} |
| Running/Pending | {len(pending)} |
| **Total** | **{len(jobs)}** |
""")

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Delete failed audits", use_container_width=True, disabled=not failed):
        db.delete_audits_by_status("failed")
        st.success(f"Deleted {len(failed)} failed audit(s).")
        st.rerun()
with col2:
    if st.button("Delete all audits", use_container_width=True, type="secondary", disabled=not jobs):
        db.delete_audits_by_status()
        st.success("All audits deleted.")
        st.rerun()
with col3:
    if st.button("Sign out", use_container_width=True):
        db.logout()
        st.switch_page("app.py")

st.divider()

# ── Environment info ──────────────────────────────────────────────────────────
with st.expander("Environment diagnostics"):
    import sys, platform
    st.markdown(f"""
| Variable | Value |
|---|---|
| Python | `{sys.version.split()[0]}` |
| Platform | `{platform.platform()}` |
| OLLAMA_URL | `{os.environ.get('OLLAMA_URL','http://localhost:11434 (default)')}` |
| OLLAMA_MODEL | `{os.environ.get('OLLAMA_MODEL','llama3.2 (default)')}` |
""")
