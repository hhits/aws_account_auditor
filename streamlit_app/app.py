"""
Entry point for Streamlit Community Cloud.
Run locally:  streamlit run streamlit_app/app.py
"""
import sys, os
_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import streamlit as st
import db

st.set_page_config(
    page_title="AWS Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  [data-testid="stSidebar"] { background: #0f172a; }
  [data-testid="stSidebar"] * { color: #e2e8f0 !important; }
  [data-testid="stSidebarNav"] a { color: #e2e8f0 !important; }
  .metric-card { background: white; border-radius: 12px; padding: 1rem; border: 1px solid #e5e7eb; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .sev-critical { color: #dc2626; font-weight: 700; }
  .sev-high     { color: #f97316; font-weight: 700; }
  .sev-medium   { color: #eab308; font-weight: 700; }
  .sev-low      { color: #22c55e; font-weight: 700; }
  .tag { display:inline-block; padding:2px 8px; border-radius:9999px; font-size:0.7rem; font-weight:600; margin:2px; }
  .finding-card { background:white; border:1px solid #e5e7eb; border-radius:12px; padding:1rem; margin:0.5rem 0; }
  .hero { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color:white; padding:2rem; border-radius:16px; margin-bottom:1rem; }
</style>
""", unsafe_allow_html=True)

# ── Auth gate ─────────────────────────────────────────────────────────────────
if not db.is_logged_in():
    st.markdown('<div class="hero"><h1>🛡️ AWS Security Auditor</h1><p>Multi-account · CIS · PCI-DSS · SOC2 · HIPAA · NIST · AI-Powered</p></div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.subheader("Sign in")
        with st.form("login"):
            email    = st.text_input("Email", placeholder="you@example.com")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Sign in", use_container_width=True, type="primary"):
                ok, err = db.login(email, password)
                if ok:
                    st.success("Signed in!")
                    st.rerun()
                else:
                    st.error(f"Login failed: {err}")
    st.stop()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ AWS Auditor")
    st.markdown(f"**{st.session_state.get('user_email', '')}**")
    st.divider()
    if st.button("Sign out", use_container_width=True):
        db.logout()
        st.rerun()

# ── Redirect to dashboard ─────────────────────────────────────────────────────
st.switch_page("pages/1_📊_Dashboard.py")
