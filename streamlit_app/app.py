"""
Entry point for Streamlit Community Cloud.
Run locally:  streamlit run streamlit_app/app.py
"""
import sys, os, base64
_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
_LOGO = os.path.normpath(os.path.join(_LIB, "..", "..", "auditor", "assets", "logo.png"))
import streamlit as st
import db

st.set_page_config(
    page_title="AWS Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global app CSS (applies to all pages) ────────────────────────────────────
st.markdown("""
<style>
  [data-testid="stSidebar"]        { background:#0f172a; }
  [data-testid="stSidebar"] *      { color:#e2e8f0 !important; }
  [data-testid="stSidebarNav"] a   { color:#e2e8f0 !important; }
  .metric-card { background:white; border-radius:12px; padding:1rem;
                 border:1px solid #e5e7eb; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .sev-critical { color:#dc2626; font-weight:700; }
  .sev-high     { color:#f97316; font-weight:700; }
  .sev-medium   { color:#eab308; font-weight:700; }
  .sev-low      { color:#22c55e; font-weight:700; }
</style>
""", unsafe_allow_html=True)

# ── Handle OAuth callback (?code= query param) ────────────────────────────────
params = st.query_params
if "code" in params and not db.is_logged_in():
    with st.spinner("Completing sign-in…"):
        ok, err = db.exchange_oauth_code(params["code"])
    if ok:
        st.query_params.clear()
        st.rerun()
    else:
        st.error(f"OAuth sign-in failed: {err}")

# ── Already logged in → go to dashboard ───────────────────────────────────────
db.restore_session()
if db.is_logged_in():
    with st.sidebar:
        if os.path.exists(_LOGO):
            st.image(_LOGO, use_container_width=True)
        else:
            st.markdown("### 🛡️ AWS Auditor")
        st.markdown(f"**{st.session_state.get('user_email', '')}**")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            db.logout()
            st.rerun()
    st.switch_page("pages/1_📊_Dashboard.py")

# ── App URL for OAuth redirect ────────────────────────────────────────────────
try:
    APP_URL = str(st.secrets.get("app_url", "https://awsauditor.streamlit.app"))
except Exception:
    APP_URL = "https://awsauditor.streamlit.app"

# ─── Encode logo to base64 so it embeds cleanly in raw HTML ──────────────────
_logo_tag = ""
if os.path.exists(_LOGO):
    with open(_LOGO, "rb") as _f:
        _logo_b64 = base64.b64encode(_f.read()).decode()
    _logo_tag = f'<img src="data:image/png;base64,{_logo_b64}" style="width:220px;max-width:100%;margin-bottom:1.5rem">'
else:
    _logo_tag = '<div style="font-size:2rem;font-weight:800;color:white">🛡️ AWS Auditor</div>'

# ── Login page CSS ────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Hide Streamlit chrome on login page */
#MainMenu, footer, [data-testid="stHeader"]     { display:none !important; }
[data-testid="stSidebar"], [data-testid="collapsedControl"] { display:none !important; }

/* Remove all outer padding — full bleed layout */
.stMainBlockContainer.block-container { padding:0 !important; max-width:100vw !important; }
section[data-testid="stMain"] > div:first-child { padding:0 !important; }

/* Full dark page background */
[data-testid="stAppViewContainer"],
section[data-testid="stMain"]        { background:#0b1628 !important; }

/* Left column: transparent (inherits dark bg) */
[data-testid="stColumn"]:first-child > div {
    padding: 0 !important;
}

/* Right column: white card */
[data-testid="stColumn"]:last-child > div {
    background: #ffffff;
    border-radius: 20px;
    padding: 2.5rem 2.5rem !important;
    margin: 2rem 2rem 2rem 0;
    box-shadow: 0 25px 80px rgba(0,0,0,.45);
    min-height: calc(100vh - 4rem);
}

/* Force form labels + text inside RIGHT column to be dark */
[data-testid="stColumn"]:last-child label,
[data-testid="stColumn"]:last-child p,
[data-testid="stColumn"]:last-child small { color: #334155 !important; }

/* OAuth button style */
.oauth-btn {
    display:flex; align-items:center; justify-content:center; gap:10px;
    width:100%; padding:12px 16px; border-radius:10px;
    font-size:0.95rem; font-weight:600; cursor:pointer;
    text-decoration:none !important; color:#1e293b !important;
    background:#f8fafc; border:1.5px solid #e2e8f0;
    transition:all .18s ease; margin-bottom:10px;
}
.oauth-btn:hover {
    border-color:#94a3b8; background:#fff;
    box-shadow:0 4px 14px rgba(0,0,0,.1); transform:translateY(-1px);
}
.oauth-na {
    display:flex; align-items:center; justify-content:center; gap:10px;
    width:100%; padding:12px 16px; border-radius:10px;
    font-size:0.95rem; font-weight:600;
    color:#94a3b8; background:#f1f5f9;
    border:1.5px dashed #cbd5e1; margin-bottom:10px;
}
.divider-line {
    display:flex; align-items:center; gap:12px;
    color:#94a3b8; font-size:0.82rem; margin:18px 0;
}
.divider-line::before, .divider-line::after {
    content:""; flex:1; height:1px; background:#e2e8f0;
}
/* Tabs: override Streamlit default */
[data-testid="stColumn"]:last-child [data-baseweb="tab"] {
    font-weight:600;
}
</style>
""", unsafe_allow_html=True)

# ── Two-column layout ─────────────────────────────────────────────────────────
left, right = st.columns([1, 1], gap="small")

# ═══════════════════════════════════════════════════════════════════════════════
# LEFT PANEL — pure HTML, full control
# ═══════════════════════════════════════════════════════════════════════════════
with left:
    st.markdown(f"""
<div style="padding:3.5rem 3rem;min-height:100vh;
            display:flex;flex-direction:column;justify-content:space-between;">

  <!-- Logo -->
  {_logo_tag}

  <!-- Badges -->
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:1.2rem">
    <span style="background:rgba(59,130,246,.2);color:#93c5fd;padding:4px 12px;
                 border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">MULTI-ACCOUNT</span>
    <span style="background:rgba(168,85,247,.2);color:#c4b5fd;padding:4px 12px;
                 border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">AI-POWERED</span>
    <span style="background:rgba(16,185,129,.2);color:#6ee7b7;padding:4px 12px;
                 border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">CIS · PCI · SOC2</span>
  </div>

  <!-- Headline -->
  <h1 style="color:#fff;font-size:2rem;font-weight:800;line-height:1.2;margin:0 0 .8rem">
    Unified AWS Security<br>Audit Platform
  </h1>
  <p style="color:#94a3b8;font-size:.95rem;line-height:1.6;margin-bottom:2.2rem">
    Continuous compliance, AI-driven insights,<br>
    and actionable remediation across all your AWS accounts.
  </p>

  <!-- Feature list -->
  <div style="display:flex;flex-direction:column;gap:1rem;margin-bottom:2.5rem">

    <div style="display:flex;align-items:flex-start;gap:14px">
      <div style="width:36px;height:36px;border-radius:10px;background:rgba(59,130,246,.15);
                  display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">🔍</div>
      <div>
        <div style="color:#f1f5f9;font-weight:600;font-size:.9rem">Multi-account auditing</div>
        <div style="color:#64748b;font-size:.82rem">IAM, network, cost &amp; public exposure</div>
      </div>
    </div>

    <div style="display:flex;align-items:flex-start;gap:14px">
      <div style="width:36px;height:36px;border-radius:10px;background:rgba(168,85,247,.15);
                  display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">🤖</div>
      <div>
        <div style="color:#f1f5f9;font-weight:600;font-size:.9rem">AI-powered remediation</div>
        <div style="color:#64748b;font-size:.82rem">CLI &amp; CloudFormation fixes generated instantly</div>
      </div>
    </div>

    <div style="display:flex;align-items:flex-start;gap:14px">
      <div style="width:36px;height:36px;border-radius:10px;background:rgba(16,185,129,.15);
                  display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">📋</div>
      <div>
        <div style="color:#f1f5f9;font-weight:600;font-size:.9rem">Compliance scorecards</div>
        <div style="color:#64748b;font-size:.82rem">CIS, PCI-DSS, SOC 2, HIPAA, NIST 800-53</div>
      </div>
    </div>

    <div style="display:flex;align-items:flex-start;gap:14px">
      <div style="width:36px;height:36px;border-radius:10px;background:rgba(245,158,11,.15);
                  display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">🔒</div>
      <div>
        <div style="color:#f1f5f9;font-weight:600;font-size:.9rem">Zero credential storage</div>
        <div style="color:#64748b;font-size:.82rem">Role-based cross-account — no keys saved</div>
      </div>
    </div>

  </div>

  <!-- Footer -->
  <div style="color:#334155;font-size:.78rem;padding-top:1rem;border-top:1px solid #1e293b">
    © 2025 H&amp;H IT Solutions ·
    <a href="mailto:info@hhitsolutions.com"
       style="color:#475569;text-decoration:none">info@hhitsolutions.com</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# RIGHT PANEL — Streamlit widgets inside the white card
# ═══════════════════════════════════════════════════════════════════════════════
with right:
    st.markdown("""
<h2 style="font-size:1.6rem;font-weight:800;color:#0f172a;margin:0 0 .2rem">Welcome back 👋</h2>
<p style="color:#64748b;margin-bottom:1.8rem;font-size:.92rem">Sign in to your account or create a new one</p>
""", unsafe_allow_html=True)

    # ── OAuth buttons ─────────────────────────────────────────────────────────
    PROVIDERS = [
        ("google", "https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
         "Continue with Google"),
        ("github", "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
         "Continue with GitHub"),
        ("azure",  "https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/512px-Microsoft_logo.svg.png",
         "Continue with Microsoft"),
    ]

    for provider, icon_url, label in PROVIDERS:
        url, _ = db.get_oauth_url(provider, APP_URL)
        if url:
            st.markdown(
                f'<a href="{url}" class="oauth-btn" target="_self">'
                f'<img src="{icon_url}" style="width:20px;height:20px;object-fit:contain">'
                f'<span>{label}</span></a>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="oauth-na">'
                f'<img src="{icon_url}" style="width:20px;height:20px;object-fit:contain;opacity:.4">'
                f'<span>{label} — <em style="font-weight:400">not configured</em></span></div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="divider-line">or continue with email</div>',
                unsafe_allow_html=True)

    # ── Sign in / Create account tabs ──────────────────────────────────────────
    tab_in, tab_up = st.tabs(["Sign in", "Create account"])

    with tab_in:
        with st.form("login_form"):
            email    = st.text_input("Email address", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign in →", use_container_width=True, type="primary")
        if submitted:
            ok, err = db.login(email, password)
            if ok:
                st.rerun()
            else:
                st.error(err)

    with tab_up:
        with st.form("signup_form"):
            new_email = st.text_input("Email address", placeholder="you@example.com", key="su_email")
            new_pw    = st.text_input("Password", type="password",
                                      placeholder="Min 8 characters", key="su_pw")
            new_pw2   = st.text_input("Confirm password", type="password",
                                      placeholder="Re-enter password", key="su_pw2")
            register  = st.form_submit_button("Create account →", use_container_width=True, type="primary")
        if register:
            if new_pw != new_pw2:
                st.error("Passwords don't match.")
            elif len(new_pw) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                ok, status = db.signup(new_email, new_pw)
                if not ok:
                    st.error(status)
                elif status == "confirm":
                    st.success("✅ Check your email to confirm your account, then sign in.")
                else:
                    st.rerun()

    st.markdown("""
<p style="color:#94a3b8;font-size:.75rem;text-align:center;margin-top:1.5rem;line-height:1.6">
  By signing in you agree to our Terms of Service.<br>
  Your AWS credentials are never stored by this app.
</p>
""", unsafe_allow_html=True)
