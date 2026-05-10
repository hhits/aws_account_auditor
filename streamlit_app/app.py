"""
Entry point for Streamlit Community Cloud.
Run locally: streamlit run streamlit_app/app.py
"""
import sys, os
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

# ── Global CSS (all pages) ────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stSidebar"] { background:#0f172a; }
[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
[data-testid="stSidebarNav"] a { color:#e2e8f0 !important; }
.metric-card { background:white; border-radius:12px; padding:1rem;
               border:1px solid #e5e7eb; box-shadow:0 1px 3px rgba(0,0,0,.08); }
.sev-critical{color:#dc2626;font-weight:700}
.sev-high    {color:#f97316;font-weight:700}
.sev-medium  {color:#eab308;font-weight:700}
.sev-low     {color:#22c55e;font-weight:700}
</style>
""", unsafe_allow_html=True)

# ── Handle OAuth callback (?code=) ────────────────────────────────────────────
params = st.query_params
if "code" in params and not db.is_logged_in():
    with st.spinner("Completing sign-in…"):
        ok, err = db.exchange_oauth_code(params["code"])
        if ok:
            st.query_params.clear()
            st.rerun()
        else:
            st.error(f"OAuth sign-in failed: {err}")

# ── Already logged in → go to dashboard ──────────────────────────────────────
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

# ── Login-page-only CSS ───────────────────────────────────────────────────────
st.markdown("""
<style>
/* Hide Streamlit chrome */
#MainMenu, footer,
[data-testid="stHeader"],
[data-testid="stSidebar"],
[data-testid="collapsedControl"] { display:none !important; }

/* Zero outer padding */
.stMainBlockContainer.block-container { padding:0 !important; max-width:100vw !important; }
section[data-testid="stMain"] > div:first-child { padding:0 !important; }

/* Full dark page */
[data-testid="stAppViewContainer"],
section[data-testid="stMain"] { background:#0b1628 !important; }

/* Left column: comfortable padding and vertical layout */
div[data-testid="stColumn"]:not(:has([data-testid="stForm"])) > div:first-child {
    padding:4rem 3rem 3rem 4rem !important;
    display:flex;
    flex-direction:column;
    justify-content:center;
    min-height:100vh;
}

/* Force ALL text in the left (non-form) column to be bright */
div[data-testid="stColumn"]:not(:has([data-testid="stForm"])) * {
    color:#f1f5f9 !important;
}

/* Remove white box from logo image container */
div[data-testid="stColumn"]:not(:has([data-testid="stForm"])) [data-testid="stImage"],
div[data-testid="stColumn"]:not(:has([data-testid="stForm"])) .stImage {
    background:transparent !important;
    box-shadow:none !important;
}

/* Right column: white card */
div[data-testid="stColumn"]:has([data-testid="stForm"]) > div:first-child {
    background:#ffffff;
    border-radius:20px;
    padding:3rem 2.5rem !important;
    margin:2rem 2rem 2rem 1rem;
    box-shadow:0 25px 80px rgba(0,0,0,.45);
    min-height:auto;
    align-self:center;
}

/* Right column text: dark */
div[data-testid="stColumn"]:has([data-testid="stForm"]) p,
div[data-testid="stColumn"]:has([data-testid="stForm"]) label,
div[data-testid="stColumn"]:has([data-testid="stForm"]) span { color:#334155 !important; }

/* Hero title brightness */
.hero-title { color:#ffffff !important; text-shadow:none !important; }

/* Hero subtitle brightness */
.hero-sub { color:#cbd5e1 !important; }

/* Feature item title brightness */
.feat-title { color:#f1f5f9 !important; }

/* Feature item sub-text brightness */
.feat-sub { color:#94a3b8 !important; }

/* OAuth buttons */
.oauth-btn {
    display:flex; align-items:center; justify-content:center; gap:10px;
    width:100%; padding:11px 16px; border-radius:10px;
    font-size:.93rem; font-weight:600; text-decoration:none !important;
    color:#1e293b !important; background:#f8fafc;
    border:1.5px solid #e2e8f0; margin-bottom:10px;
    transition:all .18s ease;
}
.oauth-btn:hover {
    border-color:#94a3b8; background:#fff;
    box-shadow:0 4px 14px rgba(0,0,0,.1); transform:translateY(-1px);
}
.oauth-na {
    display:flex; align-items:center; justify-content:center; gap:10px;
    width:100%; padding:11px 16px; border-radius:10px;
    font-size:.93rem; color:#94a3b8; background:#f1f5f9;
    border:1.5px dashed #cbd5e1; margin-bottom:10px;
}
.div-line {
    display:flex; align-items:center; gap:10px;
    color:#94a3b8; font-size:.8rem; margin:16px 0;
}
.div-line::before,.div-line::after{ content:""; flex:1; height:1px; background:#e2e8f0; }
</style>
""", unsafe_allow_html=True)

# ── Two-column layout ─────────────────────────────────────────────────────────
left, right = st.columns([1.15, 0.85], gap="medium")

# ─────────────────────────────────────────────────────────────────────────────
# LEFT: logo + hero content
# ─────────────────────────────────────────────────────────────────────────────
with left:
    if os.path.exists(_LOGO):
        st.image(_LOGO, width=140)

    # Badges
    st.markdown("""
<div style="display:flex;flex-wrap:wrap;gap:8px;margin:1.2rem 0 1rem">
  <span style="background:rgba(59,130,246,.25);color:#93c5fd !important;padding:4px 12px;
    border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">MULTI-ACCOUNT</span>
  <span style="background:rgba(168,85,247,.25);color:#c4b5fd !important;padding:4px 12px;
    border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">AI-POWERED</span>
  <span style="background:rgba(16,185,129,.25);color:#6ee7b7 !important;padding:4px 12px;
    border-radius:99px;font-size:.7rem;font-weight:700;letter-spacing:.05em">CIS · PCI · SOC2</span>
</div>""", unsafe_allow_html=True)

    # Headline
    st.markdown("""
<h1 class="hero-title" style="font-size:2.2rem;font-weight:800;line-height:1.2;margin:0 0 .7rem;
  color:#ffffff !important;">
  Unified AWS Security<br>Audit Platform
</h1>
<p class="hero-sub" style="font-size:.95rem;line-height:1.7;margin-bottom:2rem;
  color:#cbd5e1 !important;">
  Continuous compliance, AI-driven insights, and<br>
  actionable remediation across all your AWS accounts.
</p>""", unsafe_allow_html=True)

    # Feature items
    FEATURES = [
        ("rgba(59,130,246,.25)",  "🔍", "Multi-account auditing",    "IAM, network, cost &amp; public exposure"),
        ("rgba(168,85,247,.25)",  "🤖", "AI-powered remediation",    "CLI &amp; CloudFormation fixes instantly"),
        ("rgba(16,185,129,.25)",  "📋", "Compliance scorecards",     "CIS, PCI-DSS, SOC 2, HIPAA, NIST 800-53"),
        ("rgba(245,158,11,.25)",  "🔒", "Zero credential storage",   "Role-based access — no AWS keys saved"),
    ]
    for bg, icon, title, sub in FEATURES:
        st.markdown(f"""
<div style="display:flex;align-items:flex-start;gap:13px;margin-bottom:.9rem">
  <div style="width:36px;height:36px;border-radius:10px;background:{bg};flex-shrink:0;
    display:flex;align-items:center;justify-content:center;font-size:1rem">{icon}</div>
  <div>
    <div class="feat-title" style="color:#f1f5f9 !important;font-weight:600;font-size:.9rem">{title}</div>
    <div class="feat-sub" style="color:#94a3b8 !important;font-size:.81rem;margin-top:2px">{sub}</div>
  </div>
</div>""", unsafe_allow_html=True)

    # Footer
    st.markdown("""
<div style="margin-top:2.5rem;padding-top:1rem;border-top:1px solid #1e3a5f;
  color:#94a3b8 !important;font-size:.76rem">
  © 2025 H&amp;H IT Solutions ·
  <a href="mailto:info@hhitsolutions.com"
    style="color:#60a5fa !important;text-decoration:none">info@hhitsolutions.com</a>
</div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# RIGHT: white card with OAuth + forms
# ─────────────────────────────────────────────────────────────────────────────
with right:
    st.markdown("""
<h2 style="font-size:1.55rem;font-weight:800;color:#0f172a !important;margin:0 0 .25rem">
  Welcome back 👋
</h2>
<p style="color:#64748b !important;margin-bottom:1.6rem;font-size:.9rem">
  Sign in to your account or create a new one
</p>""", unsafe_allow_html=True)

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
                f'<img src="{icon_url}" style="width:20px;height:20px;object-fit:contain;opacity:.35">'
                f'<span>{label} <em style="font-weight:400;font-size:.85rem">— not configured</em></span></div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="div-line">or continue with email</div>', unsafe_allow_html=True)

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
<p style="color:#94a3b8 !important;font-size:.74rem;text-align:center;margin-top:1.5rem;line-height:1.6">
  By signing in you agree to our Terms of Service.<br>
  Your AWS credentials are never stored by this app.
</p>""", unsafe_allow_html=True)
