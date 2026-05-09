"""
Direct Supabase database operations — no FastAPI intermediary.
Uses service role key for all server-side reads/writes.
"""
from __future__ import annotations
import os
import uuid
from datetime import datetime
from typing import Any

import streamlit as st

try:
    from supabase import create_client, Client
    _HAS_SUPABASE = True
except ImportError:
    _HAS_SUPABASE = False

# ── Cookie-based session persistence ─────────────────────────────────────────

_COOKIE_TTL = 7 * 24 * 3600  # 7 days


def _cookies():
    """Return a CookieController, creating it once per session."""
    if "aws_audit_cc" not in st.session_state:
        try:
            from streamlit_cookies_controller import CookieController
            st.session_state["aws_audit_cc"] = CookieController(key="aws_audit")
        except Exception:
            st.session_state["aws_audit_cc"] = None
    return st.session_state["aws_audit_cc"]


def _save_cookies(uid: str, email: str, refresh: str) -> None:
    cc = _cookies()
    if not cc:
        return
    try:
        cc.set("u", uid,     max_age=_COOKIE_TTL)
        cc.set("e", email,   max_age=_COOKIE_TTL)
        cc.set("r", refresh, max_age=_COOKIE_TTL)
    except Exception:
        pass


def _clear_cookies() -> None:
    cc = _cookies()
    if not cc:
        return
    for k in ("u", "e", "r"):
        try:
            cc.remove(k)
        except Exception:
            pass


def restore_session() -> bool:
    """Try to restore auth session from browser cookies. Call at top of each page.

    CookieController is a JavaScript component — after a page refresh the
    WebSocket reconnects and session_state is cleared.  The component needs
    exactly ONE render cycle before its .get() calls return real values.
    We trigger that single forced rerun here and bail out; on the next render
    (still the same WebSocket session, so state is preserved) cookies are live.
    """
    if is_logged_in():
        return True

    cc = _cookies()
    if not cc:
        return False

    # First render after reconnect: let the JS component initialise, then rerun.
    if "cookie_init" not in st.session_state:
        st.session_state["cookie_init"] = True
        st.rerun()

    try:
        uid = cc.get("u")
        if not uid:
            return False
        refresh = cc.get("r") or ""
        if refresh:
            try:
                resp = _anon_client().auth.refresh_session(refresh)
                if resp and resp.session:
                    st.session_state["user_id"]      = resp.user.id
                    st.session_state["user_email"]   = resp.user.email
                    st.session_state["access_token"] = resp.session.access_token
                    _save_cookies(resp.user.id, resp.user.email,
                                  resp.session.refresh_token or "")
                    return True
            except Exception:
                pass
        # Fallback: trust stored uid/email without a live access_token.
        # DB writes that require auth will re-authenticate lazily.
        st.session_state["user_id"]      = uid
        st.session_state["user_email"]   = cc.get("e") or ""
        st.session_state["access_token"] = ""
        return True
    except Exception:
        return False


def _secrets(key: str, default: str = "") -> str:
    """Read from st.secrets (Streamlit Cloud) or environment variables (local)."""
    try:
        parts = key.split(".")
        obj = st.secrets
        for part in parts:
            obj = obj[part]
        return str(obj)
    except (KeyError, AttributeError):
        return os.environ.get(key.replace(".", "_").upper(), default)


@st.cache_resource
def _anon_client() -> "Client":
    url = _secrets("supabase.url") or _secrets("NEXT_PUBLIC_SUPABASE_URL")
    key = _secrets("supabase.anon_key") or _secrets("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
    if not url or not key:
        raise RuntimeError("Supabase URL and anon key must be configured in .streamlit/secrets.toml")
    return create_client(url, key)


@st.cache_resource
def _service_client() -> "Client":
    url = _secrets("supabase.url") or _secrets("NEXT_PUBLIC_SUPABASE_URL")
    key = _secrets("supabase.service_role_key") or _secrets("SUPABASE_SERVICE_ROLE_KEY") or _secrets("SUPABASE_JWT_SECRET")
    if not url or not key:
        raise RuntimeError("Supabase service role key must be configured")
    return create_client(url, key)


# ── Auth ──────────────────────────────────────────────────────────────────────

def login(email: str, password: str) -> tuple[bool, str]:
    """Returns (success, error_message)."""
    try:
        client = _anon_client()
        result = client.auth.sign_in_with_password({"email": email, "password": password})
        session = result.session
        st.session_state["user_id"]      = result.user.id
        st.session_state["user_email"]   = result.user.email
        st.session_state["access_token"] = session.access_token
        _save_cookies(result.user.id, result.user.email,
                      session.refresh_token or "")
        st.session_state["cookie_init"] = True   # cookies already available this session
        return True, ""
    except Exception as exc:
        return False, str(exc)


def logout():
    _clear_cookies()
    for key in ("user_id", "user_email", "access_token", "aws_audit_cc", "cookie_init"):
        st.session_state.pop(key, None)


def current_user_id() -> str | None:
    return st.session_state.get("user_id")


def is_logged_in() -> bool:
    return bool(current_user_id())


# ── AWS Config ────────────────────────────────────────────────────────────────

def get_config() -> dict | None:
    uid = current_user_id()
    if not uid:
        return None
    rows = _service_client().table("aws_configs").select("*").eq("user_id", uid).execute().data
    return rows[0] if rows else None


def save_config(data: dict) -> dict:
    uid = current_user_id()
    existing = get_config()
    data["user_id"] = uid
    data["updated_at"] = datetime.utcnow().isoformat()
    if existing:
        return _service_client().table("aws_configs").update(data).eq("id", existing["id"]).execute().data[0]
    data["id"] = str(uuid.uuid4())
    data["created_at"] = datetime.utcnow().isoformat()
    return _service_client().table("aws_configs").insert(data).execute().data[0]


def delete_config():
    uid = current_user_id()
    _service_client().table("aws_accounts").delete().eq("user_id", uid).execute()
    _service_client().table("aws_configs").delete().eq("user_id", uid).execute()


# ── Accounts ──────────────────────────────────────────────────────────────────

def list_accounts() -> list[dict]:
    uid = current_user_id()
    return _service_client().table("aws_accounts").select("*").eq("user_id", uid).execute().data


def add_account(account_id: str, account_name: str = "") -> dict:
    uid = current_user_id()
    row = {"id": str(uuid.uuid4()), "user_id": uid, "account_id": account_id, "account_name": account_name, "created_at": datetime.utcnow().isoformat()}
    return _service_client().table("aws_accounts").insert(row).execute().data[0]


def remove_account(row_id: str):
    _service_client().table("aws_accounts").delete().eq("id", row_id).execute()


# ── Audit jobs ────────────────────────────────────────────────────────────────

def list_audits(limit: int = 50) -> list[dict]:
    uid = current_user_id()
    return (_service_client().table("audit_jobs").select("*")
            .eq("user_id", uid).order("created_at", desc=True).limit(limit).execute().data)


def get_audit(job_id: str) -> dict | None:
    rows = _service_client().table("audit_jobs").select("*").eq("id", job_id).execute().data
    return rows[0] if rows else None


def create_audit_job() -> dict:
    uid = current_user_id()
    row = {
        "id": str(uuid.uuid4()), "user_id": uid, "status": "pending",
        "accounts_audited": [], "total_findings": 0,
        "created_at": datetime.utcnow().isoformat(),
    }
    return _service_client().table("audit_jobs").insert(row).execute().data[0]


def update_audit_job(job_id: str, updates: dict):
    _service_client().table("audit_jobs").update(updates).eq("id", job_id).execute()


def delete_audit_job(job_id: str):
    _service_client().table("findings").delete().eq("job_id", job_id).execute()
    _service_client().table("audit_jobs").delete().eq("id", job_id).execute()


def delete_audits_by_status(status: str | None = None):
    uid = current_user_id()
    q = _service_client().table("audit_jobs").select("id").eq("user_id", uid)
    if status:
        q = q.eq("status", status)
    job_ids = [r["id"] for r in q.execute().data]
    for jid in job_ids:
        _service_client().table("findings").delete().eq("job_id", jid).execute()
    q2 = _service_client().table("audit_jobs").delete().eq("user_id", uid)
    if status:
        q2 = q2.eq("status", status)
    q2.execute()


# ── Findings ──────────────────────────────────────────────────────────────────

def get_findings(job_id: str) -> list[dict]:
    return _service_client().table("findings").select("*").eq("job_id", job_id).execute().data


def save_findings(job_id: str, user_id: str, findings: list[dict]):
    """Bulk-insert findings for a completed audit job."""
    import json as _json
    rows = []
    for f in findings:
        ts = f.get("Timestamp") or f.get("timestamp")
        if isinstance(ts, str) and ts:
            try:
                from datetime import datetime as _dt
                ts = _dt.fromisoformat(ts.replace("Z","")).isoformat()
            except Exception:
                ts = None
        compliance = f.get("Compliance") or f.get("compliance") or {}

        rows.append({
            "id": str(uuid.uuid4()),
            "job_id": job_id,
            "user_id": user_id,
            "account_id": f.get("AccountId") or f.get("account_id", ""),
            "region": f.get("Region") or f.get("region", ""),
            "service": f.get("Service") or f.get("service", ""),
            "check_name": f.get("Check") or f.get("check_name", ""),
            "status": f.get("Status") or f.get("status", ""),
            "severity": f.get("Severity") or f.get("severity", "Low"),
            "finding_type": f.get("FindingType") or f.get("finding_type", ""),
            "details": f.get("Details") or f.get("details", ""),
            "recommendation": f.get("Recommendation") or f.get("recommendation", ""),
            "timestamp": ts,
            "compliance": compliance if isinstance(compliance, dict) else {},
            "created_at": datetime.utcnow().isoformat(),
        })
    # Insert in batches of 500
    for i in range(0, len(rows), 500):
        _service_client().table("findings").insert(rows[i:i+500]).execute()


def get_summary(job_id: str) -> dict:
    findings = get_findings(job_id)
    by_severity: dict[str, int] = {}
    by_service: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        svc = f.get("service", "Unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_service[svc]  = by_service.get(svc, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_service": by_service}


# ── AI analysis ───────────────────────────────────────────────────────────────

def get_ai_analysis(job_id: str) -> dict | None:
    rows = _service_client().table("ai_analyses").select("*").eq("job_id", job_id).execute().data
    return rows[0] if rows else None


def save_ai_analysis(job_id: str, user_id: str, result: dict):
    existing = get_ai_analysis(job_id)
    row = {
        "job_id": job_id, "user_id": user_id,
        "headline": result.get("headline", ""),
        "risk_level": result.get("risk_level", ""),
        "summary": result.get("summary", ""),
        "top_risks": result.get("top_risks", []),
        "quick_wins": result.get("quick_wins", []),
        "narrative": result.get("narrative", ""),
        "executive_report": result.get("executive_report"),
        "raw_response": result,
        "updated_at": datetime.utcnow().isoformat(),
    }
    if existing:
        _service_client().table("ai_analyses").update(row).eq("id", existing["id"]).execute()
    else:
        row["id"] = str(uuid.uuid4())
        row["created_at"] = datetime.utcnow().isoformat()
        _service_client().table("ai_analyses").insert(row).execute()


def save_finding_remediation(finding_id: str, remediation: dict):
    _service_client().table("findings").update({"ai_remediation": remediation}).eq("id", finding_id).execute()
