"""
AI client — Groq (free, cloud) preferred; falls back to Ollama (local).
Set GROQ_API_KEY in Streamlit secrets or environment to enable cloud AI.
"""
from __future__ import annotations
import json
import os
import logging

import requests

logger = logging.getLogger(__name__)

# ── Groq ──────────────────────────────────────────────────────────────────────
GROQ_BASE  = "https://api.groq.com/openai/v1"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_BASE   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL", "llama3.2")
TIMEOUT = 120


def _groq_key() -> str:
    """Read Groq API key — checks env, all secret locations, and common TOML mistakes."""
    if os.environ.get("GROQ_API_KEY"):
        return os.environ["GROQ_API_KEY"]
    try:
        import streamlit as st
        for path in (
            ("GROQ_API_KEY",),          # top-level (correct placement)
            ("aws", "GROQ_API_KEY"),    # under [aws] section (common TOML mistake)
            ("groq", "api_key"),        # under [groq] section
            ("groq", "GROQ_API_KEY"),
        ):
            try:
                obj = st.secrets
                for part in path:
                    obj = obj[part]
                val = str(obj).strip()
                if val:
                    return val
            except (KeyError, AttributeError):
                continue
    except Exception:
        pass
    return ""


def is_available() -> tuple[bool, str]:
    """Returns (available, description). Prefers Groq over Ollama."""
    # Try Groq first
    key = _groq_key()
    if key:
        try:
            r = requests.get(f"{GROQ_BASE}/models",
                             headers={"Authorization": f"Bearer {key}"}, timeout=5)
            if r.status_code == 200:
                return True, f"Groq · {GROQ_MODEL}"
        except Exception:
            pass
        return False, "Groq API key set but unreachable"

    # Fall back to Ollama
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        if any(OLLAMA_MODEL in m for m in models):
            return True, f"Ollama · {OLLAMA_MODEL}"
        if models:
            return False, f"Ollama running but model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}"
        return False, "Ollama running but no models pulled"
    except Exception:
        return False, "No AI available. Add GROQ_API_KEY to Streamlit secrets (free at console.groq.com)"


def _complete(messages: list[dict]) -> str:
    """Send chat messages and return the reply text."""
    key = _groq_key()
    if key:
        r = requests.post(
            f"{GROQ_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": GROQ_MODEL, "messages": messages, "temperature": 0.3},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    # Ollama fallback
    r = requests.post(
        f"{OLLAMA_BASE}/api/chat",
        json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def _findings_snippet(findings: list[dict], n: int = 40) -> str:
    rows = []
    for f in findings[:n]:
        rows.append(
            f"[{f.get('severity','?')}] {f.get('service','?')} / {f.get('check_name','?')} "
            f"({f.get('status','?')}) — {f.get('details','')[:120]}"
        )
    return "\n".join(rows)


def analyze_findings(findings: list[dict], account_ids: list[str]) -> dict:
    snippet = _findings_snippet(findings)
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "?")
        counts[sev] = counts.get(sev, 0) + 1

    system = (
        "You are a senior AWS cloud security engineer. "
        "Analyse the provided findings and respond ONLY with valid JSON. "
        "Do not include any text outside the JSON object."
    )
    user = f"""Accounts audited: {', '.join(account_ids)}
Severity counts: {json.dumps(counts)}
Findings (sample):
{snippet}

Respond with this EXACT JSON:
{{
  "headline": "<one-sentence executive summary>",
  "risk_level": "<Critical|High|Medium|Low>",
  "summary": "<2-3 sentence overview>",
  "top_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "quick_wins": ["<fix 1>", "<fix 2>", "<fix 3>"],
  "narrative": "<3-4 paragraph analysis covering IAM, network, data, logging posture>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except Exception:
        return {"headline": "Analysis complete", "risk_level": "Unknown", "summary": raw[:400],
                "top_risks": [], "quick_wins": [], "narrative": raw}


def generate_remediation(finding: dict) -> dict:
    system = (
        "You are an AWS security engineer. "
        "Respond ONLY with valid JSON. No text outside the JSON object."
    )
    user = f"""Finding:
Service: {finding.get('service')}  Check: {finding.get('check_name')}
Severity: {finding.get('severity')}  Details: {finding.get('details')}
Recommendation: {finding.get('recommendation')}
Account: {finding.get('account_id')}  Region: {finding.get('region')}

Respond with:
{{
  "explanation": "<why this is a risk>",
  "steps": ["<step 1>", "<step 2>"],
  "cli_script": "<AWS CLI commands with comments>",
  "terraform_snippet": "<Terraform HCL or empty string>",
  "estimated_effort": "<5 minutes|30 minutes|2 hours|1 day>",
  "risk_if_not_fixed": "<exploitation scenario>"
}}"""

    raw = _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith(("json", "hcl")):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except Exception:
        return {"explanation": finding.get("recommendation", ""),
                "steps": [raw[:300]], "cli_script": "", "terraform_snippet": "",
                "estimated_effort": "Unknown", "risk_if_not_fixed": ""}


def chat(question: str, findings: list[dict], history: list[dict] | None = None) -> str:
    snippet = _findings_snippet(findings, n=50)
    system = (
        "You are an expert AWS cloud security analyst. "
        "Answer questions about the provided audit findings concisely and accurately. "
        "Always ground answers in the specific findings provided."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Here are the current audit findings:\n\n{snippet}\n\nUse this context for my questions."},
        {"role": "assistant", "content": "Understood. I have reviewed the audit findings and am ready to answer your questions."},
    ]
    if history:
        messages.extend(history[-10:])  # keep last 10 turns to stay within context
    messages.append({"role": "user", "content": question})
    return _complete(messages)


def generate_executive_report(summary: dict, findings: list[dict], compliance_scores: dict, account_ids: list[str]) -> str:
    framework_lines = "\n".join(
        f"- {fw}: {data['score']}% ({data['pass']} pass / {data['fail']} fail)"
        for fw, data in compliance_scores.items()
    )
    snippet = _findings_snippet(findings, n=30)
    system = (
        "You are a senior cybersecurity consultant writing a board-level compliance report. "
        "Write in clear, professional Markdown with headers and bullet points."
    )
    user = f"""Write an executive compliance report for the following AWS audit.

Accounts: {', '.join(account_ids)}
Total findings: {summary.get('total', 0)}
Severity: {json.dumps(summary.get('by_severity', {}))}
Compliance scores:
{framework_lines}
Sample findings:
{snippet}

Sections: 1. Executive Summary  2. Risk Overview  3. Compliance Posture (per framework)
4. Critical/High Issues  5. Remediation Roadmap  6. Conclusion.
~800-1200 words, actionable and specific to AWS."""

    return _complete([{"role": "system", "content": system}, {"role": "user", "content": user}])
