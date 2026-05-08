import sys
import os
# Ensure project root is on sys.path so 'auditor.*' imports work whether this
# file is run directly or via `streamlit run auditor/dashboard.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import subprocess
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import streamlit as st

from auditor.utils.aws_utils import is_valid_finding

central = ZoneInfo("America/Chicago")

st.set_page_config(
    page_title="AWS Audit Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
    page_icon=":shield:",
    menu_items={
        'Get Help': 'https://docs.aws.amazon.com/audit-manager/latest/userguide/what-is.html'
    }
)

st.markdown("""
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #f8f9fa; }
        .stApp { background-color: #ffffff; }
        .sidebar .sidebar-content { background-color: #f0f2f6; }
        h1, h2, h3, h4 { color: #2c3e50; }
        .metric-box { background-color: #e3f2fd; padding: 10px; border-radius: 5px; }
        .executive-summary {
            background-color: #e8f5e9; padding: 15px;
            border-radius: 5px; margin-bottom: 20px;
        }
    </style>
""", unsafe_allow_html=True)

STANDARD_COLUMNS = {
    "AccountId": "Account ID", "Account ID": "Account ID", "account_id": "Account ID",
    "Finding.AccountId": "Account ID",
    "Region": "Region", "region": "Region",
    "Check": "Check", "check": "Check",
    "Status": "Status", "status": "Status",
    "Details": "Details", "details": "Details",
    "Severity": "Severity", "severity": "Severity",
    "Finding Type": "Finding Type", "FindingType": "Finding Type", "finding_type": "Finding Type",
    "Service": "Service", "service": "Service",
    "Message": "Details", "message": "Details",
    "Recommendation": "Recommendation", "recommendation": "Recommendation",
    "Timestamp": "Timestamp", "timestamp": "Timestamp",
    "Compliance": "Compliance", "compliance": "Compliance",
    "CloudFront": "CloudFront", "APIGateway": "API Gateway",
    "CloudTrail": "CloudTrail", "GuardDuty": "GuardDuty",
    "Lambda": "Lambda", "ElasticBeanstalk": "Elastic Beanstalk",
    "KMS": "KMS", "IAM": "IAM", "SecurityHub": "SecurityHub",
    "EC2": "EC2", "ELB": "ELB", "ELBv2": "ELBv2", "Macie": "Macie", "S3": "S3",
}

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


# === Data loading ===

@st.cache_data
def load_and_normalize_data(report_path):
    if not report_path or not os.path.exists(report_path):
        return pd.DataFrame({
            "Account ID": [], "Region": [], "Service": [], "Check": [],
            "Severity": [], "Status": [], "Finding Type": [],
            "Details": [], "Recommendation": [], "Timestamp": []
        })
    with open(report_path, 'r') as f:
        all_data = json.load(f)
    valid_data = [f for f in all_data if is_valid_finding(f)]
    normalized_data = []
    for finding in valid_data:
        standardized = {}
        for key, value in finding.items():
            col = STANDARD_COLUMNS.get(key, key)
            if col == "Timestamp" and isinstance(value, str):
                standardized[col] = pd.to_datetime(value, errors='coerce')
            else:
                standardized[col] = value
        normalized_data.append(standardized)
    temp_df = pd.DataFrame(normalized_data)
    df = temp_df.loc[:, ~temp_df.columns.duplicated()]
    if "Compliance" in df.columns:
        df["Compliance"] = df["Compliance"].apply(
            lambda x: json.dumps(x) if isinstance(x, dict) else x
        )
    return df


@st.cache_data(ttl=10)  # Re-scan report directory at most every 10 seconds
def get_available_reports():
    if not os.path.exists(REPORTS_DIR):
        return []
    files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")]
    return sorted(files, key=lambda f: os.path.getmtime(os.path.join(REPORTS_DIR, f)), reverse=True)


# === Sidebar ===

LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "logo.png")

with st.sidebar:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=260, caption="H&H IT Solutions")
    st.markdown("""
        <div style="text-align: left;">
            <h3><i>Cybersecurity Made Simple</i></h3><br>
            <p><b><u>Contact Us</u></b></p>
            <p>Email: <a href="mailto:info@hhitsolutions.com">info@hhitsolutions.com</a></p>
            <p>Website: <a href="https://hhitsolutions.com">H&H IT Solutions</a></p>
            <p>📞 : +1 (650) 713 8630</p>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("### 📂 Report")
    available_reports = get_available_reports()
    if available_reports:
        selected_report_name = st.selectbox("Select report", options=available_reports, index=0)
        selected_report_path = os.path.join(REPORTS_DIR, selected_report_name)
    else:
        st.warning("No reports found in auditor/reports/. Run an audit first.")
        selected_report_path = None

    # Audit trigger with running state feedback
    if "audit_running" not in st.session_state:
        st.session_state.audit_running = False

    if st.session_state.audit_running:
        st.info("⏳ Audit is running in the background...")
        if st.button("✅ Mark as complete / Refresh"):
            st.session_state.audit_running = False
            get_available_reports.clear()
            st.rerun()
    else:
        if st.button("▶ Run New Audit"):
            subprocess.Popen(["python3", "-m", "auditor.main"])
            st.session_state.audit_running = True
            st.rerun()


# === Load data ===

df = load_and_normalize_data(selected_report_path)

if df.empty:
    st.warning("No findings loaded. Select a report from the sidebar or run a new audit.")
    st.stop()


# === Filters ===

st.sidebar.title("🔎 Filter Findings")

required_cols = ["Account ID", "Region", "Service", "Check", "Severity", "Status", "Finding Type"]
missing = [c for c in required_cols if c not in df.columns]
if missing:
    st.error(f"Required columns missing from report: {', '.join(missing)}")
    st.stop()

account_ids = sorted(df["Account ID"].astype(str).dropna().unique().tolist())
regions     = sorted([r for r in df["Region"].dropna().astype(str).unique() if r])
services    = sorted(df["Service"].astype(str).dropna().unique().tolist())
severities  = sorted(df["Severity"].astype(str).dropna().unique().tolist())
statuses    = sorted(df["Status"].astype(str).dropna().unique().tolist())
finding_types = sorted(df["Finding Type"].astype(str).dropna().unique().tolist())

selected_accounts     = st.sidebar.multiselect("Account IDs",      options=account_ids,   default=account_ids)
selected_regions      = st.sidebar.multiselect("Regions",          options=regions,        default=regions)
selected_services     = st.sidebar.multiselect("Services",         options=services,       default=services)
selected_severity     = st.sidebar.multiselect("Severity Levels",  options=severities,     default=severities)
selected_status       = st.sidebar.multiselect("Status",           options=statuses,       default=statuses)
selected_finding_types= st.sidebar.multiselect("Finding Types",    options=finding_types,  default=finding_types)

if "Compliance" in df.columns:
    compliance_sidebar_df = pd.DataFrame([
        {"Standard": k, "Control": v}
        for d in df["Compliance"].dropna()
        for k, v in json.loads(d).items() if k and v
    ])
    compliance_standards = sorted(compliance_sidebar_df["Standard"].dropna().unique().tolist()) if not compliance_sidebar_df.empty else []
    selected_standards = st.sidebar.multiselect("Compliance Standards", options=compliance_standards, default=compliance_standards)
else:
    selected_standards = []

filtered_df = df[
    df["Account ID"].astype(str).isin(selected_accounts)
    & df["Region"].astype(str).isin(selected_regions)
    & df["Service"].astype(str).isin(selected_services)
    & df["Severity"].astype(str).isin(selected_severity)
    & df["Status"].astype(str).isin(selected_status)
    & df["Finding Type"].astype(str).isin(selected_finding_types)
]
if selected_standards and "Compliance" in df.columns:
    filtered_df = filtered_df[
        filtered_df["Compliance"].apply(
            lambda x: any(std in json.loads(x) for std in selected_standards) if isinstance(x, str) else False
        )
    ]


# === Header ===

st.markdown("""
    <h1>🔍 AWS Account Audit Dashboard</h1>
""", unsafe_allow_html=True)


# === Executive Summary ===

st.markdown("### 📑 Executive Summary", help="High-level overview for stakeholders")
critical_issues = len(filtered_df[filtered_df["Severity"] == "Critical"])
high_issues     = len(filtered_df[filtered_df["Severity"] == "High"])
st.markdown(f"""
    <div class="executive-summary">
        <p><strong>Total Findings:</strong> {len(filtered_df)}</p>
        <p><strong>Critical Issues:</strong> {critical_issues}</p>
        <p><strong>High Severity Issues:</strong> {high_issues}</p>
        <p><strong>Recommendations:</strong></p>
        <ul>
            <li>Prioritize remediation of Critical and High severity findings.</li>
            <li>Enable MFA for all IAM users with console access.</li>
            <li>Restrict public access to S3 buckets and security groups.</li>
        </ul>
    </div>
""", unsafe_allow_html=True)


# === Summary metrics ===

st.markdown("### 📊 Summary")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Findings",    len(df),                    help="Total findings in this report")
col2.metric("Filtered Findings", len(filtered_df),           help="Findings after applying filters")
col3.metric("Accounts",          df["Account ID"].nunique(), help="Unique AWS accounts audited")
col4.metric("Regions",           df["Region"].nunique(),     help="Unique regions audited")
col5.metric("Services",          df["Service"].nunique(),    help="Unique services audited")


# === Findings table ===

st.markdown("### 📋 Filtered Findings")

if filtered_df.empty:
    st.info("No findings match the current filters.")
else:
    def highlight_status(row):
        status   = row.get("Status", "")
        severity = row.get("Severity", "")
        styles = [''] * len(row)
        if status == "SKIPPED":
            styles = ['background-color: #fff9c4'] * len(row)
        elif status == "ERROR":
            styles = ['background-color: #ffebee'] * len(row)
        elif status == "WARNING":
            styles = ['background-color: #fff3e0'] * len(row)
        elif status == "FAIL":
            styles = ['background-color: #ef9a9a'] * len(row)
        if "Severity" in row.index:
            sev_idx = row.index.get_loc("Severity")
            if severity == "Critical":
                styles[sev_idx] = 'color: #d32f2f; font-weight: bold'
            elif severity == "High":
                styles[sev_idx] = 'color: #f44336'
            elif severity == "Medium":
                styles[sev_idx] = 'color: #ff9800'
            elif severity == "Low":
                styles[sev_idx] = 'color: #4caf50'
        return styles

    sort_cols = [c for c in ["Severity", "Account ID", "Check"] if c in filtered_df.columns]
    styled_df = filtered_df.sort_values(by=sort_cols).style.apply(highlight_status, axis=1)
    st.dataframe(styled_df, use_container_width=True, height=400)


# === Severity by Account ===

st.markdown("### 🧭 Severity by Account")
if not filtered_df.empty:
    severity_summary = filtered_df.groupby(["Account ID", "Severity"]).size().reset_index(name="Count")
    pivot_table = severity_summary.pivot(index="Account ID", columns="Severity", values="Count").fillna(0).astype(int)
    st.dataframe(pivot_table, use_container_width=True)


# === Severity pie charts by region ===

st.markdown("### 📌 Severity Distribution by Region")
if not filtered_df.empty:
    region_list = sorted([r for r in filtered_df["Region"].dropna().unique() if isinstance(r, str)])
    selected_regions_pie = st.multiselect("Select Regions for Pie Charts", options=region_list, default=region_list[:10])
    if selected_regions_pie:
        cols = st.columns(min(len(selected_regions_pie), 3))
        for idx, region in enumerate(selected_regions_pie):
            region_sev = filtered_df[filtered_df["Region"] == region]["Severity"].value_counts().reset_index()
            region_sev.columns = ["Severity", "Count"]
            fig = px.pie(
                region_sev, names='Severity', values='Count',
                title=f"{region} - Severity Breakdown", color='Severity',
                color_discrete_map={"Critical": "#d32f2f", "High": "#f44336", "Medium": "#ff9800", "Low": "#4caf50"}
            )
            with cols[idx % 3]:
                st.plotly_chart(fig, use_container_width=True)


# === Service breakdown ===

st.markdown("### 📈 Findings by Service")
if not filtered_df.empty:
    service_counts = filtered_df["Service"].value_counts().reset_index()
    service_counts.columns = ["Service", "Count"]
    fig = px.bar(service_counts, x="Service", y="Count",
                 title="Findings Distribution by Service", color="Service", text="Count")
    fig.update_traces(textposition='auto')
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True)


# === Compliance summary ===

st.markdown("### 🛡️ Compliance Summary")
if "Compliance" in filtered_df.columns:
    compliance_rows = []
    for comp in filtered_df["Compliance"].dropna():
        if comp and isinstance(comp, str) and comp != "{}":
            try:
                for standard, control in json.loads(comp).items():
                    compliance_rows.append({"Standard": standard, "Control": control})
            except json.JSONDecodeError:
                continue
    if compliance_rows:
        compliance_detail_df = pd.DataFrame(compliance_rows)
        comp_pivot = compliance_detail_df.groupby(["Standard", "Control"]).size().reset_index(name="Findings")
        st.dataframe(comp_pivot, use_container_width=True)
    else:
        st.info("No compliance mappings found in findings.")


# === Trend chart ===

st.sidebar.title("📅 Trend Filters")

has_timestamps = "Timestamp" in df.columns and not df["Timestamp"].isna().all()
min_date = df["Timestamp"].min().date() if has_timestamps else datetime.now(central).date() - timedelta(days=30)
max_date = df["Timestamp"].max().date() if has_timestamps else datetime.now(central).date()
if min_date >= max_date:
    max_date = min_date + timedelta(days=1)

date_range = st.sidebar.slider("Select Date Range", min_value=min_date, max_value=max_date, value=(min_date, max_date))
start_date, end_date = date_range

# Use a separate date-filtered copy so the global df and summary metrics are unaffected
daily_summary = pd.DataFrame()
if has_timestamps:
    date_filtered_df = df[(df["Timestamp"].dt.date >= start_date) & (df["Timestamp"].dt.date <= end_date)]
    daily_summary = (
        date_filtered_df.dropna(subset=["Timestamp"])
        .groupby(date_filtered_df["Timestamp"].dt.date)
        .size()
        .reset_index(name="Count")
    )
    st.markdown("### 📉 Historical Findings Trend")
    if not daily_summary.empty:
        fig = px.line(
            daily_summary, x="Timestamp", y="Count",
            title="Findings Over Time", markers=True,
            range_x=[
                daily_summary["Timestamp"].min() - pd.Timedelta(days=1),
                daily_summary["Timestamp"].max() + pd.Timedelta(days=1),
            ],
            height=400,
        )
        fig.update_traces(line_color="#FF6347")
        fig.update_layout(xaxis_title="Date", yaxis_title="Number of Findings", hovermode="x unified")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No findings in the selected date range.")
else:
    st.warning("No Timestamp data available for trend chart.")


# === Export options ===

st.markdown("### 📤 Export Options")
col1, col2, col3 = st.columns(3)

with col1:
    export_df = filtered_df.copy()
    if "Timestamp" in export_df.columns:
        export_df["Timestamp"] = export_df["Timestamp"].astype(str)
    st.download_button(
        "Download JSON",
        json.dumps(export_df.to_dict(orient="records"), indent=2),
        file_name="filtered_findings.json",
    )

with col2:
    st.download_button(
        "Download CSV",
        filtered_df.to_csv(index=False),
        file_name="filtered_findings.csv",
    )

with col3:
    html_content = filtered_df.to_html(index=False, classes="table table-striped")
    st.download_button(
        "Download HTML",
        f"<html><head><style>table {{border-collapse:collapse}} th,td {{border:1px solid #ddd;padding:8px}}</style></head><body>{html_content}</body></html>",
        file_name="filtered_findings.html",
    )

if not daily_summary.empty:
    st.download_button(
        "Download Trend CSV",
        daily_summary.to_csv(index=False),
        file_name="historical_findings_trend.csv",
    )


# === Footer ===

st.markdown("""
    <footer style="text-align: center; padding: 20px;">
        <p>© 2025 H&H IT Solutions. All rights reserved.</p>
        <p><a href="https://www.hhitsolutions.com" target="_blank">Visit our website</a></p>
    </footer>
""", unsafe_allow_html=True)
