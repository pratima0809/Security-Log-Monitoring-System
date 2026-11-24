import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import os

from datetime import datetime
from risk_scoring import calculate_risk
from threat_intel import analyze_ip
from database import initialize_database

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Security Monitoring SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
# Initialize database on application startup
initialize_database()

# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background-color: #080d18;
    color: #e5e7eb;
}

[data-testid="stSidebar"] {
    background-color: #0d1423;
    border-right: 1px solid #25344a;
}

.hero {
    background: linear-gradient(120deg, #14233d, #0d1729);
    padding: 28px;
    border-radius: 15px;
    border: 1px solid #29466c;
    margin-bottom: 25px;
}

.hero h1 {
    color: #60a5fa;
    font-size: 30px;
    font-weight: 800;
}

.hero p {
    color: #94a3b8;
    font-size: 14px;
}

.section-title {
    color: #60a5fa;
    font-size: 19px;
    font-weight: 700;
    margin-top: 25px;
    margin-bottom: 15px;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# DATABASE HEALTH CHECK
# ==========================================

def check_database():

    try:

        if not os.path.exists("security_logs.db"):
            return False

        conn = sqlite3.connect(
            "security_logs.db",
            timeout=3
        )

        cursor = conn.cursor()

        cursor.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            AND name='security_alerts'
        """)

        result = cursor.fetchone()

        conn.close()

        return result is not None

    except sqlite3.Error:
        return False


# ==========================================
# MODULE HEALTH CHECK
# ==========================================

def check_module(filename):
    return os.path.isfile(filename)


# ==========================================
# LOAD DATABASE
# ==========================================

@st.cache_data(ttl=10)
def load_data():

    try:

        conn = sqlite3.connect(
            "security_logs.db",
            timeout=3
        )

        df = pd.read_sql_query(
            """
            SELECT * FROM security_alerts
            ORDER BY detected_at DESC
            """,
            conn
        )

        conn.close()

        return df

    except (sqlite3.Error, pd.errors.DatabaseError):
        return pd.DataFrame()


df = load_data()


# ==========================================
# PROCESS SECURITY DATA
# ==========================================

if not df.empty:

    risk_data = df.apply(
        lambda row: calculate_risk({
            "severity": str(row["severity"]).upper(),
            "attempts": int(row["attempts"])
        }),
        axis=1
    )

    df["Risk Score"] = [
        item["risk_score"] for item in risk_data
    ]

    df["Risk Level"] = [
        item["risk_level"] for item in risk_data
    ]

    df["IP Category"] = df["ip_address"].apply(
        lambda ip: analyze_ip(str(ip))["category"]
    )


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.markdown("# 🛡️ SENTINEL")

st.sidebar.caption(
    "SECURITY OPERATIONS CENTER"
)

st.sidebar.divider()

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Overview",
        "Security Alerts",
        "IP Intelligence",
        "MITRE ATT&CK",
        "Reports"
    ]
)


# ==========================================
# SYSTEM STATUS
# ==========================================

database_status = check_database()
detector_status = check_module("detector.py")
risk_status = check_module("risk_scoring.py")
intel_status = check_module("threat_intel.py")

st.sidebar.divider()

st.sidebar.markdown("### 🖥️ SYSTEM STATUS")


def show_status(label, status):

    if status:
        st.sidebar.success(
            f"{label}: Available"
        )

    else:
        st.sidebar.error(
            f"{label}: Unavailable"
        )


show_status("SQLite Database", database_status)
show_status("Detection Module", detector_status)
show_status("Risk Scoring", risk_status)
show_status("IP Intelligence", intel_status)


if all([
    database_status,
    detector_status,
    risk_status,
    intel_status
]):

    st.sidebar.success(
        "Core Components Available"
    )

else:

    st.sidebar.warning(
        "Some Components Unavailable"
    )


st.sidebar.divider()

if st.sidebar.button(
    "🔄 Refresh Dashboard",
    width="stretch"
):

    st.cache_data.clear()
    st.rerun()


st.sidebar.caption("SENTINEL SOC v1.0")


# ==========================================
# HEADER
# ==========================================

st.markdown("""
<div class="hero">

<h1>🛡️ SENTINEL SOC COMMAND CENTER</h1>

<p>
SECURITY LOG MONITORING & THREAT DETECTION SYSTEM
</p>

<p>
Threat Detection | Risk Analysis | Security Intelligence
</p>

</div>
""", unsafe_allow_html=True)


# ==========================================
# OVERVIEW
# ==========================================

if page == "Overview":

    st.markdown("### SECURITY OVERVIEW")

    if not df.empty:

        total_alerts = len(df)

        critical = len(
            df[df["Risk Level"] == "CRITICAL"]
        )

        high = len(
            df[df["severity"].str.upper() == "HIGH"]
        )

        unique_ips = df["ip_address"].nunique()


        # METRIC CARDS

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric(
                "TOTAL ALERTS",
                total_alerts,
                border=True
            )

        with c2:
            st.metric(
                "CRITICAL THREATS",
                critical,
                border=True
            )

        with c3:
            st.metric(
                "HIGH SEVERITY",
                high,
                border=True
            )

        with c4:
            st.metric(
                "UNIQUE IP ADDRESSES",
                unique_ips,
                border=True
            )


        # THREAT ANALYTICS

        st.markdown(
            '<div class="section-title">THREAT ANALYTICS</div>',
            unsafe_allow_html=True
        )

        left, right = st.columns(2)


        with left:

            severity = (
                df["severity"]
                .str.upper()
                .value_counts()
                .reset_index()
            )

            severity.columns = [
                "Severity",
                "Count"
            ]

            fig = px.pie(
                severity,
                names="Severity",
                values="Count",
                hole=0.65,
                color="Severity",

                color_discrete_map={
                    "HIGH": "#ef4444",
                    "MEDIUM": "#f59e0b",
                    "LOW": "#22c55e"
                },

                title="Threat Severity Distribution"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#111b2d",
                plot_bgcolor="#111b2d"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )


        with right:

            risk = (
                df["Risk Level"]
                .value_counts()
                .reset_index()
            )

            risk.columns = [
                "Risk Level",
                "Count"
            ]

            fig = px.bar(
                risk,
                x="Risk Level",
                y="Count",
                color="Risk Level",

                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#22c55e"
                },

                title="Risk Classification"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#111b2d",
                plot_bgcolor="#111b2d"
            )

            st.plotly_chart(
                fig,
                width="stretch"
            )


        # RECENT EVENTS

        st.markdown("### RECENT SECURITY EVENTS")

        st.dataframe(
            df.head(10),
            width="stretch",
            hide_index=True
        )

    else:

        st.warning(
            "No security alerts found. Run main.py first."
        )


# ==========================================
# SECURITY ALERTS
# ==========================================

elif page == "Security Alerts":

    st.subheader("🚨 SECURITY ALERT MANAGEMENT")

    if not df.empty:

        severity_filter = st.multiselect(
            "Filter by Severity",
            sorted(df["severity"].dropna().unique())
        )

        filtered = df.copy()

        if severity_filter:

            filtered = filtered[
                filtered["severity"].isin(severity_filter)
            ]

        search = st.text_input(
            "🔍 Search IP Address"
        )

        if search:

            filtered = filtered[
                filtered["ip_address"]
                .astype(str)
                .str.contains(
                    search,
                    case=False,
                    na=False
                )
            ]

        st.write(
            f"Showing {len(filtered)} alerts"
        )

        st.dataframe(
            filtered,
            width="stretch",
            hide_index=True
        )

    else:

        st.info("No security alerts available.")


# ==========================================
# IP INTELLIGENCE
# ==========================================

elif page == "IP Intelligence":

    st.subheader("🌐 IP INTELLIGENCE ANALYSIS")

    st.caption(
        "IP classification using Python ipaddress module."
    )

    if not df.empty:

        st.dataframe(
            df[
                [
                    "ip_address",
                    "IP Category",
                    "Risk Score",
                    "Risk Level"
                ]
            ],
            width="stretch",
            hide_index=True
        )

    else:

        st.info("No IP intelligence records available.")


# ==========================================
# MITRE ATT&CK
# ==========================================

elif page == "MITRE ATT&CK":

    st.subheader("🎯 MITRE ATT&CK TECHNIQUE MAPPING")

    if not df.empty:

        st.dataframe(
            df[
                [
                    "ip_address",
                    "threat",
                    "mitre_technique",
                    "severity"
                ]
            ],
            width="stretch",
            hide_index=True
        )

        st.info(
            "MITRE techniques displayed from database records."
        )

    else:

        st.info("No MITRE ATT&CK records available.")


# ==========================================
# REPORTS
# ==========================================

elif page == "Reports":

    st.subheader("📊 SECURITY REPORT CENTER")

    if not df.empty:

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Total Alerts",
            len(df)
        )

        c2.metric(
            "Critical Threats",
            len(
                df[df["Risk Level"] == "CRITICAL"]
            )
        )

        c3.metric(
            "Unique IPs",
            df["ip_address"].nunique()
        )

        csv = df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "⬇️ Download Security Report",
            data=csv,
            file_name="security_report.csv",
            mime="text/csv",
            width="stretch"
        )

    else:

        st.warning(
            "No security data available."
        )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "Security Log Monitoring & Threat Detection System | SENTINEL SOC"
)

st.caption(
    f"Last refreshed: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
)
