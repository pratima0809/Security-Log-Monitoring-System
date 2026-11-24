import streamlit as st
import sqlite3
import pandas as pd

from risk_scoring import calculate_risk
from threat_intel import analyze_ip

st.set_page_config(
    page_title="Security Monitoring SOC",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SECURITY OPERATIONS CENTER")
st.caption("Security Log Monitoring & Threat Detection System")

# Connect to database
conn = sqlite3.connect("security_logs.db")

df = pd.read_sql_query(
    "SELECT * FROM security_alerts",
    conn
)

conn.close()

if not df.empty:

    # Calculate risk scores
    risk_data = df.apply(
        lambda row: calculate_risk({
            "severity": row["severity"],
            "attempts": row["attempts"]
        }),
        axis=1
    )

    df["Risk Score"] = [
        item["risk_score"] for item in risk_data
    ]

    df["Risk Level"] = [
        item["risk_level"] for item in risk_data
    ]

    # IP intelligence
    df["IP Category"] = df["ip_address"].apply(
        lambda ip: analyze_ip(ip)["category"]
    )

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", len(df))
    col2.metric("Critical Threats", len(df[df["Risk Level"] == "CRITICAL"]))
    col3.metric("High Severity", len(df[df["severity"] == "HIGH"]))
    col4.metric("Unique IPs", df["ip_address"].nunique())

    st.divider()

    # Charts
    left, right = st.columns(2)

    with left:
        st.subheader("Threat Severity")
        st.bar_chart(df["severity"].value_counts())

    with right:
        st.subheader("Risk Distribution")
        st.bar_chart(df["Risk Level"].value_counts())

    st.divider()

    # Alert table
    st.subheader("Security Alerts")

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

    # IP information
    st.subheader("IP Intelligence")

    st.dataframe(
        df[["ip_address", "IP Category", "Risk Score", "Risk Level"]],
        use_container_width=True,
        hide_index=True
    )

else:
    st.warning("No security alerts found. Run main.py first.")

st.sidebar.success("Monitoring System Online")
st.sidebar.write("Detection Engine: Active")
st.sidebar.write("Database: Connected")
st.sidebar.write("MITRE ATT&CK: Enabled")
