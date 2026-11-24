import sqlite3
from datetime import datetime

DB_NAME = "security_logs.db"


def initialize_database():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            attempts INTEGER,
            severity TEXT,
            threat TEXT,
	    mitre_technique TEXT,
            detected_at TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("[+] Database initialized successfully")


def save_alerts(alerts):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    for alert in alerts:

        cursor.execute("""
            SELECT COUNT(*) FROM security_alerts
            WHERE ip_address = ? AND attempts = ? AND threat = ?
        """, (
            alert["ip"],
            alert["attempts"],
            alert["threat"]
        ))

        if cursor.fetchone()[0] > 0:
            continue

        cursor.execute("""
    INSERT INTO security_alerts
    (ip_address, attempts, severity, threat, detected_at, mitre_technique)
    VALUES (?, ?, ?, ?, ?, ?)
""", (
    alert["ip"],
    alert["attempts"],
    alert["severity"],
    alert["threat"],
    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    alert["mitre_technique"]
))

    connection.commit()
    connection.close()

    print("[+] Security alerts saved successfully")


def get_alerts():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM security_alerts")
    results = cursor.fetchall()

    connection.close()

    return results
