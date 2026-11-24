from detector import analyze_logs
from database import initialize_database, save_alerts, get_alerts
from report import generate_report

print("\n===================================")
print("   SECURITY LOG MONITORING SYSTEM")
print("===================================\n")

# Initialize database
initialize_database()

# Select log file
log_file = "logs/test_attack.log"

# Analyze security logs
events, alerts = analyze_logs(log_file)

print("\nTOTAL EVENTS DETECTED:", len(events))
print("TOTAL SECURITY ALERTS:", len(alerts))

print("\nSECURITY ALERTS:")
print("-----------------------------------")

if alerts:
    for alert in alerts:
        print("IP Address:", alert["ip"])
        print("Attempts:", alert["attempts"])
        print("Severity:", alert["severity"])
        print("Threat:", alert["threat"])
        print("MITRE ATT&CK:", alert["mitre_technique"])
        print("-----------------------------------")
else:
    print("No suspicious activity detected.")

# Save alerts to database
save_alerts(alerts)

# Display database records
print("\nDATABASE RECORDS:")
records = get_alerts()

for record in records:
    print(record)

# Generate security report
generate_report()

print("\n[+] SCAN COMPLETED SUCCESSFULLY")
