import re
from collections import defaultdict


def analyze_logs(log_file):

    failed_attempts = defaultdict(int)
    events = []

    with open(log_file, "r") as file:

        for line in file:

            if "Failed password" in line:

                match = re.search(
                    r"Failed password for (\S+) from ([\d.]+)",
                    line
                )

                if match:

                    username = match.group(1)
                    ip_address = match.group(2)

                    failed_attempts[ip_address] += 1

                    events.append({
                        "username": username,
                        "ip": ip_address,
                        "event": "Failed Login"
                    })

    alerts = []

    for ip, count in failed_attempts.items():

        if count >= 5:
            severity = "HIGH"

        elif count >= 3:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        if count >= 3:

            alerts.append({
                "ip": ip,
                "attempts": count,
                "severity": severity,
                "threat": "Possible Brute Force Attack",
		"mitre_technique": "T1110"
            })


    return events, alerts
