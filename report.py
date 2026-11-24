import csv
import os
from database import get_alerts


def generate_report():

    records = get_alerts()

    os.makedirs("reports", exist_ok=True)

    filename = "reports/security_report.csv"

    with open(filename, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "ID",
            "IP Address",
            "Attempts",
            "Severity",
            "Threat",
            "Detected At"
        ])

        for record in records:
            writer.writerow(record)

    print("\n[+] Security report generated!")
    print("[+] Report location:", filename)


if __name__ == "__main__":
    generate_report()
