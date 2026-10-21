import re
from collections import Counter


def analyze_logs(log_file):
    failed_ips = Counter()

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for line in file:
                if "Failed password" in line or "authentication failure" in line:
                    match = re.search(
                        r"from (\d{1,3}(?:\.\d{1,3}){3})", line
                    )

                    if match:
                        failed_ips[match.group(1)] += 1

        alerts = []

        for ip, count in failed_ips.items():
            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "risk": "HIGH" if count >= 3 else "LOW"
            })

        return {
            "total_suspicious_ips": len(failed_ips),
            "alerts": alerts
        }

    except FileNotFoundError:
        return {"error": f"Log file not found: {log_file}"}


if __name__ == "__main__":
    print(analyze_logs("logs/auth.log"))
