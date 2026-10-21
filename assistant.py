from detector import analyze_logs


def generate_summary(result):
    if "error" in result:
        return f"Error: {result['error']}"

    alerts = result.get("alerts", [])

    print("\n===== AI SOC ASSISTANT =====")
    print(f"Suspicious IPs detected: {result['total_suspicious_ips']}")

    if not alerts:
        print("No suspicious login activity detected.")
        return

    for alert in alerts:
        ip = alert["ip"]
        attempts = alert["failed_attempts"]
        risk = alert["risk"]

        print(f"\nIP Address: {ip}")
        print(f"Failed Attempts: {attempts}")
        print(f"Risk Level: {risk}")

        if risk == "HIGH":
            print("AI Summary: Repeated failed logins detected. Investigate this IP.")
        else:
            print("AI Summary: Limited failed login activity. Continue monitoring.")


if __name__ == "__main__":
    result = analyze_logs("logs/auth.log")
    generate_summary(result)
