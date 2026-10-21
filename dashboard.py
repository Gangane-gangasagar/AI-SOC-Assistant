from http.server import BaseHTTPRequestHandler, HTTPServer
from detector import analyze_logs
from html import escape


class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        result = analyze_logs("logs/auth.log")
        alerts = result.get("alerts", [])

        cards = ""
        for alert in alerts:
            ip = escape(str(alert["ip"]))
            risk = escape(str(alert["risk"]))
            attempts = alert["failed_attempts"]

            cards += f"""
            <div class="card">
                <h3>IP Address: {ip}</h3>
                <p>Failed Attempts: {attempts}</p>
                <p>Risk Level: <b>{risk}</b></p>
            </div>
            """

        if "error" in result:
            cards = f"<p>{escape(result['error'])}</p>"
        elif not alerts:
            cards = "<p>No suspicious login activity detected.</p>"

        page = f"""
        <html>
        <head>
        <title>AI SOC Assistant</title>
        <style>
        body {{
            background: #101827;
            color: white;
            font-family: Arial;
            padding: 30px;
        }}
        h1 {{ color: #38bdf8; }}
        .card {{
            background: #1e293b;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 5px solid #38bdf8;
        }}
        .stats {{
            background: #263449;
            padding: 15px;
            border-radius: 10px;
        }}
        </style>
        </head>
        <body>
        <h1>AI SOC Assistant</h1>
        <p>Security Operations Dashboard</p>
        <div class="stats">
            <h2>Suspicious IPs: {result.get('total_suspicious_ips', 0)}</h2>
            <p>Login Failure Monitoring</p>
        </div>
        <h2>Security Alerts</h2>
        {cards}
        <p>Local SOC Monitoring Dashboard</p>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))


print("SOC Dashboard: http://127.0.0.1:8000")
HTTPServer(("127.0.0.1", 8000), Dashboard).serve_forever()
