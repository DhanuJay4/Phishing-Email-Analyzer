from email import policy
from email.parser import BytesParser
from pathlib import Path
from email.utils import parseaddr
from urllib.parse import urlparse
import html
import ipaddress
import json
import re
import sys


RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd",
    ".js", ".vbs", ".ps1", ".msi",
    ".hta", ".jar", ".com"
}


def get_domain(email_address):
    """Extract the domain from an email address."""
    _, address = parseaddr(email_address)

    if "@" not in address:
        return ""

    return address.split("@", 1)[1].lower()


def extract_urls(text):
    """Extract HTTP/HTTPS URLs from text."""
    url_pattern = r"https?://[^\s<>\"]+"
    return re.findall(url_pattern, text)


def analyze_url(url):
    """Check a URL for suspicious characteristics."""
    findings = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return findings

        try:
            ipaddress.ip_address(hostname)
            findings.append(
                "URL uses an IP address instead of a domain name."
            )
        except ValueError:
            pass

        if "@" in url:
            findings.append(
                "URL contains '@', which can obscure the actual destination."
            )

        if len(url) > 100:
            findings.append("URL is unusually long.")

        if parsed.scheme.lower() not in ("http", "https"):
            findings.append("URL uses a non-standard scheme.")

    except ValueError:
        findings.append("URL could not be parsed normally.")

    return findings


def analyze_attachments(message):
    """Find email attachments and identify risky file types."""
    attachments = []

    for part in message.iter_attachments():
        filename = part.get_filename()

        if filename:
            extension = Path(filename).suffix.lower()

            attachments.append({
                "filename": filename,
                "extension": extension,
                "risky": extension in RISKY_EXTENSIONS
            })

    return attachments


def get_severity(score):
    """Convert the risk score into a severity level."""

    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def generate_html_report(report, output_path):
    """Generate an analyst-friendly HTML report."""

    def esc(value):
        return html.escape(str(value))

    indicator_rows = ""

    if report["detected_indicators"]:
        for indicator in report["detected_indicators"]:
            indicator_rows += f"""
            <li class="warning">{esc(indicator)}</li>
            """
    else:
        indicator_rows = "<li>No basic phishing indicators detected.</li>"

    url_rows = ""

    if report["urls"]:
        for url in report["urls"]:
            findings = []

            for item in report["suspicious_url_findings"]:
                if item["url"] == url:
                    findings.extend(item["findings"])

            if findings:
                finding_text = "<br>".join(
                    f"⚠ {esc(finding)}" for finding in findings
                )
            else:
                finding_text = "No suspicious characteristics detected."

            url_rows += f"""
            <tr>
                <td>{esc(url)}</td>
                <td>{finding_text}</td>
            </tr>
            """
    else:
        url_rows = """
        <tr>
            <td colspan="2">No URLs detected.</td>
        </tr>
        """

    attachment_rows = ""

    if report["attachments"]:
        for attachment in report["attachments"]:
            status = (
                "Potentially risky"
                if attachment["risky"]
                else "Not in risky extension list"
            )

            attachment_rows += f"""
            <tr>
                <td>{esc(attachment["filename"])}</td>
                <td>{esc(attachment["extension"])}</td>
                <td>{esc(status)}</td>
            </tr>
            """
    else:
        attachment_rows = """
        <tr>
            <td colspan="3">No attachments detected.</td>
        </tr>
        """

    score_rows = ""

    if report["score_breakdown"]:
        for reason in report["score_breakdown"]:
            score_rows += f"<li>{esc(reason)}</li>"
    else:
        score_rows = "<li>No score contributions.</li>"

    severity = report["severity"]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Phishing Email Analysis Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}}

.container {{
    max-width: 1000px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 10px;
}}

h1 {{
    margin-top: 0;
}}

h2 {{
    border-bottom: 1px solid #ddd;
    padding-bottom: 8px;
}}

.summary {{
    display: flex;
    gap: 20px;
    margin: 20px 0;
}}

.card {{
    flex: 1;
    padding: 20px;
    border: 1px solid #ddd;
    border-radius: 8px;
}}

.score {{
    font-size: 32px;
    font-weight: bold;
}}

.severity {{
    font-size: 24px;
    font-weight: bold;
}}

.warning {{
    margin-bottom: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #f0f2f4;
}}

code {{
    word-break: break-all;
}}
</style>
</head>

<body>

<div class="container">

<h1>Phishing Email Analyzer</h1>

<p><strong>File:</strong> {esc(report["file"])}</p>

<div class="summary">

<div class="card">
<div>Risk Score</div>
<div class="score">{report["risk_score"]}</div>
</div>

<div class="card">
<div>Severity</div>
<div class="severity">{esc(severity)}</div>
</div>

</div>

<h2>Email Details</h2>

<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Sender</td><td>{esc(report["sender"])}</td></tr>
<tr><td>Recipient</td><td>{esc(report["recipient"])}</td></tr>
<tr><td>Reply-To</td><td>{esc(report["reply_to"])}</td></tr>
<tr><td>Sender Domain</td><td>{esc(report["sender_domain"])}</td></tr>
<tr><td>Reply-To Domain</td><td>{esc(report["reply_to_domain"])}</td></tr>
<tr><td>Subject</td><td>{esc(report["subject"])}</td></tr>
<tr><td>Date</td><td>{esc(report["date"])}</td></tr>
<tr><td>Message-ID</td><td>{esc(report["message_id"])}</td></tr>
</table>

<h2>Detected Indicators</h2>

<ul>
{indicator_rows}
</ul>

<h2>Risk Score Breakdown</h2>

<ul>
{score_rows}
</ul>

<h2>URL Analysis</h2>

<table>
<tr>
<th>URL</th>
<th>Analysis</th>
</tr>
{url_rows}
</table>

<h2>Attachment Analysis</h2>

<table>
<tr>
<th>Filename</th>
<th>Extension</th>
<th>Status</th>
</tr>
{attachment_rows}
</table>

</div>

</body>
</html>
"""

    with output_path.open("w", encoding="utf-8") as report_file:
        report_file.write(html_content)


def analyze_email(file_path):
    """Analyze email and generate JSON and HTML reports."""

    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] File not found: {path}")
        return

    if path.suffix.lower() != ".eml":
        print("[ERROR] Please provide an .eml email file.")
        return

    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    from_address = message.get("From", "")
    to_address = message.get("To", "")
    reply_to = message.get("Reply-To", "")
    subject = message.get("Subject", "")
    date = message.get("Date", "")
    message_id = message.get("Message-ID", "")

    from_domain = get_domain(from_address)
    reply_domain = get_domain(reply_to)

    body = message.get_body(preferencelist=("plain", "html"))

    if body:
        body_text = body.get_content()
    else:
        body_text = ""

    email_text = f"{subject} {body_text}".lower()

    urls = extract_urls(body_text)
    attachments = analyze_attachments(message)

    risk_score = 0
    alerts = []
    score_reasons = []
    suspicious_url_findings = []

    # From / Reply-To mismatch
    if from_domain and reply_domain and from_domain != reply_domain:
        alerts.append("From and Reply-To domains do not match.")
        risk_score += 25
        score_reasons.append("From/Reply-To mismatch: +25")

    # Urgency language
    urgency_keywords = [
        "urgent",
        "immediately",
        "verify your account",
        "action required",
        "suspended",
        "account locked",
        "security alert",
    ]

    detected_keywords = []

    for keyword in urgency_keywords:
        if keyword in email_text:
            detected_keywords.append(keyword)

    if detected_keywords:
        alerts.append(
            "Urgency/threat language detected: "
            + ", ".join(detected_keywords)
        )

        risk_score += 15
        score_reasons.append("Urgency/threat language: +15")

    # URLs
    if urls:
        alerts.append(f"{len(urls)} URL(s) detected in email body.")
        risk_score += 10
        score_reasons.append("URL detected: +10")

    # Suspicious URL characteristics
    for url in urls:

        findings = analyze_url(url)

        if findings:

            suspicious_url_findings.append({
                "url": url,
                "findings": findings
            })

            for finding in findings:
                alerts.append(f"{finding} ({url})")
                risk_score += 20
                score_reasons.append(
                    "Suspicious URL characteristic: +20"
                )

    # Attachments
    for attachment in attachments:

        if attachment["risky"]:

            filename = attachment["filename"]

            alerts.append(
                f"Potentially risky attachment type: {filename}"
            )

            risk_score += 30

            score_reasons.append(
                f"Risky attachment ({filename}): +30"
            )

    severity = get_severity(risk_score)

    report = {
        "file": path.name,
        "sender": from_address,
        "recipient": to_address,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "sender_domain": from_domain,
        "reply_to_domain": reply_domain,
        "urls": urls,
        "suspicious_url_findings": suspicious_url_findings,
        "attachments": attachments,
        "detected_indicators": alerts,
        "score_breakdown": score_reasons,
        "risk_score": risk_score,
        "severity": severity
    }

    # Terminal output
    print("\n" + "=" * 60)
    print("        PHISHING EMAIL ANALYZER - V10")
    print("=" * 60)

    print(f"From     : {from_address or 'Not found'}")
    print(f"To       : {to_address or 'Not found'}")
    print(f"Reply-To : {reply_to or 'Not found'}")
    print(f"Subject  : {subject or 'Not found'}")
    print(f"Date     : {date or 'Not found'}")
    print(f"Message-ID: {message_id or 'Not found'}")

    print("\n" + "-" * 60)
    print("RISK ASSESSMENT")
    print("-" * 60)

    print(f"Risk Score : {risk_score}")
    print(f"Severity   : {severity}")

    print("\nScore breakdown:")

    if score_reasons:
        for reason in score_reasons:
            print(f"  - {reason}")
    else:
        print("  No risk indicators contributed to the score.")

    print("\n" + "-" * 60)
    print("Detected indicators:")

    if alerts:
        for alert in alerts:
            print(f"[WARNING] {alert}")
    else:
        print("[OK] No basic phishing indicators detected.")

    reports_directory = Path("reports")
    reports_directory.mkdir(exist_ok=True)

    json_path = reports_directory / f"{path.stem}_report.json"
    html_path = reports_directory / f"{path.stem}_report.html"

    with json_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

    generate_html_report(report, html_path)

    print("\n" + "-" * 60)
    print(f"JSON report : {json_path}")
    print(f"HTML report : {html_path}")
    print("=" * 60)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python src\\analyzer.py <email.eml>")
        sys.exit(1)

    analyze_email(sys.argv[1])