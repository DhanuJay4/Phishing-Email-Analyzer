# Phishing Email Analyzer

A Python-based cybersecurity tool that analyzes `.eml` email files for common phishing indicators and generates structured risk-assessment reports.

The project is designed as a defensive security analysis tool for learning, SOC-style investigation, and controlled phishing-email detection.

---

## Features

- 📧 Email header analysis
- 🔍 From / Reply-To domain mismatch detection
- ⚠️ Urgency and threat-language detection
- 🔗 URL extraction from email content
- 🌐 Suspicious URL characteristic detection
- 📎 Email attachment analysis
- 🚨 Risky attachment extension detection
- 📊 Heuristic phishing risk scoring
- 📝 JSON report generation
- 🌐 HTML report generation
- 💻 Command-line interface
- 🧪 Automated unit tests

---

## How It Works

The analyzer processes a `.eml` email file and examines several characteristics.

### 1. Header Analysis

The tool extracts:

- Sender
- Recipient
- Reply-To
- Subject
- Date
- Message-ID
- Sender domain
- Reply-To domain

It checks whether the sender and Reply-To domains are different.

### 2. Urgency / Threat Detection

The analyzer checks the subject and email body for predefined urgency or threat-related phrases such as:

- `urgent`
- `immediately`
- `verify your account`
- `action required`
- `suspended`
- `account locked`
- `security alert`

### 3. URL Analysis

URLs are extracted from the email body.

The analyzer checks for suspicious characteristics such as:

- IP addresses used instead of domain names
- `@` characters
- unusually long URLs
- non-standard URL schemes

Detecting a URL does **not** automatically mean that the URL is malicious.

### 4. Attachment Analysis

Email attachments are identified and analyzed.

The current risky-extension list includes:

```text
.exe
.scr
.bat
.cmd
.js
.vbs
.ps1
.msi
.hta
.jar
.com