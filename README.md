# Phishing Email Analyzer

A Python-based cybersecurity tool that analyzes `.eml` email files and identifies common phishing indicators using header analysis, text analysis, URL heuristics, attachment analysis, and a transparent risk-scoring model.

## Project Overview

Phishing emails often use techniques such as:

- Sender and Reply-To mismatches
- Urgency or threat-based language
- Suspicious URLs
- IP-address-based URLs
- Potentially risky attachment types

This project automates the initial analysis of an email and generates both machine-readable and analyst-friendly reports.

## Features

### Email Header Analysis

Extracts:

- From
- To
- Reply-To
- Subject
- Date
- Message-ID
- Sender domain
- Reply-To domain

### Phishing Indicator Detection

Detects:

- From/Reply-To domain mismatch
- Urgency and threat-related keywords
- URLs in the email body
- Suspicious URL characteristics
- Email attachments
- Potentially risky attachment extensions

### URL Analysis

The analyzer checks for characteristics such as:

- IP address used instead of a domain
- `@` symbol in the URL
- Unusually long URLs
- Non-standard URL schemes

These are heuristic indicators and do not by themselves prove that a URL is malicious.

### Attachment Analysis

The tool identifies attachments and checks their extensions against a configurable list of potentially risky file types.

Examples include:

```text
.exe
.scr
.bat
.cmd
.js
.vbs
.ps1
.msi