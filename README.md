# Email Authentication Demonstration System

A cybersecurity-focused web application for demonstrating email authentication concepts using SPF, DKIM, and DMARC.

The system provides a controlled interface for analyzing sample email headers, extracting authentication-related fields, retrieving DNS-based records, and presenting structured authentication results. It is intended for learning, demonstration, and research support around email spoofing, phishing prevention, and domain impersonation risks.

---

## Overview

Email remains one of the most common attack vectors used in phishing, spoofing, and business email compromise attacks. Traditional email protocols were not originally designed with strong sender authentication, which makes it possible for attackers to forge sender identities.

This project demonstrates how modern email authentication mechanisms help improve trust in email communication:

- **SPF** validates whether a sending mail server is authorized to send email for a domain.
- **DKIM** supports message integrity and sender authenticity using digital signatures.
- **DMARC** combines SPF and DKIM results with domain alignment and policy enforcement.

---

## Features

- Web-based email authentication demonstration interface
- Raw email header input
- Email header parsing
- Extraction of key fields such as:
  - `Return-Path`
  - `From`
  - `Received`
  - `DKIM-Signature`
  - `Subject`
- SPF record lookup and evaluation
- DKIM signature-related analysis
- DMARC alignment and policy analysis
- Structured result display
- Educational demonstration of authentication decisions
- GitHub-based version control
- Cloud deployment support using Render

---

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python |
| Web Framework | Flask |
| Frontend | HTML, CSS |
| DNS Lookup | Python DNS-related libraries |
| Version Control | Git and GitHub |
| Deployment | Render |

---

## Project Structure

```text
email-auth-demo/
│
├── app.py
├── engine.py
├── parser.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
└── .gitignore
