# Trivy Security Dashboard

A lightweight web dashboard for container security scanning using Trivy. Provides fleet-wide visibility of vulnerabilities and exposed secrets across multiple container images.

## What It Does

Scans container images from any registry and displays:
- **Vulnerability Analysis**: CVE counts by severity (Critical/High/Medium/Low)
- **Secret Detection**: Exposed API keys, passwords, private keys, certificates
- **Fleet Overview**: Side-by-side comparison of up to 20 containers
- **Risk Prioritization**: Sort by severity to focus on critical issues first

## Key Features

- **Registry-native scanning** - No need to pull/run containers locally
- **Dark theme interface** - Professional, easy-on-the-eyes design
- **Sortable results** - Click columns to sort by vulnerabilities or secrets
- **SQLite backend** - Lightweight, no external database required
- **One-command setup** - Automated deployment on Rocky Linux 9
- **No authentication** - Perfect for internal security teams

Built for security professionals who need quick visibility into container security posture across development and production environments.

## Quick Deploy (Rocky Linux 9 Minimal ISO)

```bash
curl -sSL https://raw.githubusercontent.com/skiptosecure/security-toolkits/main/Trivy-Scanner/setup/setup.sh | bash
cd ~/trivy-security-dashboard
source venv/bin/activate
python app.py
