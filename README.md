# Linux Automated System Audit Tool

Welcome to the Linux Automated System Audit Tool project! This repository contains powerful scripts designed to perform comprehensive security audits on Linux systems. 

## 🛡️ Project Summary

These tools are built to help System Administrators and Cybersecurity professionals quickly identify common misconfigurations and vulnerabilities on a Linux server. The audit scripts scan various components of the operating system and generate an actionable remediation report. 

By utilizing different auditing methods (scripts like `test1.sh` and `sh3.sh`), you can adapt the scan to fit your specific environment, whether you need a quick overview or an in-depth analysis across multiple package managers.

The core areas audited include:
- **Network Security:** Detects open TCP/UDP ports, listening services, and identifies potentially exposed legacy protocols.
- **File System Permissions:** Scans for world-writable files, SUID/SGID binaries, and verifies the permissions of critical system files (like `/etc/passwd` and `/etc/ssh/sshd_config`).
- **Identity & Access Management:** Checks for unauthorized UID 0 accounts, empty passwords, inactive accounts, and evaluates SSH hardening configurations.
- **Patch Management:** Integrates with native package managers (`apt`, `dnf`, `yum`, `pacman`, `zypper`) to identify pending security patches and outdated software.

## ✨ Features

- **Automated Scanning:** Run a full system check with a single command.
- **Clear Reporting:** Generates beautifully formatted terminal output with visual indicators.
- **Markdown Reports:** Automatically creates clean `.md` reports of the findings for easy sharing, documentation, and GitHub display.
- **Actionable Remediation:** Not only identifies problems but provides specific commands to fix them.

## 🚀 Getting Started

To run the audit scripts on your system, follow these steps:

1. **Clone the repository** (or copy the scripts to your target server).
2. **Make the script executable:**
   ```bash
   chmod +x file.sh
   ```
   *(Replace `file.sh` with the specific script you want to run, such as `sh3.sh` or `test1.sh`)*

3. **Execute the script as root:**
   ```bash
   sudo ./file.sh
   ```

> **⚠️ Note:** Root privileges are required to accurately inspect system-level configurations, protected files, and listening network sockets.

## 📄 Audit Results

After the script finishes execution, you will see a detailed summary in your terminal. Additionally, a comprehensive Markdown report (`audit_report.md` or similar, depending on the script run) will be generated in your directory. You can view this file directly on GitHub or in any Markdown viewer!

---
*Created for the Linux and Shell Programming Project.*
