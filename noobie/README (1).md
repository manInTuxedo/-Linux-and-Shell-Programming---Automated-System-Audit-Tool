# 🛡️ RHEL Automated System Audit Tool

A bash-based security audit tool for Red Hat Linux that scans your system for vulnerabilities and uses **Groq AI** to give you smart recommendations for every issue it finds.

---

## 📁 Files

| File | Purpose |
|------|---------|
| `audit.sh` | Main script — runs the full audit |
| `setup_cron.sh` | Optional — schedule audits to run automatically |

---

## ⚙️ Requirements

| Tool | Why it's needed |
|------|----------------|
| `bash` | To run the script |
| `curl` | To call the Groq AI API |
| `jq` | To read the AI response (JSON parser) |
| `sudo / root` | Some checks require root access |

### Install jq (if not installed)
```bash
sudo curl -L -o /usr/local/bin/jq https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64
sudo chmod +x /usr/local/bin/jq
jq --version
```

---

## 🚀 How to Run

**Step 1 — Add your Groq API key**
Open `audit.sh` and replace the placeholder on line 10:
```bash
GROQ_API_KEY="your_groq_api_key_here"
```
Get a free key at: https://console.groq.com → API Keys

**Step 2 — Make the script executable**
```bash
chmod +x audit.sh
```

**Step 3 — Run the audit**
```bash
sudo bash audit.sh
```

**Step 4 — View the report**
```bash
cat audit_report_YYYYMMDD_HHMMSS.md
```

---

## 🔄 Schedule Automatic Audits (Optional)

```bash
chmod +x setup_cron.sh
sudo bash setup_cron.sh
```

Then pick a schedule from the menu:
- Every day at midnight
- Every week
- Every month

---

## 🔍 How It Works — Step by Step

When you run `sudo bash audit.sh`, the script does the following:

```
START
  │
  ├─ check_root()         → Make sure script is run as root
  │
  ├─ MODULE 1             → Check SELinux + Firewall
  ├─ MODULE 2             → Check SSH configuration
  ├─ MODULE 3             → Scan open ports
  ├─ MODULE 4             → Check user accounts
  ├─ MODULE 5             → Check file permissions
  ├─ MODULE 6             → Check software updates
  │
  └─ Save report as .md file
```

Every time an issue is found, the script also calls **Groq AI** to get a specific fix recommendation.

---

## 📋 Modules Explained

### Module 1 — Core System Protections
Checks the two most important Red Hat security features:

- **SELinux** — Red Hat's built-in security system. Should always be `Enforcing`.
  If it's `Permissive` or `Disabled`, attackers can bypass system protections.
- **Firewalld** — The firewall that controls which network connections are allowed.
  If it's off, your server is exposed to the network.

```
[✔] SELinux is Enforcing.
[✖] Firewalld is NOT active.
    -> Fix: systemctl enable --now firewalld
    [AI] Enable firewalld immediately to block unauthorized access...
```

---

### Module 2 — SSH Security
SSH is the main way admins connect to servers — if it's misconfigured, attackers can get in.

- **PermitRootLogin** — If set to `yes`, anyone who cracks the root password owns your server.
  Should always be `no`.
- **PasswordAuthentication** — Passwords can be brute-forced. SSH keys are much safer.
  Should be `no` (use key-based login instead).

```
[✖] SSH root login is permitted.
    -> Fix: Set PermitRootLogin no in /etc/ssh/sshd_config
    [AI] Disable root SSH login immediately. Edit sshd_config...
```

---

### Module 3 — Open Ports
Lists every service listening for network connections, then flags dangerous ones.

**How it works:**
```bash
ss -tulpn   # lists all open ports and which program opened them
```

It then checks for known dangerous ports:

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Sends passwords in plain text |
| 23 | Telnet | Fully unencrypted remote access |
| 445 | SMB | Target of ransomware (EternalBlue) |
| 3389 | RDP | Brute-force target |
| 5900 | VNC | Often unencrypted remote desktop |

```
Protocol   Address:Port         Process
tcp        0.0.0.0:22           sshd
tcp        0.0.0.0:23           telnetd   ← dangerous!

[✖] Dangerous port 23 is open!
    -> Fix: firewall-cmd --remove-port=23/tcp --permanent
```

---

### Module 4 — User & Access Control
Checks for account security issues:

- **UID 0 accounts** — UID 0 means root-level access. Only `root` should have it.
  Any other account with UID 0 is a serious red flag.
- **Empty passwords** — Accounts with no password can be logged into without any credentials.
- **Password expiry** — Passwords should expire every 90 days to force regular changes.
  Checked using the `chage` command.
- **Interactive shells** — Service accounts (like `apache`, `mysql`) should not have
  a login shell. If they do, they can be used to log into the system.

```
[✔] Only root has UID 0.
[✖] Account with no password: testuser
    -> Fix: passwd testuser  OR  passwd -l testuser
[!] Users with no password expiry: john
    -> Fix: chage -M 90 john
```

---

### Module 5 — File Permissions
Checks that sensitive files are not accessible by the wrong people.

- **World-writable files** — Files with `o+w` permission can be modified by ANY user
  on the system. This is dangerous in `/etc`, `/usr/bin`, etc.
- **SUID/SGID binaries** — Files with the SUID bit run as root even when a normal
  user executes them. Unexpected SUID files can be used for privilege escalation.
- **Critical file permissions** — Three files are especially sensitive:

| File | Should be | Why |
|------|-----------|-----|
| `/etc/shadow` | `640` | Contains hashed passwords |
| `/etc/passwd` | `644` | Contains user account info |
| `/etc/sudoers` | `440` | Controls who can use sudo |

```
[✖] /etc/shadow has wrong permissions (666, expected 640).
    -> Fix: chmod 640 /etc/shadow
    [AI] Fix /etc/shadow permissions immediately...
```

---

### Module 6 — Software Updates
Checks if your system has pending security patches using `dnf`:

```bash
dnf check-update --security   # lists pending security patches
```

- If `dnf` returns **exit code 100**, it means updates are available.
- It also checks if `dnf-automatic` is running — this is Red Hat's tool
  for applying security patches automatically without manual intervention.

```
[!] 5 security update(s) are pending.
    -> Fix: dnf update --security -y
    [AI] Apply security patches immediately to close known vulnerabilities...
[!] Automatic updates are not enabled.
    -> Fix: systemctl enable --now dnf-automatic
```

---

## 🤖 How Groq AI Works

Every time the script finds an issue it calls the `ask_groq()` function:

```bash
ask_groq "SELinux is set to Permissive on Red Hat Linux"
```

This sends the issue to the **Groq API** (which runs the LLaMA 3.3 model) and asks for a 2-line fix with the exact command. The response is printed under the finding and saved to the report.

```
[AI] Set SELinux to Enforcing immediately to enforce mandatory access controls.
     Run: setenforce 1 and set SELINUX=enforcing in /etc/selinux/config
```

---

## 📄 Report Output

The report is saved as a Markdown file:
```
audit_report_20260510_143022.md
```

It includes:
- Date, hostname
- All findings with ✅ ❌ ⚠️ ℹ️ icons
- Fix commands for every issue
- AI recommendations
- Collapsible lists for long outputs (world-writable files, SUID binaries, pending updates)

To read it:
```bash
cat audit_report_*.md
```

---

## 🎓 Grading Criteria Coverage

| Criteria | How it's covered |
|----------|-----------------|
| Scanning open ports & weak permissions | Modules 3 and 5 |
| Detecting outdated software & users | Modules 4 and 6 |
| Report generation with findings | Saved as `.md` file with icons |
| Recommendations in output | Every issue has a `-> Fix:` line + AI advice |
| Shell scripting accuracy | Modular functions, error handling, exit codes |
| Q&A | See explanations above for each module |
| Enhancement (cron automation) | `setup_cron.sh` schedules recurring audits |
