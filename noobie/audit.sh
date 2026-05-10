#!/bin/bash
# =============================================
#   System Audit Tool - Main Script
#   With Groq AI Recommendations
# =============================================

REPORT="audit_report_$(date +%Y%m%d_%H%M%S).txt"

# ── Put your Groq API key here ────────────────
GROQ_API_KEY="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"

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ── Print a section header ────────────────────
section() {
    echo ""
    echo "============================="
    echo "  $1"
    echo "============================="
}

# ── Print a result line ───────────────────────
ok()       { echo -e "  ${GREEN}[OK]${RESET}       $1"; }
warn()     { echo -e "  ${YELLOW}[WARNING]${RESET}  $1"; }
critical() { echo -e "  ${RED}[CRITICAL]${RESET} $1"; }
info()     { echo    "  [INFO]     $1"; }

# ── Save to report file ───────────────────────
log() { echo "$1" >> "$REPORT"; }

# ─────────────────────────────────────────────
#   ASK GROQ FOR A RECOMMENDATION
#   Usage: ask_groq "Port 23 is open on this Linux server"
# ─────────────────────────────────────────────
ask_groq() {
    local ISSUE="$1"

    # Check that jq and curl are available
    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        echo -e "  ${CYAN}[AI]${RESET}       Install curl and jq to get AI recommendations"
        return
    fi

    echo -e "  ${CYAN}[AI]${RESET}       Asking Groq for advice..."

    # Send the issue to Groq and get a recommendation back
    RESPONSE=$(curl -s https://api.groq.com/openai/v1/chat/completions \
        -H "Authorization: Bearer $GROQ_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"llama-3.3-70b-versatile\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"You are a Linux security expert. Give a short 2-line fix for this issue on Red Hat Linux: $ISSUE. Be direct and include the exact command to fix it.\"
            }],
            \"max_tokens\": 100
        }" 2>/dev/null)

    # Pull the text out of the JSON response
    ADVICE=$(echo "$RESPONSE" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [ -z "$ADVICE" ] || [ "$ADVICE" = "null" ]; then
        echo -e "  ${CYAN}[AI]${RESET}       Could not get a response — check your API key"
    else
        echo -e "  ${CYAN}[AI]${RESET}       $ADVICE"
        log "[AI ADVICE] $ISSUE → $ADVICE"
    fi
}

# ─────────────────────────────────────────────
#   MODULE 1: Check Open Ports
# ─────────────────────────────────────────────
check_ports() {
    section "MODULE 1: Open Ports"

    DANGEROUS_PORTS="21 23 445 3389 5900"

    for PORT in $DANGEROUS_PORTS; do
        if ss -tuln 2>/dev/null | grep -q ":$PORT "; then
            critical "Port $PORT is open — this is a security risk!"
            log "[CRITICAL] Port $PORT open"
            ask_groq "Port $PORT is open on this Red Hat Linux server"
        fi
    done

    # Check firewall (Red Hat uses firewalld)
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        ok "Firewall (firewalld) is active"
    elif systemctl is-active --quiet iptables 2>/dev/null; then
        ok "Firewall (iptables) is active"
    else
        warn "No firewall detected"
        log "[WARNING] No firewall"
        ask_groq "No firewall is running on this Red Hat Linux server"
    fi
}

# ─────────────────────────────────────────────
#   MODULE 2: Check File Permissions
# ─────────────────────────────────────────────
check_permissions() {
    section "MODULE 2: File Permissions"

    # Check /etc/shadow permissions
    SHADOW_PERM=$(stat -c "%a" /etc/shadow 2>/dev/null)
    if [ "$SHADOW_PERM" = "640" ]; then
        ok "/etc/shadow has correct permissions ($SHADOW_PERM)"
    else
        critical "/etc/shadow permissions are $SHADOW_PERM — should be 640"
        log "[CRITICAL] /etc/shadow perm: $SHADOW_PERM"
        ask_groq "/etc/shadow has wrong permissions ($SHADOW_PERM) on Red Hat Linux"
    fi

    # Find world-writable files
    info "Searching for world-writable files (this may take a moment)..."
    WW_FILES=$(find /etc /usr/bin /usr/sbin -type f -perm -o+w 2>/dev/null)

    if [ -z "$WW_FILES" ]; then
        ok "No world-writable files found in sensitive directories"
    else
        critical "World-writable files found:"
        echo "$WW_FILES" | while read -r FILE; do
            echo "    → $FILE"
            log "[CRITICAL] World-writable: $FILE"
        done
        ask_groq "World-writable files exist in /etc or /usr/bin on Red Hat Linux"
    fi

    # Check for SUID binaries
    info "Checking for unexpected SUID binaries..."
    SUID=$(find /usr/bin /usr/sbin -perm -4000 2>/dev/null)
    if [ -n "$SUID" ]; then
        warn "SUID binaries found (verify each is legitimate):"
        echo "$SUID" | while read -r FILE; do
            echo "    → $FILE"
        done
        ask_groq "Unexpected SUID binaries found in /usr/bin on Red Hat Linux"
    fi
}

# ─────────────────────────────────────────────
#   MODULE 3: Check Users
# ─────────────────────────────────────────────
check_users() {
    section "MODULE 3: User Accounts"

    # Check for unauthorized UID 0 accounts
    UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [ -z "$UID0" ]; then
        ok "Only root has UID 0 (no unauthorized superusers)"
    else
        critical "These accounts have root-level UID 0: $UID0"
        log "[CRITICAL] Unauthorized UID 0: $UID0"
        ask_groq "User account '$UID0' has UID 0 (root access) on Red Hat Linux"
    fi

    # Check for accounts with no password
    EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!!") {print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$EMPTY_PW" ]; then
        ok "All accounts have passwords"
    else
        critical "Accounts with NO password: $EMPTY_PW"
        log "[CRITICAL] No password: $EMPTY_PW"
        ask_groq "User account '$EMPTY_PW' has no password set on Red Hat Linux"
    fi

    # List human users
    info "Human user accounts on this system:"
    awk -F: '$3 >= 1000 && $3 != 65534 {print "    → "$1" (UID="$3")"}' /etc/passwd

    # Show sudo/wheel group users (Red Hat uses wheel, not sudo)
    info "Users with sudo access (wheel group):"
    getent group wheel 2>/dev/null | awk -F: '{print "    → "$4}' | tr ',' '\n'
}

# ─────────────────────────────────────────────
#   MODULE 4: Check Software Updates
# ─────────────────────────────────────────────
check_software() {
    section "MODULE 4: Software Updates"

    # Pick package manager — dnf (RHEL 8+) or yum (RHEL 7)
    if command -v dnf &>/dev/null; then
        PKG="dnf"
    elif command -v yum &>/dev/null; then
        PKG="yum"
    else
        info "No supported package manager found — skipping"
        return
    fi

    info "Checking for available updates (using $PKG)..."

    UPDATE_COUNT=$($PKG check-update -q 2>/dev/null | grep -v "^$" | wc -l)
    SECURITY_COUNT=$($PKG updateinfo list security 2>/dev/null | grep -i "RHSA" | wc -l)

    if [ "$SECURITY_COUNT" -gt 0 ]; then
        critical "$SECURITY_COUNT security update(s) need to be installed!"
        log "[CRITICAL] $SECURITY_COUNT security updates pending"
        ask_groq "$SECURITY_COUNT security updates are pending on Red Hat Linux"
    elif [ "$UPDATE_COUNT" -gt 0 ]; then
        warn "$UPDATE_COUNT package update(s) available"
        info "Run: sudo $PKG update -y"
    else
        ok "All packages are up to date"
    fi

    # Check automatic updates (dnf-automatic)
    if systemctl is-active --quiet dnf-automatic 2>/dev/null; then
        ok "Automatic updates (dnf-automatic) are enabled"
    else
        warn "Automatic updates are not enabled"
        ask_groq "Automatic updates (dnf-automatic) are disabled on Red Hat Linux"
    fi
}

# ─────────────────────────────────────────────
#   SUMMARY
# ─────────────────────────────────────────────
print_summary() {
    section "AUDIT COMPLETE"
    echo ""
    echo "  Report saved to: $REPORT"
    echo ""
}

# ─────────────────────────────────────────────
#   RUN EVERYTHING
# ─────────────────────────────────────────────
echo "=============================="
echo "  System Audit Tool"
echo "  $(date)"
echo "  Host: $(hostname)"
echo "=============================="

check_ports
check_permissions
check_users
check_software
print_summary
