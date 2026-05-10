#!/bin/bash
# ==============================================================================
#   RHEL Automated System Audit Tool
#   Scans: system status, SSH, open ports, users, permissions, updates
#   Enhancement: Groq AI recommendations for every issue found
# ==============================================================================

REPORT="audit_report_$(date +%Y%m%d_%H%M%S).md"
GROQ_API_KEY="your_groq_api_key_here"

# ── Colors ────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Icons ─────────────────────────────────────
PASS="[${GREEN}✔${NC}]"
FAIL="[${RED}✖${NC}]"
WARN="[${YELLOW}!${NC}]"
INFO="[${CYAN}i${NC}]"

# ── Initialize report file ────────────────────
cat <<EOF > "$REPORT"
# RHEL System Audit Report
**Date:** $(date)
**Hostname:** $(hostname)

---
EOF

# ─────────────────────────────────────────────
#   HELPER: Write section header
# ─────────────────────────────────────────────
write_header() {
    echo -e "\n${CYAN}=== $1 ===${NC}"
    echo -e "\n## $1\n" >> "$REPORT"
}

# ─────────────────────────────────────────────
#   HELPER: Log a finding to terminal + report
# ─────────────────────────────────────────────
log_finding() {
    local status="$1"
    local term_msg="$2"
    local report_msg="$3"
    local remediation="$4"

    # Print to terminal
    echo -e "${status} ${term_msg}"
    [[ -n "$remediation" ]] && echo -e "    ${CYAN}-> Fix:${NC} ${remediation}"

    # Pick markdown icon
    local md_icon=""
    case "$status" in
        "$PASS") md_icon="✅" ;;
        "$FAIL") md_icon="❌" ;;
        "$WARN") md_icon="⚠️" ;;
        "$INFO") md_icon="ℹ️" ;;
    esac

    # Write to report
    if [[ -n "$report_msg" ]]; then
        echo "- **${md_icon}** ${report_msg}" >> "$REPORT"
        [[ -n "$remediation" ]] && echo "  - *Fix:* \`${remediation}\`" >> "$REPORT"
    fi
}

# ─────────────────────────────────────────────
#   HELPER: Ask Groq AI for advice on an issue
# ─────────────────────────────────────────────
ask_groq() {
    local issue="$1"

    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        return
    fi

    echo -e "    ${CYAN}[AI]${NC} Asking Groq..."

    local response
    response=$(curl -s https://api.groq.com/openai/v1/chat/completions \
        -H "Authorization: Bearer $GROQ_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"llama-3.3-70b-versatile\",
            \"messages\": [{
                \"role\": \"user\",
                \"content\": \"You are a Red Hat Linux security expert. Give a short 2-line fix for this issue: $issue. Include the exact command.\"
            }],
            \"max_tokens\": 100
        }" 2>/dev/null)

    local advice
    advice=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [[ -n "$advice" && "$advice" != "null" ]]; then
        echo -e "    ${CYAN}[AI]${NC} $advice"
        echo "  - *AI Advice:* $advice" >> "$REPORT"
    fi
}

# ─────────────────────────────────────────────
#   CHECK: Must run as root
# ─────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${FAIL} ${RED}This script must be run as root. Use: sudo bash $0${NC}"
        exit 1
    fi
}

# ─────────────────────────────────────────────
#   MODULE 1: Core System Protections
# ─────────────────────────────────────────────
scan_system_status() {
    write_header "MODULE 1: Core System Protections"

    # SELinux (important on Red Hat)
    if command -v getenforce &>/dev/null; then
        local selinux=$(getenforce)
        if [[ "$selinux" == "Enforcing" ]]; then
            log_finding "$PASS" "SELinux is Enforcing." "SELinux is active and enforcing." ""
        else
            log_finding "$FAIL" "SELinux is NOT enforcing (Current: $selinux)." "SELinux is set to $selinux." "setenforce 1 and set SELINUX=enforcing in /etc/selinux/config"
            ask_groq "SELinux is set to $selinux on Red Hat Linux"
        fi
    else
        log_finding "$WARN" "SELinux tools not found." "getenforce not found." "sudo dnf install selinux-policy"
    fi

    # Firewall
    if systemctl is-active --quiet firewalld; then
        log_finding "$PASS" "Firewalld is active." "Firewalld is running." ""
    else
        log_finding "$WARN" "Firewalld is NOT active." "Firewalld is not running." "systemctl enable --now firewalld"
        ask_groq "Firewalld is disabled on Red Hat Linux"
    fi
}

# ─────────────────────────────────────────────
#   MODULE 2: SSH Security
# ─────────────────────────────────────────────
scan_ssh_config() {
    write_header "MODULE 2: SSH Security"

    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_finding "$INFO" "SSH config not found at $sshd_config." "SSH config not found." ""
        return
    fi

    # Root login check
    if grep -qE "^PermitRootLogin\s+yes" "$sshd_config"; then
        log_finding "$FAIL" "SSH root login is permitted." "PermitRootLogin is set to yes." "Set PermitRootLogin no in $sshd_config then restart sshd"
        ask_groq "SSH root login is enabled on Red Hat Linux"
    else
        log_finding "$PASS" "SSH root login is disabled." "PermitRootLogin is restricted." ""
    fi

    # Password authentication check
    if grep -qE "^PasswordAuthentication\s+yes" "$sshd_config"; then
        log_finding "$WARN" "SSH password authentication is enabled." "PasswordAuthentication is yes." "Set PasswordAuthentication no and use SSH keys instead"
        ask_groq "SSH password authentication is enabled on Red Hat Linux"
    else
        log_finding "$PASS" "SSH password authentication is disabled." "PasswordAuthentication is disabled." ""
    fi
}

# ─────────────────────────────────────────────
#   MODULE 3: Open Ports
# ─────────────────────────────────────────────
scan_open_ports() {
    write_header "MODULE 3: Open Ports"

    local raw_ports
    raw_ports=$(ss -tulpn | tail -n +2)

    if [[ -z "$raw_ports" ]]; then
        log_finding "$PASS" "No listening ports found." "No listening ports found." ""
        return
    fi

    log_finding "$INFO" "Listening ports detected (see report for full list)." "" ""

    # Table in report
    echo "| Protocol | Address:Port | Process |" >> "$REPORT"
    echo "|---|---|---|" >> "$REPORT"

    # Table in terminal
    printf "${CYAN}%-10s %-30s %-20s${NC}\n" "Protocol" "Address:Port" "Process"
    echo "-------------------------------------------------------------"

    echo "$raw_ports" | while read -r line; do
        local proto=$(echo "$line" | awk '{print $1}')
        local addr=$(echo "$line" | awk '{print $5}')
        local process=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
        [[ -z "$process" ]] && process="unknown"

        printf "%-10s %-30s %-20s\n" "$proto" "$addr" "$process"
        echo "| $proto | \`$addr\` | $process |" >> "$REPORT"
    done

    echo ""
    echo -e "    ${CYAN}-> Fix:${NC} Disable unused services: systemctl disable <service>"
    echo "  - *Fix:* Disable unused services or block ports via firewall-cmd" >> "$REPORT"

    # Flag known dangerous ports
    local dangerous="21 23 445 3389 5900"
    for port in $dangerous; do
        if echo "$raw_ports" | grep -q ":$port "; then
            log_finding "$FAIL" "Dangerous port $port is open!" "Port $port is open." "firewall-cmd --remove-port=$port/tcp --permanent && firewall-cmd --reload"
            ask_groq "Port $port is open on Red Hat Linux"
        fi
    done
}

# ─────────────────────────────────────────────
#   MODULE 4: User & Access Control
# ─────────────────────────────────────────────
scan_users() {
    write_header "MODULE 4: User & Access Control"

    # UID 0 accounts other than root
    local uid0
    uid0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [[ -n "$uid0" ]]; then
        for user in $uid0; do
            log_finding "$FAIL" "Unauthorized UID 0 account: $user" "Unauthorized UID 0 account: \`$user\`." "userdel $user  OR  usermod -u <new_uid> $user"
            ask_groq "User $user has UID 0 (root privileges) on Red Hat Linux"
        done
    else
        log_finding "$PASS" "Only root has UID 0." "No unauthorized UID 0 accounts." ""
    fi

    # Empty passwords
    local empty_pw
    empty_pw=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pw" ]]; then
        for user in $empty_pw; do
            log_finding "$FAIL" "Account with no password: $user" "Account with empty password: \`$user\`." "passwd $user  OR  passwd -l $user to lock it"
            ask_groq "User $user has no password on Red Hat Linux"
        done
    else
        log_finding "$PASS" "All accounts have passwords set." "No empty password accounts found." ""
    fi

    # Password aging (are passwords set to expire?)
    local no_expiry
    no_expiry=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd | while read -r user; do
        max=$(chage -l "$user" 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ')
        [[ "$max" == "99999" || -z "$max" ]] && echo "$user"
    done)

    if [[ -n "$no_expiry" ]]; then
        log_finding "$WARN" "Users with no password expiry: $no_expiry" "Users with no password expiry: \`$no_expiry\`." "chage -M 90 <username>"
        ask_groq "User accounts have no password expiry set on Red Hat Linux"
    else
        log_finding "$PASS" "All user passwords have expiry set." "All passwords have expiry configured." ""
    fi

    # Users with interactive shells
    local interactive
    interactive=$(grep -Ev 'nologin|false|sync|halt|shutdown' /etc/passwd | awk -F: '{print $1}' | tr '\n' ' ')
    [[ -n "$interactive" ]] && log_finding "$INFO" "Users with login shells: $interactive" "Users with login shells: \`$interactive\`." "usermod -s /sbin/nologin <user> for service accounts"
}

# ─────────────────────────────────────────────
#   MODULE 5: File Permissions
# ─────────────────────────────────────────────
scan_permissions() {
    write_header "MODULE 5: File Permissions"

    echo -e "${INFO} Scanning for weak permissions (may take a moment)..."

    local exclude="-type d \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp \) -prune -o"

    # World-writable files
    local ww_files
    ww_files=$(find / $exclude -type f -perm -0002 -print 2>/dev/null)

    if [[ -n "$ww_files" ]]; then
        local count=$(echo "$ww_files" | wc -l)
        log_finding "$FAIL" "Found $count world-writable file(s)." "Found $count world-writable files." "chmod o-w <file> for each listed file"
        ask_groq "There are $count world-writable files on Red Hat Linux"

        # Collapsible list in report
        echo "<details><summary>View world-writable files</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$ww_files" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"
    else
        log_finding "$PASS" "No world-writable files found." "No world-writable files found." ""
    fi

    # SUID/SGID binaries
    local suid
    suid=$(find / $exclude -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)

    if [[ -n "$suid" ]]; then
        local count=$(echo "$suid" | wc -l)
        log_finding "$WARN" "Found $count SUID/SGID file(s) — verify each is legitimate." "Found $count SUID/SGID files." "chmod u-s,g-s <file> if SUID is not needed"
        ask_groq "There are $count SUID/SGID binaries found on Red Hat Linux"

        echo "<details><summary>View SUID/SGID files</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$suid" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"
    else
        log_finding "$PASS" "No unexpected SUID/SGID files found." "No SUID/SGID files found." ""
    fi

    # Critical file permissions
    declare -A critical_files=(
        ["/etc/shadow"]="640"
        ["/etc/passwd"]="644"
        ["/etc/sudoers"]="440"
    )

    for file in "${!critical_files[@]}"; do
        expected="${critical_files[$file]}"
        if [[ -f "$file" ]]; then
            actual=$(stat -c "%a" "$file" 2>/dev/null)
            if [[ "$actual" != "$expected" ]]; then
                log_finding "$FAIL" "$file has wrong permissions ($actual, expected $expected)." "$file permissions are $actual (expected $expected)." "chmod $expected $file"
                ask_groq "$file has permissions $actual instead of $expected on Red Hat Linux"
            else
                log_finding "$PASS" "$file permissions are correct ($actual)." "$file permissions are correct ($actual)." ""
            fi
        fi
    done
}

# ─────────────────────────────────────────────
#   MODULE 6: Software Updates
# ─────────────────────────────────────────────
scan_updates() {
    write_header "MODULE 6: Software Updates"

    echo -e "${INFO} Checking for security updates via dnf..."

    if ! command -v dnf &>/dev/null; then
        log_finding "$INFO" "dnf not found — skipping update check." "dnf not found." ""
        return
    fi

    local updates
    updates=$(dnf check-update --security -q 2>/dev/null)
    local exit_code=$?

    # dnf returns exit code 100 when updates are available
    if [[ $exit_code -eq 100 || -n "$updates" ]]; then
        local count=$(echo "$updates" | grep -v '^$' | wc -l)
        log_finding "$WARN" "$count security update(s) are pending." "$count security updates pending." "dnf update --security -y"
        ask_groq "$count security updates are pending on Red Hat Linux"

        echo "<details><summary>View pending updates</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$updates" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"
    else
        log_finding "$PASS" "System is fully up to date." "No pending security updates." ""
    fi

    # Auto-updates check
    if systemctl is-active --quiet dnf-automatic; then
        log_finding "$PASS" "Automatic updates (dnf-automatic) are enabled." "dnf-automatic is active." ""
    else
        log_finding "$WARN" "Automatic updates are not enabled." "dnf-automatic is not running." "systemctl enable --now dnf-automatic"
        ask_groq "Automatic updates are disabled on Red Hat Linux"
    fi
}

# ─────────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────────
main() {
    clear
    echo -e "${YELLOW}=================================================${NC}"
    echo -e "${YELLOW}         RHEL Automated System Audit Tool        ${NC}"
    echo -e "${YELLOW}=================================================${NC}"

    check_root

    scan_system_status
    scan_ssh_config
    scan_open_ports
    scan_users
    scan_permissions
    scan_updates

    echo -e "\n${GREEN}=================================================${NC}"
    echo -e "${GREEN}  Audit complete!                                ${NC}"
    echo -e "${GREEN}  Report saved to: ${CYAN}$REPORT${NC}"
    echo -e "${GREEN}=================================================${NC}\n"
}

main
