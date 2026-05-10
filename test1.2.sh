#!/bin/bash

# ==============================================================================
# RHEL Automated System Audit Tool
# Description: Comprehensive system audit scanning for system status, open ports, 
#              weak permissions, unauthorized users, and pending security updates.
# ==============================================================================

# -------------------------
# Variables & Formatting
# -------------------------
REPORT_FILE="audit_report.md"

# Color Codes for Terminal Output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Visual Indicators
PASS="[${GREEN}✔${NC}]"
FAIL="[${RED}✖${NC}]"
WARN="[${YELLOW}!${NC}]"
INFO="[${CYAN}i${NC}]"

# Initialize/Clear the report file
> "$REPORT_FILE"
cat <<EOF > "$REPORT_FILE"
# RHEL System Audit Report
**Date:** $(date)
**Hostname:** $(hostname)

---
EOF

# -------------------------
# Helper Functions
# -------------------------

# Function to check for Root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${FAIL} ${RED}CRITICAL: This script must be run as root. Exiting.${NC}"
        exit 1
    fi
}

# Function to log findings
# Arguments: $1 = Status (PASS/FAIL/WARN/INFO), $2 = Terminal Msg, $3 = Report Msg, $4 = Remediation
log_finding() {
    local status="$1"
    local term_msg="$2"
    local report_msg="$3"
    local remediation="$4"

    # Print to Terminal
    echo -e "${status} ${term_msg}"
    if [[ -n "$remediation" ]]; then
        echo -e "    ${CYAN}-> Remediation:${NC} ${remediation}"
    fi

    # Determine markdown icon
    local md_icon=""
    case "$status" in
        "$PASS") md_icon="✅" ;;
        "$FAIL") md_icon="❌" ;;
        "$WARN") md_icon="⚠️" ;;
        "$INFO") md_icon="ℹ️" ;;
    esac

    # Append to Report File
    if [[ -n "$report_msg" ]]; then
        echo "- **${md_icon}** ${report_msg}" >> "$REPORT_FILE"
        if [[ -n "$remediation" ]]; then
            echo "  - *Remediation:* ${remediation}" >> "$REPORT_FILE"
        fi
    fi
}

write_header() {
    local title="$1"
    echo -e "\n${CYAN}=== ${title} ===${NC}"
    echo -e "\n## ${title}\n" >> "$REPORT_FILE"
}

# -------------------------
# Scan Modules
# -------------------------

scan_system_status() {
    write_header "Core System Protections"

    # Check SELinux
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status=$(getenforce)
        if [[ "$selinux_status" == "Enforcing" ]]; then
            log_finding "$PASS" "SELinux is Enforcing." "SELinux is active and enforcing policies." ""
        else
            log_finding "$FAIL" "SELinux is not Enforcing (Current: $selinux_status)." "SELinux is currently set to $selinux_status." "Set SELinux to Enforcing in /etc/selinux/config and run 'setenforce 1'."
        fi
    else
        log_finding "$WARN" "SELinux tools not found." "SELinux 'getenforce' command not found." "Install selinux-policy."
    fi

    # Check Firewall (firewalld)
    if systemctl is-active --quiet firewalld; then
        log_finding "$PASS" "Firewalld is active." "Firewalld is active and running." ""
    else
        log_finding "$WARN" "Firewalld is NOT active." "Firewalld is NOT running." "Ensure a firewall is enabled using 'systemctl enable --now firewalld'."
    fi
}

scan_ssh_config() {
    write_header "SSH Security Configuration"

    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        # Check Root Login
        if grep -qE "^PermitRootLogin\s+yes" "$sshd_config"; then
            log_finding "$FAIL" "SSH Root Login is permitted." "SSH PermitRootLogin is set to 'yes'." "Change 'PermitRootLogin yes' to 'no' in $sshd_config and restart sshd."
        else
            log_finding "$PASS" "SSH Root Login is restricted." "SSH PermitRootLogin is restricted." ""
        fi

        # Check Password Auth
        if grep -qE "^PasswordAuthentication\s+yes" "$sshd_config"; then
            log_finding "$WARN" "SSH Password Authentication is enabled." "SSH PasswordAuthentication is set to 'yes'." "Use SSH keys and set 'PasswordAuthentication no' in $sshd_config."
        else
            log_finding "$PASS" "SSH Password Authentication is disabled." "SSH PasswordAuthentication is disabled." ""
        fi
    else
        log_finding "$INFO" "SSH configuration not found ($sshd_config)." "SSH configuration not found." ""
    fi
}

scan_open_ports() {
    write_header "Network Security (Listening Ports)"

    local raw_ports=$(ss -tulpn | tail -n +2)
    
    if [[ -n "$raw_ports" ]]; then
        log_finding "$INFO" "Active listening ports detected (see report for details)." "" ""
        
        # Add to Markdown table
        echo "| Protocol | Local Address:Port | Process |" >> "$REPORT_FILE"
        echo "|---|---|---|" >> "$REPORT_FILE"
        
        # Format terminal output nicely
        printf "${CYAN}%-10s %-25s %-30s${NC}\n" "Protocol" "Local Address" "Process"
        echo "-----------------------------------------------------------------"

        echo "$raw_ports" | while read -r line; do
            local proto=$(echo "$line" | awk '{print $1}')
            local local_addr=$(echo "$line" | awk '{print $5}')
            local process=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
            [[ -z "$process" ]] && process="unknown"
            
            # Print to terminal
            printf "%-10s %-25s %-30s\n" "$proto" "$local_addr" "$process"
            
            # Print to Markdown
            echo "| $proto | \`$local_addr\` | $process |" >> "$REPORT_FILE"
        done
        echo "" >> "$REPORT_FILE"
        
        echo -e "    ${CYAN}-> Remediation:${NC} Disable unneeded services via 'systemctl disable <service>' or close ports using 'firewall-cmd --remove-port=<port>/tcp'."
        echo "  - *Remediation:* Disable unneeded services or block ports via firewall." >> "$REPORT_FILE"
    else
        log_finding "$PASS" "No active listening ports found." "No active listening ports found." ""
    fi
}

scan_unauthorized_users() {
    write_header "User & Access Control"

    # Check for UID 0 (other than root)
    local uid_zero=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [[ -n "$uid_zero" ]]; then
        for user in $uid_zero; do
            log_finding "$FAIL" "Unauthorized UID 0 account found: $user" "Unauthorized UID 0 account found: \`$user\`." "Change UID ('usermod -u <new_uid> $user') or delete account ('userdel $user')."
        done
    else
        log_finding "$PASS" "No unauthorized UID 0 accounts found." "No unauthorized UID 0 accounts found." ""
    fi

    # Check for empty passwords in /etc/shadow
    local empty_pass_real=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pass_real" ]]; then
        for user in $empty_pass_real; do
            log_finding "$FAIL" "Account with empty password found: $user" "Account with empty password found: \`$user\`." "Lock the account with 'passwd -l $user' or set a password using 'passwd $user'."
        done
    else
        log_finding "$PASS" "No accounts with empty passwords found." "No accounts with empty passwords found." ""
    fi

    # List users with interactive shells
    local interactive_users=$(grep -E -v 'nologin|false|sync|halt|shutdown' /etc/passwd | awk -F: '{print $1}')
    if [[ -n "$interactive_users" ]]; then
        local user_list=$(echo $interactive_users | tr '\n' ' ')
        log_finding "$INFO" "Users with interactive shells: $user_list" "Users with interactive shells: \`$user_list\`." "Review list. Change shell for service accounts using 'usermod -s /sbin/nologin <user>'."
    fi
}

scan_weak_permissions() {
    write_header "File System Security (Permissions)"

    echo -e "${INFO} Scanning filesystem for world-writable and SUID/SGID files (this may take a minute)..."

    # Exclude virtual filesystems to save time and prevent errors
    local exclude_dirs="-type d \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media -o -path /tmp \) -prune -o"

    # Find world-writable files (777)
    local world_writable=$(find / $exclude_dirs -type f -perm -0002 -print 2>/dev/null)
    
    if [[ -n "$world_writable" ]]; then
        echo "<details><summary><b>World-Writable Files Found</b></summary>" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo '```text' >> "$REPORT_FILE"
        
        local ww_count=0
        for file in $world_writable; do
            ww_count=$((ww_count+1))
            echo "$file" >> "$REPORT_FILE"
        done
        echo '```' >> "$REPORT_FILE"
        echo "</details>" >> "$REPORT_FILE"

        log_finding "$FAIL" "Found $ww_count world-writable file(s)." "Found $ww_count world-writable file(s)." "Review files and run 'chmod o-w <file>' to remove write access for others."
    else
        log_finding "$PASS" "No world-writable files found." "No world-writable files found on standard filesystems." ""
    fi

    # Find SUID/SGID files
    local suid_sgid=$(find / $exclude_dirs -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
    
    if [[ -n "$suid_sgid" ]]; then
        echo "<details><summary><b>SUID/SGID Files Found</b></summary>" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo '```text' >> "$REPORT_FILE"
        
        local sg_count=0
        for file in $suid_sgid; do
            sg_count=$((sg_count+1))
            echo "$file" >> "$REPORT_FILE"
        done
        echo '```' >> "$REPORT_FILE"
        echo "</details>" >> "$REPORT_FILE"

        log_finding "$WARN" "Found $sg_count SUID/SGID file(s)." "Found $sg_count SUID/SGID file(s)." "Ensure SUID/SGID is required. If not, remove using 'chmod u-s,g-s <file>'."
    else
        log_finding "$PASS" "No unexpected SUID/SGID files found." "No SUID/SGID files found." ""
    fi
}

scan_outdated_software() {
    write_header "Patch Management"

    echo -e "${INFO} Checking for security updates via dnf. This may take a moment..."
    
    if command -v dnf >/dev/null 2>&1; then
        local security_updates=$(dnf check-update --security -q 2>/dev/null)
        local dnf_status=$?
        
        # dnf check-update returns exit code 100 if updates are available
        if [[ $dnf_status -eq 100 || -n "$security_updates" ]]; then
            local count=$(echo "$security_updates" | grep -v '^$' | wc -l)
            log_finding "$WARN" "Pending security patches found ($count package(s))." "Pending security patches found ($count packages)." "Apply updates immediately using 'dnf update --security -y'."
            
            echo "<details><summary><b>Pending Updates List</b></summary>" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
            echo '```text' >> "$REPORT_FILE"
            echo "$security_updates" >> "$REPORT_FILE"
            echo '```' >> "$REPORT_FILE"
            echo "</details>" >> "$REPORT_FILE"
        else
            log_finding "$PASS" "System is up to date. No pending security patches found." "System is up to date. No pending security patches found." ""
        fi
    else
        log_finding "$INFO" "dnf command not found. Skipping update check." "dnf command not found. Skipping update check." ""
    fi
}

# -------------------------
# Main Execution
# -------------------------
main() {
    clear
    echo -e "${YELLOW}=================================================${NC}"
    echo -e "${YELLOW}           RHEL System Audit Tool                ${NC}"
    echo -e "${YELLOW}=================================================${NC}"
    
    check_root
    scan_system_status
    scan_ssh_config
    scan_open_ports
    scan_unauthorized_users
    scan_weak_permissions
    scan_outdated_software

    echo -e "\n${GREEN}=================================================${NC}"
    echo -e "${GREEN} Audit Complete!                                 ${NC}"
    echo -e "${GREEN} Actionable report saved to: ${CYAN}${REPORT_FILE}${NC}"
    echo -e "${GREEN}=================================================${NC}\n"
}

# Run the script
main