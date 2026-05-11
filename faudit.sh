#!/bin/bash
# ==============================================================================
#   RHEL Automated System Audit Tool
#   Scans: system status, SSH, open ports, users, permissions, updates
#   Enhancement: Groq AI recommendations for every issue found
# ==============================================================================

# The report file name includes the date and time so each run creates a new file
REPORT="audit_report_$(date +%Y%m%d_%H%M%S).md"

# Put your Groq API key here (get one free at console.groq.com)
GROQ_API_KEY="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"

# ── Terminal Colors ───────────────────────────
# These make the output easier to read in the terminal
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'   # NC = No Color (resets back to normal)

# ── Status Icons ──────────────────────────────
# These are printed before each finding so you can spot issues quickly
PASS="[${GREEN}✔${NC}]"   # Green checkmark = everything is fine
FAIL="[${RED}✖${NC}]"    # Red X = critical problem found
WARN="[${YELLOW}!${NC}]"  # Yellow ! = warning, should be reviewed
INFO="[${CYAN}i${NC}]"   # Cyan i = just information, no action needed

# ── Create the report file with a header ─────
cat <<EOF > "$REPORT"
# RHEL System Audit Report
**Date:** $(date)
**Hostname:** $(hostname)

---
EOF


# ==============================================================================
#   HELPER FUNCTIONS
#   Small reusable tools used by all the modules below
# ==============================================================================

# Prints a section title to the terminal and adds it to the report
write_header() {
    echo -e "\n${CYAN}=== $1 ===${NC}"
    echo -e "\n## $1\n" >> "$REPORT"
}

# Prints a finding to the terminal and saves it to the report
# Usage: log_finding "$PASS" "what happened" "report message" "how to fix it"
log_finding() {
    local status="$1"       # The icon: PASS, FAIL, WARN, or INFO
    local term_msg="$2"     # Message shown in the terminal
    local report_msg="$3"   # Message saved in the report file
    local fix="$4"          # The command to fix the issue (can be empty)

    # Print the status icon and message to the terminal
    echo -e "${status} ${term_msg}"

    # If a fix was provided, print it below the finding
    if [[ -n "$fix" ]]; then
        echo -e "    ${CYAN}-> Fix:${NC} ${fix}"
    fi

    # Choose the right emoji for the report based on the status icon
    local md_icon=""
    if [[ "$status" == "$PASS" ]]; then
        md_icon="✅"
    elif [[ "$status" == "$FAIL" ]]; then
        md_icon="❌"
    elif [[ "$status" == "$WARN" ]]; then
        md_icon="⚠️"
    else
        md_icon="ℹ️"
    fi

    # Save the finding and fix to the report file
    if [[ -n "$report_msg" ]]; then
        echo "- **${md_icon}** ${report_msg}" >> "$REPORT"
        if [[ -n "$fix" ]]; then
            echo "  - *Fix:* \`${fix}\`" >> "$REPORT"
        fi
    fi
}

# Sends an issue to Groq AI and prints the recommendation it gives back
# Usage: ask_groq "description of the problem"
ask_groq() {
    local issue="$1"

    # Skip silently if curl or jq are not installed
    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        return
    fi

    echo -e "    ${CYAN}[AI]${NC} Asking Groq..."

    # Send the issue to the Groq API and store the full JSON response
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

    # Pull just the advice text out of the JSON response
    local advice
    advice=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    # Print and save the advice only if we got a valid response
    if [[ -n "$advice" && "$advice" != "null" ]]; then
        echo -e "    ${CYAN}[AI]${NC} $advice"
        echo "  - *AI Advice:* $advice" >> "$REPORT"
    fi
}

# Stops the script if it is not being run as root
# Some checks like reading /etc/shadow require root access
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${FAIL} ${RED}This script must be run as root. Use: sudo bash $0${NC}"
        exit 1
    fi
}


# ==============================================================================
#   MODULE 1: Core System Protections
#   Checks SELinux and the firewall — two key Red Hat security features
# ==============================================================================
scan_system_status() {
    write_header "MODULE 1: Core System Protections"

    # --- Check SELinux ---
    # SELinux is Red Hat's built-in security system
    # It should always be "Enforcing" — anything else means protections are off
    if command -v getenforce &>/dev/null; then

        # Get the current SELinux mode: Enforcing, Permissive, or Disabled
        local selinux_mode
        selinux_mode=$(getenforce)

        if [[ "$selinux_mode" == "Enforcing" ]]; then
            log_finding "$PASS" "SELinux is Enforcing." \
                "SELinux is active and enforcing." ""
        else
            log_finding "$FAIL" "SELinux is NOT enforcing (Current: $selinux_mode)." \
                "SELinux is set to $selinux_mode." \
                "setenforce 1 and set SELINUX=enforcing in /etc/selinux/config"
            ask_groq "SELinux is set to $selinux_mode on Red Hat Linux"
        fi

    else
        # The getenforce command was not found on this system
        log_finding "$WARN" "SELinux tools not found." \
            "getenforce not found." \
            "sudo dnf install selinux-policy"
    fi

    # --- Check Firewall ---
    # firewalld is the default firewall on Red Hat
    # If it is not running, the server is exposed to the network
    if systemctl is-active --quiet firewalld; then
        log_finding "$PASS" "Firewalld is active." "Firewalld is running." ""
    else
        log_finding "$WARN" "Firewalld is NOT active." \
            "Firewalld is not running." \
            "systemctl enable --now firewalld"
        ask_groq "Firewalld is disabled on Red Hat Linux"
    fi
}


# ==============================================================================
#   MODULE 2: SSH Security
#   Checks the SSH config file for common misconfigurations
# ==============================================================================
scan_ssh_config() {
    write_header "MODULE 2: SSH Security"

    local sshd_config="/etc/ssh/sshd_config"

    # Stop here if the SSH config file does not exist on this system
    if [[ ! -f "$sshd_config" ]]; then
        log_finding "$INFO" "SSH config not found at $sshd_config." \
            "SSH config not found." ""
        return
    fi

    # --- Check if root can log in over SSH ---
    # Allowing root SSH login is dangerous — attackers target it directly
    # We search the config file for the line "PermitRootLogin yes"
    if grep -qE "^PermitRootLogin\s+yes" "$sshd_config"; then
        log_finding "$FAIL" "SSH root login is permitted." \
            "PermitRootLogin is set to yes." \
            "Set PermitRootLogin no in $sshd_config then restart sshd"
        ask_groq "SSH root login is enabled on Red Hat Linux"
    else
        log_finding "$PASS" "SSH root login is disabled." \
            "PermitRootLogin is restricted." ""
    fi

    # --- Check if password login is allowed ---
    # Passwords can be brute-forced by attackers — SSH keys are much safer
    # We search the config file for the line "PasswordAuthentication yes"
    if grep -qE "^PasswordAuthentication\s+yes" "$sshd_config"; then
        log_finding "$WARN" "SSH password authentication is enabled." \
            "PasswordAuthentication is yes." \
            "Set PasswordAuthentication no and use SSH keys instead"
        ask_groq "SSH password authentication is enabled on Red Hat Linux"
    else
        log_finding "$PASS" "SSH password authentication is disabled." \
            "PasswordAuthentication is disabled." ""
    fi
}


# ==============================================================================
#   MODULE 3: Open Ports
#   Lists all services listening for network connections
#   Then flags any ports known to be dangerous
# ==============================================================================
scan_open_ports() {
    write_header "MODULE 3: Open Ports"

    # Get all currently listening ports using the ss command
    # tail -n +2 skips the first header line so we only get the data
    local all_ports
    all_ports=$(ss -tulpn | tail -n +2)

    # If nothing is listening, the system is clean — stop here
    if [[ -z "$all_ports" ]]; then
        log_finding "$PASS" "No listening ports found." "No listening ports found." ""
        return
    fi

    log_finding "$INFO" "Listening ports detected (see report for full list)." "" ""

    # Write a table header into the report file
    echo "| Protocol | Address:Port | Process |" >> "$REPORT"
    echo "|---|---|---|" >> "$REPORT"

    # Print a table header to the terminal
    printf "${CYAN}%-10s %-30s %-20s${NC}\n" "Protocol" "Address:Port" "Process"
    echo "-------------------------------------------------------------"

    # Loop through each open port line and display it as a table row
    while read -r line; do

        # Extract the protocol (tcp or udp) from column 1
        local proto
        proto=$(echo "$line" | awk '{print $1}')

        # Extract the address and port from column 5
        local addr
        addr=$(echo "$line" | awk '{print $5}')

        # Extract the process name — it is hidden inside brackets in the output
        local process
        process=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')

        # If no process name was found, label it as unknown
        if [[ -z "$process" ]]; then
            process="unknown"
        fi

        # Print this port to the terminal and save it to the report
        printf "%-10s %-30s %-20s\n" "$proto" "$addr" "$process"
        echo "| $proto | \`$addr\` | $process |" >> "$REPORT"

    done <<< "$all_ports"

    echo ""
    echo -e "    ${CYAN}-> Fix:${NC} Disable unused services: systemctl disable <service>"
    echo "  - *Fix:* Disable unused services or block ports via firewall-cmd" >> "$REPORT"

    # --- Flag known dangerous ports ---
    # These ports are common attack targets and should not be open
    local dangerous_ports="21 23 445 3389 5900"

    for port in $dangerous_ports; do

        # Check if this port number appears in the list of open ports
        if echo "$all_ports" | grep -q ":$port "; then
            log_finding "$FAIL" "Dangerous port $port is open!" \
                "Port $port is open." \
                "firewall-cmd --remove-port=$port/tcp --permanent && firewall-cmd --reload"
            ask_groq "Port $port is open on Red Hat Linux"
        fi

    done
}


# ==============================================================================
#   MODULE 4: User & Access Control
#   Checks for weak or unauthorized user account settings
# ==============================================================================
scan_users() {
    write_header "MODULE 4: User & Access Control"

    # --- Check for accounts with UID 0 other than root ---
    # UID 0 means root-level access — only the root account should have it
    # We read /etc/passwd and look for any account where column 3 is 0
    local uid0_users
    uid0_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)

    if [[ -n "$uid0_users" ]]; then
        for user in $uid0_users; do
            log_finding "$FAIL" "Unauthorized UID 0 account: $user" \
                "Unauthorized UID 0 account: \`$user\`." \
                "userdel $user  OR  usermod -u <new_uid> $user"
            ask_groq "User $user has UID 0 (root privileges) on Red Hat Linux"
        done
    else
        log_finding "$PASS" "Only root has UID 0." \
            "No unauthorized UID 0 accounts." ""
    fi

    # --- Check for accounts with no password ---
    # An account with no password can be logged into by anyone with no credentials
    # /etc/shadow stores passwords — an empty second column means no password is set
    local empty_pw_users
    empty_pw_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)

    if [[ -n "$empty_pw_users" ]]; then
        for user in $empty_pw_users; do
            log_finding "$FAIL" "Account with no password: $user" \
                "Account with empty password: \`$user\`." \
                "passwd $user  OR  passwd -l $user to lock it"
            ask_groq "User $user has no password on Red Hat Linux"
        done
    else
        log_finding "$PASS" "All accounts have passwords set." \
            "No empty password accounts found." ""
    fi

    # --- Check that passwords are set to expire ---
    # Passwords should expire every 90 days to force regular changes
    # chage -l shows expiry info — a max of 99999 means the password never expires
    local no_expiry_users=""

    # Loop through every human user account (UID 1000 and above)
    while read -r username; do

        # Get the maximum password age for this user
        local max_days
        max_days=$(chage -l "$username" 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ')

        # If max is 99999 or blank, the password never expires — flag this user
        if [[ "$max_days" == "99999" || -z "$max_days" ]]; then
            no_expiry_users="$no_expiry_users $username"
        fi

    done < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)

    if [[ -n "$no_expiry_users" ]]; then
        log_finding "$WARN" "Users with no password expiry:$no_expiry_users" \
            "Users with no password expiry: \`$no_expiry_users\`." \
            "chage -M 90 <username>"
        ask_groq "User accounts have no password expiry set on Red Hat Linux"
    else
        log_finding "$PASS" "All user passwords have expiry set." \
            "All passwords have expiry configured." ""
    fi

    # --- List users who can log into the system interactively ---
    # Service accounts like apache or mysql should not have a login shell
    # This is informational only so the admin can review who has access
    local shell_users
    shell_users=$(grep -Ev 'nologin|false|sync|halt|shutdown' /etc/passwd | awk -F: '{print $1}' | tr '\n' ' ')

    if [[ -n "$shell_users" ]]; then
        log_finding "$INFO" "Users with login shells: $shell_users" \
            "Users with login shells: \`$shell_users\`." \
            "usermod -s /sbin/nologin <user> for service accounts"
    fi
}


# ==============================================================================
#   MODULE 5: File Permissions
#   Looks for files that have unsafe permissions
# ==============================================================================
scan_permissions() {
    write_header "MODULE 5: File Permissions"

    echo -e "${INFO} Scanning for weak permissions (may take a moment)..."

    # Skip these directories to avoid errors and unnecessary slowness
    local skip_dirs="-type d \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp \) -prune -o"

    # --- Find world-writable files ---
    # A world-writable file can be edited by any user on the system
    # This is dangerous for system files in /etc or /usr/bin
    local ww_files
    ww_files=$(find / $skip_dirs -type f -perm -0002 -print 2>/dev/null)

    if [[ -n "$ww_files" ]]; then
        local ww_count
        ww_count=$(echo "$ww_files" | wc -l)

        log_finding "$FAIL" "Found $ww_count world-writable file(s)." \
            "Found $ww_count world-writable files." \
            "chmod o-w <file> for each listed file"
        ask_groq "There are $ww_count world-writable files on Red Hat Linux"

        # Save the full list in a collapsible section in the report
        echo "<details><summary>View world-writable files</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$ww_files" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"
    else
        log_finding "$PASS" "No world-writable files found." \
            "No world-writable files found." ""
    fi

    # --- Find SUID and SGID binaries ---
    # SUID files run as root even when a normal user executes them
    # Unexpected SUID files can be used to gain unauthorized root access
    local suid_files
    suid_files=$(find / $skip_dirs -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)

    if [[ -n "$suid_files" ]]; then
        local suid_count
        suid_count=$(echo "$suid_files" | wc -l)

        log_finding "$WARN" "Found $suid_count SUID/SGID file(s) — verify each is legitimate." \
            "Found $suid_count SUID/SGID files." \
            "chmod u-s,g-s <file> if SUID is not needed"
        ask_groq "There are $suid_count SUID/SGID binaries found on Red Hat Linux"

        echo "<details><summary>View SUID/SGID files</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$suid_files" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"
    else
        log_finding "$PASS" "No unexpected SUID/SGID files found." \
            "No SUID/SGID files found." ""
    fi

    # --- Check permissions on critical system files ---
    # These three files must have exact permissions to stay secure
    # We store them as "filepath:expected_permission"
    local critical_files=(
        "/etc/shadow:640"    # Stores password hashes — must not be readable by all users
        "/etc/passwd:644"    # Stores user info — readable by all, writable by root only
        "/etc/sudoers:440"   # Controls sudo access — should only be readable by root
    )

    for entry in "${critical_files[@]}"; do

        # Split the entry into the file path and its expected permission number
        local file="${entry%%:*}"
        local expected_perm="${entry##*:}"

        if [[ -f "$file" ]]; then

            # Read the actual current permission of the file
            local actual_perm
            actual_perm=$(stat -c "%a" "$file" 2>/dev/null)

            if [[ "$actual_perm" != "$expected_perm" ]]; then
                log_finding "$FAIL" "$file has wrong permissions ($actual_perm, expected $expected_perm)." \
                    "$file permissions are $actual_perm (expected $expected_perm)." \
                    "chmod $expected_perm $file"
                ask_groq "$file has permissions $actual_perm instead of $expected_perm on Red Hat Linux"
            else
                log_finding "$PASS" "$file permissions are correct ($actual_perm)." \
                    "$file permissions are correct ($actual_perm)." ""
            fi
        fi
    done
}


# ==============================================================================
#   MODULE 6: Software Updates
#   Checks if the system has any pending security patches
# ==============================================================================
scan_updates() {
    write_header "MODULE 6: Software Updates"

    echo -e "${INFO} Checking for security updates via dnf..."

    # Stop here if dnf is not available on this system
    if ! command -v dnf &>/dev/null; then
        log_finding "$INFO" "dnf not found — skipping update check." "dnf not found." ""
        return
    fi

    # Ask dnf to list any pending security updates
    # The -q flag means quiet mode — no extra output, just the results
    local pending_updates
    pending_updates=$(dnf check-update --security -q 2>/dev/null)
    local exit_code=$?

    # dnf uses exit code 100 (not 0) to signal that updates are available
    if [[ $exit_code -eq 100 || -n "$pending_updates" ]]; then

        # Count how many packages need to be updated
        local update_count
        update_count=$(echo "$pending_updates" | grep -v '^$' | wc -l)

        log_finding "$WARN" "$update_count security update(s) are pending." \
            "$update_count security updates pending." \
            "dnf update --security -y"
        ask_groq "$update_count security updates are pending on Red Hat Linux"

        # Save the full list of pending updates in a collapsible section
        echo "<details><summary>View pending updates</summary>" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$pending_updates" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "</details>" >> "$REPORT"

    else
        log_finding "$PASS" "System is fully up to date." \
            "No pending security updates." ""
    fi

    # --- Check if automatic updates are enabled ---
    # dnf-automatic applies security patches automatically without manual runs
    if systemctl is-active --quiet dnf-automatic; then
        log_finding "$PASS" "Automatic updates (dnf-automatic) are enabled." \
            "dnf-automatic is active." ""
    else
        log_finding "$WARN" "Automatic updates are not enabled." \
            "dnf-automatic is not running." \
            "systemctl enable --now dnf-automatic"
        ask_groq "Automatic updates are disabled on Red Hat Linux"
    fi
}


# ==============================================================================
#   MAIN — This is where the script starts
#   It runs each module one by one in order
# ==============================================================================
main() {
    clear
    echo -e "${YELLOW}=================================================${NC}"
    echo -e "${YELLOW}         RHEL Automated System Audit Tool        ${NC}"
    echo -e "${YELLOW}=================================================${NC}"

    # Make sure the script is running as root before doing anything
    check_root

    # Run all six audit modules in order
    scan_system_status   # Module 1 — SELinux and Firewall
    scan_ssh_config      # Module 2 — SSH settings
    scan_open_ports      # Module 3 — Open network ports
    scan_users           # Module 4 — User accounts
    scan_permissions     # Module 5 — File permissions
    scan_updates         # Module 6 — Pending software updates

    # Print completion message and report location
    echo -e "\n${GREEN}=================================================${NC}"
    echo -e "${GREEN}  Audit complete!                                ${NC}"
    echo -e "${GREEN}  Report saved to: ${CYAN}$REPORT${NC}"
    echo -e "${GREEN}=================================================${NC}\n"
}

# Start the script
main
