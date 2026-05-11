#!/usr/bin/env bash
# =============================================================================
#  Automated System Audit Tool (ASAT)
#  -------------------------------------------------------------------------
#  Author : Senior Cybersecurity Engineer / Linux Systems Administrator
#  Purpose: Audit a Linux server for common security misconfigurations and
#           generate an actionable remediation report.
#
#  Audited Areas:
#    1. Network (open TCP/UDP ports + owning processes)
#    2. File-system permissions (critical files, world-writable, SUID/SGID)
#    3. Identity & access (users, passwords, SSH hardening, UID 0)
#    4. Outdated software / missing security patches (apt|dnf|yum|pacman)
#
#  Output:
#    - Colourised terminal report
#    - Plain-text + Markdown report under ./reports/
#
#  Dependencies: GNU coreutils, awk, grep, sed, find, ss/netstat, getent,
#                stat, chage. No third-party tools required.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Globals & colours
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
readonly REPORT_DIR="${REPORT_DIR:-$(pwd)/reports}"
readonly REPORT_TXT="${REPORT_DIR}/asat_${HOSTNAME_FQDN}_${TIMESTAMP}.txt"
readonly REPORT_MD="${REPORT_DIR}/asat_${HOSTNAME_FQDN}_${TIMESTAMP}.md"

# ANSI colours (only when stdout is a TTY)
if [[ -t 1 ]]; then
    readonly C_RESET=$'\033[0m'
    readonly C_BOLD=$'\033[1m'
    readonly C_DIM=$'\033[2m'
    readonly C_RED=$'\033[31m'
    readonly C_GREEN=$'\033[32m'
    readonly C_YELLOW=$'\033[33m'
    readonly C_BLUE=$'\033[34m'
    readonly C_MAGENTA=$'\033[35m'
    readonly C_CYAN=$'\033[36m'
else
    readonly C_RESET="" C_BOLD="" C_DIM=""
    readonly C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_MAGENTA="" C_CYAN=""
fi

# Findings counters (per severity)
declare -i COUNT_CRITICAL=0
declare -i COUNT_HIGH=0
declare -i COUNT_MEDIUM=0
declare -i COUNT_LOW=0
declare -i COUNT_INFO=0

# -----------------------------------------------------------------------------
# Logging / reporting helpers
# -----------------------------------------------------------------------------

# strip_ansi <string> -> echoes string without ANSI escape sequences
strip_ansi() {
    sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' <<< "$1"
}

# print_banner — show the top banner on terminal + report files
print_banner() {
    local banner
    banner=$(cat <<EOF
================================================================
  Automated System Audit Tool (ASAT) v${SCRIPT_VERSION}
  Host       : ${HOSTNAME_FQDN}
  Kernel     : $(uname -srm)
  Date (UTC) : $(date -u '+%Y-%m-%d %H:%M:%S')
  Operator   : $(id -un) (uid=$(id -u))
================================================================
EOF
)
    echo -e "${C_BOLD}${C_CYAN}${banner}${C_RESET}"
    {
        echo "$banner"
        echo
    } >> "$REPORT_TXT"
    {
        echo "# Automated System Audit Tool — Report"
        echo
        echo "- **Host**: \`${HOSTNAME_FQDN}\`"
        echo "- **Kernel**: \`$(uname -srm)\`"
        echo "- **Date (UTC)**: $(date -u '+%Y-%m-%d %H:%M:%S')"
        echo "- **Tool version**: ${SCRIPT_VERSION}"
        echo
    } >> "$REPORT_MD"
}

# section <Title> — emit a section header to all sinks
section() {
    local title="$1"
    echo -e "\n${C_BOLD}${C_BLUE}═══ ${title} ═══${C_RESET}"
    {
        echo
        echo "==================================================================="
        echo " ${title}"
        echo "==================================================================="
    } >> "$REPORT_TXT"
    {
        echo
        echo "## ${title}"
        echo
    } >> "$REPORT_MD"
}

# info <message> — informational note (no severity counter)
info() {
    local msg="$1"
    echo -e "${C_DIM}[i] ${msg}${C_RESET}"
    echo "[i] ${msg}" >> "$REPORT_TXT"
    echo "> ${msg}" >> "$REPORT_MD"
}

# finding <severity> <description> <remediation>
#   severity ∈ {CRITICAL, HIGH, MEDIUM, LOW, INFO}
finding() {
    local severity="$1"
    local description="$2"
    local remediation="$3"
    local color tag

    case "$severity" in
        CRITICAL) color="${C_RED}${C_BOLD}";  tag="CRITICAL"; ((COUNT_CRITICAL++)) || true ;;
        HIGH)     color="${C_RED}";           tag="HIGH";     ((COUNT_HIGH++))     || true ;;
        MEDIUM)   color="${C_YELLOW}";        tag="MEDIUM";   ((COUNT_MEDIUM++))   || true ;;
        LOW)      color="${C_CYAN}";          tag="LOW";      ((COUNT_LOW++))      || true ;;
        INFO|*)   color="${C_GREEN}";         tag="INFO";     ((COUNT_INFO++))     || true ;;
    esac

    # Terminal
    echo -e "${color}[${tag}]${C_RESET} ${description}"
    echo -e "  ${C_DIM}↳ Remediation:${C_RESET} ${remediation}"

    # Plain-text report
    {
        echo "[${tag}] ${description}"
        echo "    Remediation: ${remediation}"
    } >> "$REPORT_TXT"

    # Markdown report
    {
        echo "- **[${tag}]** ${description}"
        echo "    - _Remediation_: \`${remediation}\`"
    } >> "$REPORT_MD"
}

# -----------------------------------------------------------------------------
# Pre-flight: root check + report directory
# -----------------------------------------------------------------------------
require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo -e "${C_RED}[!] This audit tool must be run as root.${C_RESET}" >&2
        echo -e "    Try: ${C_BOLD}sudo ${SCRIPT_NAME}${C_RESET}" >&2
        exit 1
    fi
}

prepare_reports() {
    mkdir -p "$REPORT_DIR"
    : > "$REPORT_TXT"
    : > "$REPORT_MD"
    chmod 600 "$REPORT_TXT" "$REPORT_MD"
}

# -----------------------------------------------------------------------------
# Module 1: Network Auditor
# -----------------------------------------------------------------------------
audit_network() {
    section "1. Network Auditor — Open Ports & Listening Services"

    local listener_cmd=""
    if command -v ss >/dev/null 2>&1; then
        # -H (suppress header) may not exist on older iproute2; test it
        if ss -tulnpH >/dev/null 2>&1; then
            listener_cmd="ss -tulnpH"
        else
            listener_cmd="ss -tulnp"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        listener_cmd="netstat -tulnp"
    else
        finding "MEDIUM" "Neither 'ss' nor 'netstat' available — cannot enumerate listening sockets." \
                "apt-get install iproute2  # or: dnf install iproute"
        return
    fi

    info "Enumerating listening sockets via: ${listener_cmd}"

    # Snapshot listeners
    local listeners
    listeners="$(${listener_cmd} 2>/dev/null || true)"

    if [[ -z "$listeners" ]]; then
        finding "INFO" "No listening TCP/UDP sockets detected." "n/a"
        return
    fi

    # Pretty-print to all sinks
    {
        echo
        echo "${listeners}"
        echo
    } | tee -a "$REPORT_TXT" >/dev/null
    {
        echo
        echo '```'
        echo "${listeners}"
        echo '```'
        echo
    } >> "$REPORT_MD"

    # Heuristic risk flags on common high-risk services
    local proto laddr port proc line
    while IFS= read -r line; do
        # Skip headers (netstat: "Proto…" / "Active…"; ss without -H: "State…")
        if [[ "$line" =~ ^Proto || "$line" =~ ^Active || "$line" =~ ^State || "$line" =~ ^Netid ]]; then
            continue
        fi
        proto="$(awk '{print $1}' <<<"$line")"
        # ss uses field 5 for local address, netstat uses field 4
        if [[ "$listener_cmd" == ss* ]]; then
            laddr="$(awk '{print $5}' <<<"$line")"
            proc="$(awk '{for (i=7; i<=NF; i++) printf $i" "; print ""}' <<<"$line")"
        else
            laddr="$(awk '{print $4}' <<<"$line")"
            proc="$(awk '{print $NF}' <<<"$line")"
        fi
        port="${laddr##*:}"
        if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
            continue
        fi

        # Flag services bound to all interfaces on legacy/cleartext ports
        if [[ "$laddr" == 0.0.0.0:* || "$laddr" == "*:"* || "$laddr" == "[::]:"* ]]; then
            case "$port" in
                21)   finding "HIGH"   "FTP (cleartext) listening on all interfaces (${laddr}) — ${proc}" \
                              "systemctl disable --now vsftpd  # or replace with sftp/ssh" ;;
                23)   finding "CRITICAL" "Telnet listening on all interfaces (${laddr}) — ${proc}" \
                              "systemctl disable --now telnet.socket inetd; remove telnetd package" ;;
                25)   finding "MEDIUM" "SMTP open on all interfaces (${laddr}) — ${proc}" \
                              "Restrict to localhost in postfix/sendmail or add firewall rules" ;;
                111)  finding "HIGH"   "RPCbind exposed on all interfaces (${laddr}) — ${proc}" \
                              "systemctl disable --now rpcbind rpcbind.socket" ;;
                139|445) finding "HIGH" "SMB/NetBIOS listening on all interfaces (${laddr}) — ${proc}" \
                              "Bind Samba to LAN only or disable: systemctl disable --now smb nmb" ;;
                512|513|514) finding "CRITICAL" "Legacy r-services on ${laddr} — ${proc}" \
                              "Remove rsh-server / inetd; use SSH instead" ;;
                3306) finding "MEDIUM" "MySQL/MariaDB exposed on ${laddr} — ${proc}" \
                              "Set bind-address=127.0.0.1 in my.cnf and restart service" ;;
                5432) finding "MEDIUM" "PostgreSQL exposed on ${laddr} — ${proc}" \
                              "Set listen_addresses='localhost' in postgresql.conf" ;;
                6379) finding "HIGH"   "Redis exposed on ${laddr} — ${proc}" \
                              "Bind to 127.0.0.1 and require auth (requirepass) in redis.conf" ;;
                27017) finding "HIGH"  "MongoDB exposed on ${laddr} — ${proc}" \
                              "Set bindIp: 127.0.0.1 and enable authorization in mongod.conf" ;;
            esac
        fi

        # Sockets owned by 'users:(("-",pid=...))' (ss prints '-' when proc not resolvable)
        if [[ "$listener_cmd" == ss* && "$proc" != *users:* ]]; then
            :
        fi
    done <<< "$listeners"

    # Sockets without an owning process (often a sign of insufficient privilege or rootkits)
    if [[ "$listener_cmd" == ss* ]]; then
        local orphan
        orphan="$(${listener_cmd} 2>/dev/null | awk '$0 !~ /users:\(/ {print}' || true)"
        if [[ -n "$orphan" ]]; then
            finding "LOW" "Listening sockets without a resolvable owning process detected." \
                    "Re-run with full privileges; investigate via: lsof -i -P -n"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Module 2: Permission & File System Auditor
# -----------------------------------------------------------------------------
audit_filesystem() {
    section "2. Permission & File-System Auditor"

    # 2.a — Critical system files
    local f mode owner expected
    declare -A EXPECTED_MODE=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="000:640"   # accept 000 (chattr +i) or 640
        ["/etc/gshadow"]="000:640"
        ["/etc/group"]="644"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
    )

    for f in "${!EXPECTED_MODE[@]}"; do
        if [[ ! -e "$f" ]]; then
            finding "INFO" "Critical file not present: ${f}" "n/a — file may be optional on this distro"
            continue
        fi
        mode=$(stat -c "%a" "$f")
        owner=$(stat -c "%U:%G" "$f")
        expected="${EXPECTED_MODE[$f]}"

        # Permission check
        if [[ ":${expected}:" != *":${mode}:"* ]]; then
            finding "HIGH" "Unsafe permissions on ${f} (current=${mode}, expected=${expected})" \
                    "chmod ${expected%%:*} ${f}"
        fi

        # Ownership check (root:root, except sshd_config sometimes root:root too)
        if [[ "$owner" != "root:root" && "$owner" != "root:shadow" ]]; then
            finding "HIGH" "Unexpected owner on ${f} (current=${owner})" \
                    "chown root:root ${f}"
        fi
    done

    # 2.b — World-writable files (excluding /proc, /sys, /dev, /run)
    info "Searching for world-writable files (this may take a moment)…"
    local ww
    ww=$(find / -xdev -type f -perm -0002 \
            ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' \
            -not -perm -1000 2>/dev/null | head -n 50 || true)
    if [[ -n "$ww" ]]; then
        local count
        count=$(wc -l <<<"$ww")
        finding "HIGH" "World-writable files detected (${count} shown, capped at 50). First entries follow:" \
                "chmod o-w <file>   # for each affected file"
        {
            echo "$ww"
        } >> "$REPORT_TXT"
        {
            echo
            echo '```'
            echo "$ww"
            echo '```'
        } >> "$REPORT_MD"
    else
        finding "INFO" "No world-writable files (without sticky bit) found." "n/a"
    fi

    # 2.c — World-writable directories without sticky bit
    local wwd
    wwd=$(find / -xdev -type d -perm -0002 ! -perm -1000 \
            ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null | head -n 30 || true)
    if [[ -n "$wwd" ]]; then
        finding "MEDIUM" "World-writable directories without sticky bit detected." \
                "chmod +t <dir>  # or remove world-write: chmod o-w <dir>"
        echo "$wwd" >> "$REPORT_TXT"
        { echo; echo '```'; echo "$wwd"; echo '```'; } >> "$REPORT_MD"
    fi

    # 2.d — SUID / SGID binaries (compared against an allow-list)
    info "Enumerating SUID/SGID binaries…"
    local known_suid_re='^(/bin|/sbin|/usr/bin|/usr/sbin|/usr/libexec|/usr/lib|/lib|/lib64|/snap|/opt)/'
    local suid
    suid=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
             ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null || true)

    if [[ -z "$suid" ]]; then
        finding "INFO" "No SUID/SGID files were found." "n/a"
    else
        # Save full list to report
        {
            echo "Full SUID/SGID inventory:"
            echo "$suid"
        } >> "$REPORT_TXT"
        { echo; echo '```'; echo "$suid"; echo '```'; } >> "$REPORT_MD"

        # Flag entries living outside standard system paths
        local suspect
        suspect=$(grep -Ev "$known_suid_re" <<<"$suid" || true)
        if [[ -n "$suspect" ]]; then
            finding "HIGH" "SUID/SGID binaries outside standard system paths — possible privilege-escalation vector." \
                    "Audit each entry; remove SUID with: chmod u-s <file>  /  chmod g-s <file>"
            echo "Suspect SUID/SGID entries:" >> "$REPORT_TXT"
            echo "$suspect" >> "$REPORT_TXT"
        else
            finding "INFO" "All SUID/SGID binaries reside in standard system paths." "n/a"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Module 3: Access & Identity Auditor
# -----------------------------------------------------------------------------
audit_identity() {
    section "3. Access & Identity Auditor"

    # 3.a — Non-root accounts with UID 0
    local uid0
    uid0=$(awk -F: '($3 == 0) && ($1 != "root") {print $1}' /etc/passwd || true)
    if [[ -n "$uid0" ]]; then
        finding "CRITICAL" "Non-root account(s) with UID 0 detected: ${uid0//$'\n'/, }" \
                "usermod -u <new_uid> <user>  # or: userdel <user>"
    else
        finding "INFO" "Only 'root' has UID 0." "n/a"
    fi

    # 3.b — Empty-password accounts (/etc/shadow field 2 empty)
    local empty_pw
    empty_pw=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pw" ]]; then
        finding "CRITICAL" "Account(s) with no password: ${empty_pw//$'\n'/, }" \
                "passwd -l <user>   # lock account, or set strong password with: passwd <user>"
    else
        finding "INFO" "No accounts with empty passwords." "n/a"
    fi

    # 3.c — Locked vs. unlocked system accounts that have a real shell
    local sysshell
    sysshell=$(awk -F: '($3 < 1000) && ($1 != "root") && ($7 ~ /\/(bash|sh|zsh|ksh|fish)$/) {print $1":"$7}' /etc/passwd || true)
    if [[ -n "$sysshell" ]]; then
        finding "MEDIUM" "System accounts (UID<1000) with interactive shells: ${sysshell//$'\n'/, }" \
                "usermod -s /usr/sbin/nologin <user>   # for each non-interactive account"
    fi

    # 3.d — Stale accounts (no login for 90+ days, where lastlog data exists)
    if command -v lastlog >/dev/null 2>&1; then
        local stale
        stale=$(lastlog -b 90 2>/dev/null | awk 'NR>1 && $0 !~ /Never logged in/ {print $1}' || true)
        if [[ -n "$stale" ]]; then
            finding "LOW" "Account(s) with no login in last 90 days: ${stale//$'\n'/, }" \
                    "Review and disable with: usermod -L <user>  or  passwd -l <user>"
        fi
    fi

    # 3.e — Password policy (login.defs)
    if [[ -r /etc/login.defs ]]; then
        local max_days min_days
        max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs)
        min_days=$(awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs)
        if [[ -n "$max_days" && "$max_days" -gt 90 ]]; then
            finding "MEDIUM" "PASS_MAX_DAYS=${max_days} (>90 days) in /etc/login.defs." \
                    "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"
        fi
        if [[ -n "$min_days" && "$min_days" -lt 1 ]]; then
            finding "LOW" "PASS_MIN_DAYS=${min_days} allows immediate password reuse." \
                    "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs"
        fi
    fi

    # 3.f — SSH hardening (/etc/ssh/sshd_config)
    local sshd_cfg="/etc/ssh/sshd_config"
    if [[ -r "$sshd_cfg" ]]; then
        # Helper: read effective directive (last uncommented occurrence wins)
        ssh_get() { grep -Ei "^[[:space:]]*${1}[[:space:]]+" "$sshd_cfg" 2>/dev/null | tail -n1 | awk '{print $2}' || true; }

        local v
        v=$(ssh_get "PermitRootLogin"); v="${v:-prohibit-password}"
        if [[ "${v,,}" == "yes" ]]; then
            finding "HIGH" "SSH permits direct root login (PermitRootLogin yes)." \
                    "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' ${sshd_cfg} && systemctl reload sshd"
        fi

        v=$(ssh_get "PermitEmptyPasswords"); v="${v:-no}"
        if [[ "${v,,}" == "yes" ]]; then
            finding "CRITICAL" "SSH allows empty passwords (PermitEmptyPasswords yes)." \
                    "sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' ${sshd_cfg} && systemctl reload sshd"
        fi

        v=$(ssh_get "PasswordAuthentication"); v="${v:-yes}"
        if [[ "${v,,}" == "yes" ]]; then
            finding "MEDIUM" "SSH password authentication enabled — prefer key-based auth." \
                    "Set 'PasswordAuthentication no' in ${sshd_cfg} after deploying SSH keys"
        fi

        v=$(ssh_get "X11Forwarding"); v="${v:-no}"
        if [[ "${v,,}" == "yes" ]]; then
            finding "LOW" "X11Forwarding is enabled in sshd." \
                    "sed -i 's/^#\\?X11Forwarding.*/X11Forwarding no/' ${sshd_cfg}"
        fi

        v=$(ssh_get "Protocol"); v="${v:-2}"
        if [[ "$v" == *1* ]]; then
            finding "CRITICAL" "SSH Protocol 1 enabled — cryptographically broken." \
                    "Set 'Protocol 2' (or remove the directive on modern OpenSSH)"
        fi

        v=$(ssh_get "MaxAuthTries"); v="${v:-6}"
        if [[ "$v" =~ ^[0-9]+$ && "$v" -gt 4 ]]; then
            finding "LOW" "MaxAuthTries=${v} (>4) — allows excessive auth attempts per connection." \
                    "Set 'MaxAuthTries 4' in ${sshd_cfg}"
        fi
    else
        finding "INFO" "${sshd_cfg} not readable; skipping SSH hardening checks." "n/a"
    fi

    # 3.g — Sudoers wildcard NOPASSWD
    if [[ -r /etc/sudoers ]]; then
        if grep -Eqs '^[^#]*NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            finding "HIGH" "NOPASSWD:ALL rule(s) found in sudoers." \
                    "Review with: grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/  — restrict to specific commands"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Module 4: Software & Patch Auditor
# -----------------------------------------------------------------------------
audit_software() {
    section "4. Software & Patch Auditor"

    if command -v apt-get >/dev/null 2>&1; then
        info "Detected APT (Debian/Ubuntu family). Refreshing package metadata…"
        apt-get update -qq >/dev/null 2>&1 || \
            finding "LOW" "'apt-get update' failed or partial." "Investigate /etc/apt/sources.list and network connectivity"
        local upgradable security_count
        upgradable=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst /{print $2}' || true)
        security_count=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / && /-security/ {c++} END {print c+0}')
        if [[ -n "$upgradable" ]]; then
            local total
            total=$(wc -l <<<"$upgradable")
            local sev="MEDIUM"
            if [[ "$security_count" -gt 0 ]]; then sev="HIGH"; fi
            finding "$sev" "${total} package(s) upgradable; ${security_count} appear to be security updates." \
                    "apt-get update && apt-get -y upgrade   # review changelog before applying"
            { echo "Upgradable packages:"; echo "$upgradable"; } >> "$REPORT_TXT"
            { echo; echo '```'; echo "$upgradable"; echo '```'; } >> "$REPORT_MD"
        else
            finding "INFO" "All APT packages are up-to-date." "n/a"
        fi

    elif command -v dnf >/dev/null 2>&1; then
        info "Detected DNF (Fedora/RHEL 8+/Rocky/Alma)."
        local sec
        sec=$(dnf -q updateinfo list security 2>/dev/null || true)
        if [[ -n "$sec" ]]; then
            finding "HIGH" "Security advisories pending via DNF." \
                    "dnf -y update --security"
            { echo "$sec"; } >> "$REPORT_TXT"
            { echo; echo '```'; echo "$sec"; echo '```'; } >> "$REPORT_MD"
        else
            local upd
            upd=$(dnf -q check-update 2>/dev/null || true)
            if [[ -n "$upd" ]]; then
                finding "MEDIUM" "Non-security package updates are available via DNF." \
                        "dnf -y update"
            else
                finding "INFO" "All DNF packages are up-to-date." "n/a"
            fi
        fi

    elif command -v yum >/dev/null 2>&1; then
        info "Detected YUM (RHEL/CentOS 7)."
        local sec
        sec=$(yum --security check-update 2>/dev/null || true)
        if grep -q 'needed for security' <<<"$sec"; then
            finding "HIGH" "YUM reports pending security updates." \
                    "yum -y update --security"
        else
            finding "INFO" "No pending YUM security updates detected." "n/a"
        fi

    elif command -v pacman >/dev/null 2>&1; then
        info "Detected Pacman (Arch). Synchronising package databases…"
        pacman -Sy --noconfirm >/dev/null 2>&1 || \
            finding "LOW" "'pacman -Sy' failed." "Check /etc/pacman.conf and mirror list"
        local upd
        upd=$(pacman -Qu 2>/dev/null || true)
        if [[ -n "$upd" ]]; then
            local total
            total=$(wc -l <<<"$upd")
            finding "MEDIUM" "${total} package(s) outdated under Pacman." \
                    "pacman -Syu   # full system upgrade (Arch supports rolling releases only)"
            { echo "$upd"; } >> "$REPORT_TXT"
            { echo; echo '```'; echo "$upd"; echo '```'; } >> "$REPORT_MD"
        else
            finding "INFO" "All Pacman packages are up-to-date." "n/a"
        fi

    elif command -v zypper >/dev/null 2>&1; then
        info "Detected Zypper (openSUSE/SLES)."
        local patches
        patches=$(zypper -q list-patches 2>/dev/null || true)
        if grep -qi 'security' <<<"$patches"; then
            finding "HIGH" "Zypper reports pending security patches." \
                    "zypper patch --category security"
        else
            finding "INFO" "No pending Zypper security patches detected." "n/a"
        fi

    else
        finding "MEDIUM" "No supported package manager (apt/dnf/yum/pacman/zypper) found." \
                "Install or use the distribution-native package manager"
    fi

    # Kernel freshness sanity check (informational only)
    local running_kernel newest_kernel
    running_kernel="$(uname -r)"
    newest_kernel="$(ls -1t /boot/vmlinuz-* 2>/dev/null | head -n1 | sed 's|/boot/vmlinuz-||' || true)"
    if [[ -n "$newest_kernel" && "$running_kernel" != "$newest_kernel" ]]; then
        finding "MEDIUM" "Running kernel ${running_kernel} differs from newest installed kernel ${newest_kernel}." \
                "Reboot to activate the latest kernel: systemctl reboot"
    fi
}

# -----------------------------------------------------------------------------
# Reporting Engine — final summary
# -----------------------------------------------------------------------------
print_summary() {
    section "Audit Summary"

    local total=$((COUNT_CRITICAL + COUNT_HIGH + COUNT_MEDIUM + COUNT_LOW))
    local body
    body=$(cat <<EOF
Total findings (excluding INFO): ${total}
  Critical : ${COUNT_CRITICAL}
  High     : ${COUNT_HIGH}
  Medium   : ${COUNT_MEDIUM}
  Low      : ${COUNT_LOW}
  Info     : ${COUNT_INFO}
EOF
)

    echo -e "${C_BOLD}${body}${C_RESET}"
    {
        echo
        echo "$body"
    } >> "$REPORT_TXT"
    {
        echo
        echo "## Summary"
        echo
        echo "| Severity | Count |"
        echo "|----------|-------|"
        echo "| Critical | ${COUNT_CRITICAL} |"
        echo "| High     | ${COUNT_HIGH} |"
        echo "| Medium   | ${COUNT_MEDIUM} |"
        echo "| Low      | ${COUNT_LOW} |"
        echo "| Info     | ${COUNT_INFO} |"
    } >> "$REPORT_MD"

    echo
    echo -e "${C_GREEN}Reports written to:${C_RESET}"
    echo -e "  • ${REPORT_TXT}"
    echo -e "  • ${REPORT_MD}"
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
main() {
    require_root
    prepare_reports
    print_banner

    audit_network
    audit_filesystem
    audit_identity
    audit_software

    print_summary

    # Exit codes: 0 clean, 1 low/medium, 2 high, 3 critical
    if   (( COUNT_CRITICAL > 0 )); then exit 3
    elif (( COUNT_HIGH > 0 ));     then exit 2
    elif (( COUNT_MEDIUM > 0 || COUNT_LOW > 0 )); then exit 1
    else exit 0
    fi
}

main "$@"
