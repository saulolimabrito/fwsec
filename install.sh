#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# =============================================================================
# fwsec installer
# Supported systems: Debian 12+ | Ubuntu 22.04+ | RHEL-family 8+ (Rocky, Alma,
# RHEL, CentOS Stream, Oracle, Fedora 40+, Amazon Linux 2023) | openSUSE Leap
# 15.4+ / SLES 15+ | Arch | Alpine 3.17+ (OpenRC)
# =============================================================================
set -euo pipefail

FWSEC_VERSION="1.5.0"
REPO="saulolimabrito/fwsec"
INSTALL_DIR="/opt/fwsec"
CONFIG_DIR="/etc/fwsec"
BIN="/usr/local/bin/fwsec"
SERVICE="/etc/systemd/system/fwsec.service"
SERVICE_OPENRC="/etc/init.d/fwsec"
# BASH_SOURCE is unset when the script is piped (curl | bash) — fall back to $0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

# Colors
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'
BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { err "$*"; exit 1; }

# =============================================================================
# Initial checks
# =============================================================================
[[ "$(id -u)" -eq 0 ]] || die "Run as root: sudo bash install.sh"
if [[ -d /var/lib/fwsec/transactions ]] && \
   [[ -n "$(find /var/lib/fwsec/transactions -mindepth 2 -maxdepth 2 -name pending -print -quit)" ]]; then
    die "A safe apply is pending: confirm it or wait for rollback before installation/upgrade."
fi

# =============================================================================
# Downloads with curl or wget (minimal distros ship only one of them)
# =============================================================================
fetch() {
    # fetch URL [OUTPUT_FILE] [TIMEOUT_SECONDS]
    # Downloads a URL with curl when available, wget otherwise.
    # Without OUTPUT_FILE the body is written to stdout.
    local url="$1" out="${2:-}" timeout="${3:-60}"
    if command -v curl &>/dev/null; then
        if [[ -n "$out" ]]; then
            curl -fsSL --max-time "$timeout" -o "$out" "$url"
        else
            curl -fsSL --max-time "$timeout" "$url"
        fi
    elif command -v wget &>/dev/null; then
        if [[ -n "$out" ]]; then
            wget -q -T "$timeout" -O "$out" "$url"
        else
            wget -q -T "$timeout" -O- "$url"
        fi
    else
        return 127
    fi
}

# =============================================================================
# Detect an existing installation
# =============================================================================
check_already_installed() {
    local installed_version=""

    if command -v fwsec &>/dev/null; then
        installed_version=$(fwsec -v 2>/dev/null | grep '^fwsec' | awk '{print $2}' || true)
    fi

    if [[ -z "$installed_version" ]]; then
        return 0  # Not installed; continue
    fi

    echo ""
    echo -e "${BOLD}${YELLOW}============================================${NC}"
    echo -e "${BOLD}${YELLOW}  fwsec is already installed!${NC}"
    echo -e "${BOLD}${YELLOW}============================================${NC}"
    echo -e "  Installed version : ${BOLD}${installed_version}${NC}"
    echo -e "  Package version   : ${BOLD}${FWSEC_VERSION}${NC}"
    echo -e "  Executable        : $(command -v fwsec)"
    echo -e "  Config           : ${CONFIG_DIR}/"
    echo ""

    if [[ "$installed_version" == "$FWSEC_VERSION" ]]; then
        echo -e "${GREEN}[OK]${NC} The installed version matches this package. Nothing to do."
        echo ""
        echo -e "  Check the repository for a newer release : ${BOLD}bash install.sh --upgrade${NC}"
        echo -e "  Force reinstallation                      : ${BOLD}bash install.sh --force${NC}"
        echo ""
        exit 0
    else
        echo -e "${YELLOW}[!]${NC} A different version is installed."
        echo ""
        echo -e "  Upgrade from the repository : ${BOLD}bash install.sh --upgrade${NC}"
        echo -e "  Reinstall                   : ${BOLD}bash install.sh --force${NC}"
        echo ""
        exit 0
    fi
}

# =============================================================================
# Operating system detection (family via ID + ID_LIKE)
# =============================================================================
_version_ge() {
    # True when version $1 >= version $2 (dot-separated numeric comparison)
    awk -v v="$1" -v f="$2" 'BEGIN {
        split(v, a, "."); split(f, b, ".")
        for (i = 1; i <= 3; i++) {
            x = (i in a ? a[i] : 0); y = (i in b ? b[i] : 0)
            if (x > y) exit 0
            if (x < y) exit 1
        }
        exit 0
    }'
}

detect_os() {
    [[ -f /etc/os-release ]] || die "/etc/os-release was not found."
    . /etc/os-release

    OS_ID="${ID:-}"
    OS_VERSION="${VERSION_ID:-0}"
    OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
    OS_LIKE="${ID_LIKE:-}"

    local _family=""
    case "$OS_ID" in
        debian|ubuntu|linuxmint|raspbian|devuan|kali|pop)
            _family="debian" ;;
        rocky|almalinux|rhel|centos|ol|fedora|amzn|vzlinux|nobara|cloudlinux)
            _family="rhel" ;;
        sles|sles_sap|opensuse-leap|opensuse-tumbleweed|opensuse)
            _family="suse" ;;
        arch|manjaro|endeavouros|garuda|artix)
            _family="arch" ;;
        alpine)
            _family="alpine" ;;
        *)
            # Derivatives: fall back to ID_LIKE
            case "$OS_LIKE" in
                *debian*) _family="debian" ;;
                *rhel*|*fedora*|*centos*) _family="rhel" ;;
                *suse*|*sles*) _family="suse" ;;
                *arch*) _family="arch" ;;
                *alpine*) _family="alpine" ;;
            esac
            ;;
    esac
    [[ -n "$_family" ]] || die "Operating system '${PRETTY_NAME:-$OS_ID}' is not supported."
    OS_FAMILY="$_family"

    # Version floors — EOL releases are out of scope. Unknown derivatives of a
    # known family (own versioning scheme) are allowed with a warning.
    case "$OS_FAMILY" in
        debian)
            case "$OS_ID" in
                ubuntu)
                    _version_ge "$OS_VERSION" "22.04" || die "Ubuntu ${OS_VERSION} is not supported. Minimum version: 22.04 (EOL releases are out of scope)."
                    ;;
                pop|linuxmint)
                    # Derivatives use their own version numbering — warn, don't die
                    _version_ge "$OS_VERSION" "22" || warn "Linux Mint/Pop!_OS ${OS_VERSION} is untested; continuing."
                    ;;
                debian)
                    _version_ge "$OS_VERSION" "12" || die "Debian ${OS_VERSION} is not supported. Minimum version: 12 (EOL releases are out of scope)."
                    ;;
                *)
                    warn "Detected a Debian derivative (${PRETTY_NAME:-$OS_ID} ${OS_VERSION}); continuing untested."
                    ;;
            esac
            ok "Detected ${PRETTY_NAME:-$OS_ID} (debian family)."
            ;;
        rhel)
            if [[ "$OS_ID" == "amzn" ]]; then
                [[ "$OS_VERSION" == "2023" ]] || die "Amazon Linux ${OS_VERSION} is not supported (Amazon Linux 2 is EOL). Use Amazon Linux 2023."
            elif [[ "$OS_ID" == "centos" ]]; then
                [[ "$OS_MAJOR" -ge 9 ]] || die "CentOS ${OS_VERSION} is not supported. Use CentOS Stream 9/10 (CentOS 7 is EOL)."
            elif [[ "$OS_ID" == "fedora" ]]; then
                _version_ge "$OS_VERSION" "40" || die "Fedora ${OS_VERSION} is not supported. Minimum version: 40."
            else
                _version_ge "$OS_VERSION" "8" || die "${PRETTY_NAME:-$OS_ID} ${OS_VERSION} is not supported. Minimum version: 8."
            fi
            ok "Detected ${PRETTY_NAME:-$OS_ID} (rhel family)."
            ;;
        suse)
            _version_ge "$OS_VERSION" "15.4" || die "${PRETTY_NAME:-$OS_ID} ${OS_VERSION} is not supported. Minimum version: 15.4."
            ok "Detected ${PRETTY_NAME:-$OS_ID} (suse family)."
            ;;
        arch)
            ok "Detected ${PRETTY_NAME:-$OS_ID} (arch family, rolling release)."
            ;;
        alpine)
            _version_ge "$OS_VERSION" "3.17" || die "Alpine ${OS_VERSION} is not supported. Minimum version: 3.17."
            ok "Detected Alpine ${OS_VERSION}."
            ;;
    esac

    detect_pkg
}

# =============================================================================
# Package manager abstraction (apt | dnf | zypper | pacman | apk)
# =============================================================================
detect_pkg() {
    case "$OS_FAMILY" in
        debian) PKG="apt" ;;
        rhel)   PKG="dnf" ;;
        suse)   PKG="zypper" ;;
        arch)   PKG="pacman" ;;
        alpine) PKG="apk" ;;
        *)      PKG="" ;;
    esac
}

pkg_refresh() {
    case "$PKG" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || \
                warn "apt-get update reported errors from an unrelated repository; continuing." ;;
        zypper) zypper --non-interactive --quiet refresh 2>/dev/null || true ;;
        *)      true ;;  # dnf/pacman/apk refresh metadata automatically
    esac
}

pkg_install() {
    case "$PKG" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" 2>/dev/null ;;
        dnf)    dnf install -y -q "$@" 2>/dev/null || \
                yum install -y -q "$@" 2>/dev/null || \
                microdnf install -q "$@" 2>/dev/null ;;
        zypper) zypper --quiet --non-interactive install "$@" 2>/dev/null ;;
        pacman) pacman -S --noconfirm --needed "$@" 2>/dev/null ;;
        apk)    apk add --no-cache --quiet "$@" 2>/dev/null ;;
        *)      return 1 ;;
    esac
}

# =============================================================================
# Init system abstraction (systemd | OpenRC | none)
# =============================================================================
detect_init() {
    if command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="none"
    fi
}

svc_enable() {
    case "$INIT_SYSTEM" in
        systemd) systemctl enable "$@" 2>/dev/null || true ;;
        openrc)  local s; for s in "$@"; do rc-update add "$s" default 2>/dev/null || true; done ;;
        *)       true ;;
    esac
}

svc_start() {
    case "$INIT_SYSTEM" in
        systemd) systemctl start "$@" 2>/dev/null || true ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" start 2>/dev/null || true; done ;;
        *)       true ;;
    esac
}

svc_restart() {
    case "$INIT_SYSTEM" in
        systemd) systemctl restart "$@" 2>/dev/null || true ;;
        openrc)  local s; for s in "$@"; do rc-service "$s" restart 2>/dev/null || true; done ;;
        *)       true ;;
    esac
}

# =============================================================================
# Base dependency installation
# =============================================================================
install_base_deps() {
    info "Installing base dependencies (${PKG})..."
    pkg_refresh
    case "$OS_FAMILY" in
        debian) pkg_install curl tar gzip ca-certificates gnupg nftables iproute2 python3 || true ;;
        rhel)   pkg_install curl tar gzip ca-certificates gnupg nftables iproute python3 || true ;;
        suse)   pkg_install curl tar gzip ca-certificates gnupg nftables iproute2 python3 || true ;;
        arch)   pkg_install curl tar gzip ca-certificates gnupg nftables iproute2 python || true ;;
        alpine) pkg_install bash curl tar gzip ca-certificates gnupg nftables iproute2 python3 || true ;;
    esac
    command -v nft &>/dev/null || die "nftables could not be installed ('nft' binary missing)."
    command -v tar &>/dev/null || die "tar could not be installed."
    ok "Base dependencies installed."
}

# =============================================================================
# Python 3.8+ (distro Python when possible; uv-managed standalone as fallback)
# =============================================================================
python_ok() {
    # True when $1 is a Python interpreter with version >= 3.8
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

find_python() {
    local py
    for py in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$py" &>/dev/null && python_ok "$(command -v "$py")"; then
            PYTHON=$(command -v "$py")
            return 0
        fi
    done
    return 1
}

_python_found() {
    PY_VER=$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    ok "Found Python ${PY_VER} at ${PYTHON}."
}

install_python() {
    info "Looking for Python 3.8+..."

    PYTHON=""
    if find_python; then
        _python_found
        return
    fi

    info "No Python 3.8+ found. Installing a newer Python from the distribution..."
    case "$OS_FAMILY" in
        debian)
            pkg_install python3.12 python3.12-venv || \
            pkg_install python3.11 python3.11-venv || \
            true
            ;;
        rhel)
            if [[ "$OS_MAJOR" == "8" ]]; then
                # Rocky/RHEL 8 provide Python 3.11 through AppStream
                pkg_install python3.11 python3.11-pip || {
                    pkg_install epel-release || true
                    pkg_install python3.11 || true
                }
            else
                pkg_install python3.11 python3.11-pip || \
                pkg_install python3.12 python3.12-pip || \
                pkg_install python3.13 python3.13-pip || \
                true
            fi
            ;;
        suse)   pkg_install python311 || pkg_install python312 || true ;;
        arch)   pkg_install python || true ;;
        alpine) pkg_install python3 || true ;;
    esac

    if find_python; then
        _python_found
        return
    fi

    # Last resort: uv provisions a standalone CPython 3.11 (glibc or musl) on
    # its own — see install_fwsec_package(). This keeps the installer working
    # on distributions whose native Python is older than the floor (e.g. SLES).
    warn "No distro Python 3.8+ available. uv will provision a standalone Python 3.11."
    PYTHON=""
}

# =============================================================================
# uv package and virtual environment manager
# =============================================================================
install_uv() {
    if command -v uv &>/dev/null; then
        ok "uv is already installed: $(uv --version)."
        return
    fi

    # Distribution packages when available (Arch extra, Alpine community)
    pkg_install uv || true
    if command -v uv &>/dev/null; then
        ok "Installed uv: $(uv --version)."
        return
    fi

    info "Installing uv (standalone installer)..."
    fetch "https://astral.sh/uv/install.sh" | env HOME=/root sh >/dev/null 2>&1 || true
    export PATH="/root/.local/bin:${HOME}/.local/bin:$PATH"

    command -v uv &>/dev/null || die "uv was not found after installation."
    ok "Installed uv: $(uv --version)."
}

# =============================================================================
# CrowdSec (optional: --no-crowdsec skips it; failures never abort the install)
# =============================================================================
install_crowdsec() {
    if [[ "$NO_CROWDSEC" -eq 1 ]]; then
        warn "CrowdSec integration disabled (--no-crowdsec)."
        return 0
    fi

    local have_crowdsec=0 have_bouncer=0

    if command -v crowdsec &>/dev/null; then
        ok "CrowdSec is already installed."
        have_crowdsec=1
    else
        info "Installing CrowdSec..."
        case "$OS_FAMILY" in
            debian)
                if fetch "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh" | bash >/dev/null 2>&1; then
                    pkg_install crowdsec && have_crowdsec=1
                fi
                ;;
            rhel|suse)
                if fetch "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh" | bash >/dev/null 2>&1; then
                    pkg_install crowdsec && have_crowdsec=1
                fi
                ;;
            alpine)
                if pkg_install crowdsec; then
                    have_crowdsec=1
                fi
                ;;
            arch)
                warn "CrowdSec on Arch is available only through the AUR. Install it manually later (e.g. yay -S crowdsec crowdsec-firewall-bouncer-nftables)."
                ;;
        esac
        if [[ "$have_crowdsec" -eq 1 ]]; then
            ok "CrowdSec installed."
        else
            warn "CrowdSec was not installed automatically. fwsec works fully without it; you can add it later."
        fi
    fi

    if command -v crowdsec-firewall-bouncer &>/dev/null || \
       [[ -f /usr/bin/crowdsec-firewall-bouncer ]]; then
        ok "The CrowdSec firewall bouncer is already installed."
        have_bouncer=1
    elif [[ "$have_crowdsec" -eq 1 ]]; then
        info "Installing the CrowdSec nftables bouncer..."
        case "$OS_FAMILY" in
            debian|rhel|suse)
                if pkg_install crowdsec-firewall-bouncer-nftables; then
                    have_bouncer=1
                fi
                ;;
            alpine)
                if pkg_install crowdsec-firewall-bouncer-nftables || pkg_install crowdsec-firewall-bouncer; then
                    have_bouncer=1
                fi
                ;;
        esac
        if [[ "$have_bouncer" -eq 1 ]]; then
            ok "CrowdSec nftables bouncer installed."
        else
            warn "The nftables bouncer was not installed automatically; CrowdSec bans will not reach nftables until it is."
        fi
    fi

    if [[ "$have_crowdsec" -eq 1 ]]; then
        svc_enable crowdsec
        svc_start crowdsec
    fi

    _configure_crowdsec_bouncer
}

_configure_crowdsec_bouncer() {
    local bouncer_conf="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    [[ -f "$bouncer_conf" ]] || { warn "Bouncer configuration was not found."; return 0; }

    # Generate a key only when the bouncer does not have a valid one
    if grep -qE '^api_key:\s*$' "$bouncer_conf" 2>/dev/null || \
       ! grep -qE '^api_key:\s+\S+' "$bouncer_conf" 2>/dev/null; then

        if cscli bouncers list 2>/dev/null | grep -q "nftables-bouncer"; then
            cscli bouncers delete nftables-bouncer 2>/dev/null || true
        fi
        local api_key
        api_key=$(cscli bouncers add nftables-bouncer 2>&1 | \
                  grep -v '^$' | grep -v 'API key' | grep -v 'Please' | tr -d ' ')

        cat > "$bouncer_conf" << BCEOF
mode: nftables
update_frequency: 10s
log_mode: file
log_dir: /var/log/crowdsec/
log_level: info

api_url: http://127.0.0.1:8080/
api_key: ${api_key}

disable_ipv6: false
deny_action: DROP
deny_log: false

supported_decisions_types:
  - ban

nftables:
  ipv4:
    enabled: true
    set-only: true
    table: filter
    chain: input
    set: crowdsec-blacklists
  ipv6:
    enabled: true
    set-only: true
    table: filter
    chain: input
    set: crowdsec6-blacklists
BCEOF
    fi

    svc_enable crowdsec-firewall-bouncer
    svc_restart crowdsec-firewall-bouncer
    ok "CrowdSec bouncer configured."
}

# =============================================================================
# SELinux (RHEL family)
# =============================================================================
configure_selinux() {
    [[ "$OS_FAMILY" == "rhel" ]] || return 0
    command -v sestatus &>/dev/null || return 0
    sestatus 2>/dev/null | grep -q "enabled" || return 0

    info "Configuring SELinux for nftables and Python..."

    if ! command -v semanage &>/dev/null; then
        pkg_install policycoreutils-python-utils || true
    fi

    # Register every effective SSH port (sshd may listen on several)
    local ssh_port
    while read -r ssh_port; do
        [[ -n "$ssh_port" && "$ssh_port" != "22" ]] || continue
        semanage port -a -t ssh_port_t -p tcp "$ssh_port" 2>/dev/null || \
        semanage port -m -t ssh_port_t -p tcp "$ssh_port" 2>/dev/null || true
    done < <(_detect_ssh_ports_bash)

    ok "SELinux configured."
}

# =============================================================================
# AppArmor (Debian/Ubuntu/SUSE)
# =============================================================================
configure_apparmor() {
    command -v aa-status &>/dev/null || return 0
    aa-status --enabled 2>/dev/null || return 0

    info "Checking AppArmor..."
    # nftables and fwsec do not require a special profile. Check only for an
    # enforcing profile that might block Python.
    if aa-status 2>/dev/null | grep -q "python"; then
        warn "AppArmor has a Python profile. Check it for conflicts."
    else
        ok "AppArmor: no conflicting profile found."
    fi
}

# === fwsec firewall migration (BEGIN) =======================================
# Detect an existing firewall (CSF / UFW / firewalld), inherit its rules into
# /etc/fwsec BEFORE anything is stopped, replace it only once fwsec is live,
# and report exactly what was — and was not — inherited.
# =============================================================================
CSF_DIR="${CSF_DIR:-/etc/csf}"
UFW_BIN="${UFW_BIN:-ufw}"
MIGRATION_SOURCES=""
MIGRATION_STAGED=0
MIGRATION_BACKUP=""
MIGRATION_SUMMARY=()

detect_migration_source() {
    MIGRATION_SOURCES=""
    if [[ -f "${CSF_DIR}/csf.conf" ]]; then
        MIGRATION_SOURCES="csf"
    fi
    if command -v "$UFW_BIN" &>/dev/null && \
       { "$UFW_BIN" status 2>/dev/null | grep -q "^Status: active" || \
         grep -qE '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; }; then
        MIGRATION_SOURCES="${MIGRATION_SOURCES:+${MIGRATION_SOURCES} }ufw"
    fi
    if command -v firewall-cmd &>/dev/null && \
       { firewall-cmd --state 2>/dev/null | grep -q running || \
         systemctl is-enabled --quiet firewalld 2>/dev/null; }; then
        MIGRATION_SOURCES="${MIGRATION_SOURCES:+${MIGRATION_SOURCES} }firewalld"
    fi
    if [[ -n "$MIGRATION_SOURCES" ]]; then
        ok "Existing firewall detected: ${MIGRATION_SOURCES} — rules can be inherited."
    fi
}

migration_backup() {
    MIGRATION_BACKUP=$(mktemp -d "${FWSEC_BACKUP_ROOT:-/root}/fwsec-migration-$(date +%Y%m%d%H%M%S).XXXXXX")
    chmod 700 "$MIGRATION_BACKUP"
    if [[ "$MIGRATION_SOURCES" == *csf* ]]; then
        tar czf "$MIGRATION_BACKUP/csf-etc.tar.gz" "$CSF_DIR" 2>/dev/null || die "CSF backup failed; migration refused."
    fi
    iptables-save > "$MIGRATION_BACKUP/iptables.rules" || die "IPv4 backup failed; migration refused."
    ip6tables-save > "$MIGRATION_BACKUP/ip6tables.rules" || die "IPv6 backup failed; migration refused."
    nft -s list ruleset > "$MIGRATION_BACKUP/nftables.ruleset" || die "nft backup failed; migration refused."
    chmod 600 "${MIGRATION_BACKUP}"/*
    ok "Pre-migration backup: ${MIGRATION_BACKUP}"
}

remove_migrated_firewall() {
    [[ "$MIGRATION_STAGED" -eq 1 ]] || return 0
    MIGRATION_SUMMARY+=("Old firewall   : kept active during the trial; NOT uninstalled")
    MIGRATION_SUMMARY+=("Next           : confirm from a NEW SSH session, then fwsec --migration-finalize")
}

run_migration_stage() {
    if [[ -z "$MIGRATION_SOURCES" ]]; then
        if ! command -v fwsec &>/dev/null; then
            if iptables-save 2>/dev/null | grep '^-A ' >/dev/null; then
                die "Unidentified existing iptables rules: refuse automatic replacement."
            fi
            if nft list ruleset 2>/dev/null | grep -E 'hook (input|output|forward)' >/dev/null; then
                die "Unidentified existing nftables hooks: inspect ownership before installation."
            fi
        fi
        return 0
    fi
    [[ "$MIGRATION_SOURCES" != *" "* ]] || die "Multiple active firewalls: migration refused, none disabled."
    [[ ! -f "${CONFIG_DIR}/fwsec.conf" ]] || die "An fwsec config already exists: refuse implicit merging or old-firewall removal."
    migration_backup
    local report="${MIGRATION_BACKUP}/migration-plan.json"
    local -a python_cmd
    if [[ -n "$PYTHON" ]]; then
        python_cmd=("$PYTHON")
    else
        python_cmd=(uv run --no-project --python 3.11)
    fi
    if ! "${python_cmd[@]}" "${SCRIPT_DIR}/src/fwsec/migration.py" \
            --source "$MIGRATION_SOURCES" --output "$report" --approve "${MIGRATION_APPROVE:-}"; then
        die "Migration needs review or has unsupported rules. Report: ${report}. No old firewall was stopped."
    fi
    mkdir -p "$CONFIG_DIR"
    cp "${SCRIPT_DIR}/etc/fwsec/fwsec.conf" "${CONFIG_DIR}/fwsec.conf"
    cp "$report" "${CONFIG_DIR}/inherited.json"
    set_conf_value "INHERITED_POLICY" "${CONFIG_DIR}/inherited.json"
    chmod 750 "$CONFIG_DIR"
    chmod 600 "${CONFIG_DIR}/inherited.json" "${CONFIG_DIR}/fwsec.conf"
    MIGRATION_STAGED=1
    MIGRATION_SUMMARY+=("Source         : ${MIGRATION_SOURCES} (exact ordered live IPv4/IPv6 policies)")
    MIGRATION_SUMMARY+=("Full report    : ${report}; fwsec --migration-report")
    MIGRATION_SUMMARY+=("Output policy  : inherited, not silently changed to ACCEPT")
}

migration_report() {
    [[ "$MIGRATION_STAGED" -eq 1 && "${#MIGRATION_SUMMARY[@]}" -gt 0 ]] || return 0
    echo ""
    echo -e "${BOLD}${CYAN}  Firewall migration report${NC}"
    echo -e "${BOLD}${CYAN}  ---------------------------------------${NC}"
    local line
    for line in "${MIGRATION_SUMMARY[@]}"; do
        echo -e "  ${line}"
    done
    echo -e "${BOLD}${CYAN}  ---------------------------------------${NC}"
}
# === fwsec firewall migration (END) =========================================

# =============================================================================
# Disable competing firewalls
# =============================================================================
disable_competing_firewalls() {
    # Destructive service stop/uninstall scripts can flush shared rulesets.
    # A staged migration keeps its source active until safe confirmation.
    if [[ "$MIGRATION_STAGED" -eq 1 ]]; then
        info "Existing firewall retained during the safe-apply trial."
        return 0
    fi
    if [[ -n "$MIGRATION_SOURCES" ]]; then
        die "Unstaged source firewall: refuse to disable anything."
    fi
    return 0
}

# =============================================================================
# Install the fwsec package in a virtual environment
# =============================================================================
install_fwsec_package() {
    info "Creating a virtual environment at ${INSTALL_DIR}..."
    export PATH="/root/.local/bin:${HOME}/.local/bin:$PATH"

    rm -rf "${INSTALL_DIR}/venv"
    if [[ -n "$PYTHON" ]]; then
        uv venv "${INSTALL_DIR}/venv" --python "$PYTHON" --quiet
    else
        # uv downloads a standalone CPython (glibc or musl) when no system
        # Python satisfies the floor — works on any distribution.
        uv venv "${INSTALL_DIR}/venv" --python 3.11 --quiet
    fi

    info "Installing fwsec ${FWSEC_VERSION}..."
    uv pip install --quiet "${SCRIPT_DIR}" \
        --python "${INSTALL_DIR}/venv/bin/python"

    ok "fwsec installed in the virtual environment."
}

# =============================================================================
# Configuration files
# =============================================================================
install_config_files() {
    info "Installing configuration files in ${CONFIG_DIR}..."
    mkdir -p "$CONFIG_DIR"

    for f in fwsec.conf fwsec.allow fwsec.deny fwsec.ignore; do
        local src="${SCRIPT_DIR}/etc/fwsec/${f}"
        local dst="${CONFIG_DIR}/${f}"
        if [[ -f "$dst" ]]; then
            ok "  ${f}: preserved (already exists)."
        elif [[ -f "$src" ]]; then
            cp "$src" "$dst"
            if [[ "$f" == "fwsec.conf" ]]; then CONF_IS_NEW=1; fi
            ok "  ${f}: installed."
        else
            warn "  ${f}: source file was not found at ${src}."
        fi
    done

    chmod 750 "$CONFIG_DIR"
    chmod 640 "${CONFIG_DIR}"/*.conf \
              "${CONFIG_DIR}"/*.allow \
              "${CONFIG_DIR}"/*.deny \
              "${CONFIG_DIR}"/*.ignore 2>/dev/null || true
}

# =============================================================================
# Wrapper /usr/local/bin/fwsec
# =============================================================================
install_binary() {
    info "Installing the executable at ${BIN}..."
    local runtime="${FWSEC_RUNTIME:-${INSTALL_DIR}/venv}" wrapper
    mkdir -p "$(dirname "$BIN")" || return 1
    [[ ! -L "$BIN" && -x "${runtime}/bin/python" ]] || return 1
    wrapper=$(mktemp "${BIN}.XXXXXX") || return 1
    if ! cat > "$wrapper" << WRAPPER
#!/usr/bin/env bash
exec "${runtime}/bin/python" -m fwsec "\$@"
WRAPPER
    then
        rm -f "$wrapper"
        return 1
    fi
    chmod 755 "$wrapper" && mv -f "$wrapper" "$BIN" || {
        rm -f "$wrapper"
        return 1
    }
    ok "Executable installed: ${BIN}."
}

# =============================================================================
# Boot service (systemd unit | OpenRC script)
# =============================================================================
install_service() {
    case "$INIT_SYSTEM" in
        systemd) _install_service_systemd ;;
        openrc)  _install_service_openrc ;;
        *)       warn "No systemd or OpenRC detected: skipping the boot service."
                 warn "Start fwsec manually after boot: fwsec -s"
                 return 0 ;;
    esac
}

_install_service_systemd() {
    info "Installing the fwsec.service systemd unit..."
    cat > "$SERVICE" << UNIT
[Unit]
Description=fwsec - nftables + CrowdSec firewall manager
Documentation=https://github.com/saulolimabrito/fwsec
After=network.target nftables.service crowdsec.service crowdsec-firewall-bouncer.service
Wants=crowdsec.service crowdsec-firewall-bouncer.service

[Service]
Type=oneshot
ExecStart=${BIN} -s
ExecStop=${BIN} -f
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload 2>/dev/null || true
    if [[ "$MIGRATION_STAGED" -ne 1 ]]; then
        systemctl enable fwsec.service 2>/dev/null || true
    fi
    ok "fwsec.service installed (boot enable is deferred during migration trials)."
}

_install_service_openrc() {
    info "Installing the fwsec OpenRC service..."
    cat > "$SERVICE_OPENRC" << UNIT
#!/sbin/openrc-run

description="fwsec - nftables + CrowdSec firewall manager"

command="${BIN}"

depend() {
    need net
    after nftables crowdsec
}

start() {
    ebegin "Starting fwsec firewall"
    "${BIN}" -s
    eend \$?
}

stop() {
    ebegin "Stopping fwsec firewall"
    "${BIN}" -f
    eend \$?
}
UNIT
    chmod +x "$SERVICE_OPENRC"
    [[ "$MIGRATION_STAGED" -eq 1 ]] || rc-update add fwsec default 2>/dev/null || true
    ok "OpenRC service installed and added to the default runlevel."
}

# =============================================================================
# Ensure the nftables service is enabled at boot
# =============================================================================
enable_nftables() {
    [[ "$MIGRATION_STAGED" -eq 0 ]] || return 0
    case "$INIT_SYSTEM" in
        systemd) systemctl enable nftables 2>/dev/null || true ;;
        openrc)  rc-update add nftables boot 2>/dev/null || true ;;
        *)       return 0 ;;
    esac
    ok "nftables enabled at boot."
}

# =============================================================================
# Post-installation check
# =============================================================================
post_install_check() {
    info "Checking the installation..."
    local issues=0

    command -v fwsec &>/dev/null          && ok "  fwsec: OK" || { err "  fwsec: NOT FOUND"; ((issues++)); }
    [[ -f "${CONFIG_DIR}/fwsec.conf" ]]   && ok "  fwsec.conf: OK" || { err "  fwsec.conf: NOT FOUND"; ((issues++)); }
    command -v nft &>/dev/null            && ok "  nft: OK" || { warn "  nft: not found"; }
    command -v crowdsec &>/dev/null       && ok "  crowdsec: OK" || { warn "  crowdsec: not found"; }
    command -v cscli &>/dev/null          && ok "  cscli: OK" || { warn "  cscli: not found"; }

    case "$INIT_SYSTEM" in
        systemd)
            if systemctl is-enabled fwsec &>/dev/null; then
                ok "  fwsec.service: enabled"
            else
                warn "  fwsec.service: not enabled"
            fi
            ;;
        openrc)
            if rc-update show default 2>/dev/null | grep -q fwsec; then
                ok "  fwsec (OpenRC): added to the default runlevel"
            else
                warn "  fwsec (OpenRC): not in the default runlevel"
            fi
            ;;
        *)
            warn "  boot service: not installed (no systemd/OpenRC)"
            ;;
    esac

    if [[ "$INIT_SYSTEM" == "systemd" ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
        err "  firewalld: STILL ACTIVE (conflicts with fwsec)"; ((issues++))
    else
        ok "  firewalld: inactive"
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
        err "  ufw: STILL ACTIVE (conflicts with fwsec)"; ((issues++))
    else
        ok "  ufw: inactive"
    fi

    return $issues
}

# =============================================================================
# Upgrade from the GitHub repository
# =============================================================================
version_gt() {
    # True when $1 is strictly newer than $2 (semantic sort)
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

fetch_remote_version() {
    local v=""
    # Prefer the latest published release tag
    v=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" "" 15 2>/dev/null \
        | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 \
        | sed -E 's/.*"v?([0-9][^"]*)"$/\1/') || true
    # Fallback: version declared in pyproject.toml on main
    if [[ -z "$v" ]]; then
        v=$(fetch "https://raw.githubusercontent.com/${REPO}/main/pyproject.toml" "" 15 2>/dev/null \
            | grep -E '^version[[:space:]]*=' | head -1 \
            | sed -E 's/.*"([^"]+)".*/\1/') || true
    fi
    echo "$v"
}

download_source() {
    # Downloads and extracts the source for version $1; echoes the source dir.
    local ver="$1" tmp dir
    tmp=$(mktemp -d /tmp/fwsec-upgrade.XXXXXX)
    if ! fetch "https://github.com/${REPO}/archive/refs/tags/v${ver}.tar.gz" \
            "${tmp}/src.tar.gz" 60 2>/dev/null; then
        # No tag for this version — fall back to the main branch tarball
        fetch "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" \
            "${tmp}/src.tar.gz" 60 \
            || { rm -rf "$tmp"; return 1; }
    fi
    tar -xzf "${tmp}/src.tar.gz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    dir=$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -1)
    [[ -n "$dir" && -f "$dir/pyproject.toml" ]] || { rm -rf "$tmp"; return 1; }
    echo "$dir"
}

bootstrap_source() {
    # When install.sh runs standalone (curl | bash) the source tree is not
    # next to it — download the latest release so the install can proceed.
    if [[ -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
        return 0
    fi

    info "Standalone mode: downloading the fwsec source (no git required)..."
    command -v curl &>/dev/null || command -v wget &>/dev/null || \
        die "curl or wget is required for the standalone install."
    command -v tar  &>/dev/null || die "tar is required for the standalone install."

    local ver src_dir
    ver=$(fetch_remote_version)
    src_dir=$(download_source "${ver:-main}") || die "Could not download the fwsec source from ${REPO}."
    SCRIPT_DIR="$src_dir"
    FWSEC_VERSION=$(grep -E '^version[[:space:]]*=' "${SCRIPT_DIR}/pyproject.toml" \
                    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    ok "fwsec ${FWSEC_VERSION} source ready at ${SCRIPT_DIR}."
}

run_upgrade() {
    command -v curl &>/dev/null || command -v wget &>/dev/null || \
        die "curl or wget is required for --upgrade."

    local installed=""
    if command -v fwsec &>/dev/null; then
        installed=$(fwsec -v 2>/dev/null | grep '^fwsec' | awk '{print $2}' || true)
    fi
    [[ -n "$installed" ]] || die "fwsec is not installed. Run: sudo bash install.sh"

    info "Installed version : ${installed}"
    info "Checking the repository (${REPO}) for the latest version..."
    local remote
    remote=$(fetch_remote_version)
    [[ -n "$remote" ]] || die "Could not query the latest version. Check network connectivity."
    info "Repository version: ${remote}"

    if ! version_gt "$remote" "$installed"; then
        ok "fwsec ${installed} is already up to date. Nothing to do."
        exit 0
    fi

    echo ""
    info "New version available. Upgrading fwsec ${installed} → ${remote}..."
    local src_dir
    src_dir=$(download_source "$remote") || die "Failed to download fwsec ${remote} from the repository."
    SCRIPT_DIR="$src_dir"
    FWSEC_VERSION="$remote"

    install_python
    install_uv
    [[ "$(command -v fwsec)" == "$BIN" ]] || die "Unexpected fwsec executable path; review before upgrading."
    local candidate runtime ident
    mkdir -p "${INSTALL_DIR}/releases"
    candidate=$(mktemp -d "${INSTALL_DIR}/releases/${remote}.XXXXXX")
    chmod 755 "$candidate"
    runtime="${candidate}/venv"
    uv venv "$runtime" --python "${PYTHON:-3.11}" --quiet
    uv pip install --quiet "$SCRIPT_DIR" --python "${runtime}/bin/python"
    [[ "$("${runtime}/bin/python" -c 'from fwsec import __version__; print(__version__)')" == "$remote" ]] || \
        die "Candidate version does not match the release; installed code is unchanged."

    info "Validating ownership/legacy equivalence before activating the new package..."
    "${runtime}/bin/fwsec" --upgrade-apply --upgrade-state "${candidate}/transaction-id" || \
        die "Candidate refused; previous executable and rules are retained (or watchdog rollback is armed)."
    ident=$(cat "${candidate}/transaction-id")
    if ! "${runtime}/bin/fwsec" --upgrade-activate "$ident"; then
        "${runtime}/bin/fwsec" --rollback "$ident" || warn "Rollback worker remains armed; inspect transaction logs."
        die "Upgrade confirmation failed; previous code/rules restored or rollback remains armed."
    fi
    rm -rf "$(dirname "$src_dir")"
    ok "fwsec upgraded to ${remote}. Configuration files were preserved."
    fwsec -v
    echo ""
    exit 0
}

# =============================================================================
# Effective SSH ports (bash-side; mirrors fwsec's _detect_ssh_ports)
# =============================================================================
_detect_ssh_ports_bash() {
    # Prints the effective SSH listening ports, one per line (default: 22).
    # sshd -T reflects the effective configuration (main file + drop-ins);
    # config parsing is the fallback. Opening a superset is always safe —
    # missing a port locks you out of the server.
    local sshd_bin ports=""

    sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
    if [[ -x "$sshd_bin" ]]; then
        ports=$("$sshd_bin" -T 2>/dev/null | awk '/^port /{print $2}' || true)
    fi

    if [[ -z "$ports" ]]; then
        ports=$({ grep -hE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null || true; \
                  grep -hE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true; } \
                | awk '{print $2}' || true)
    fi

    ports=$(printf '%s\n' $ports | sort -un | grep -v '^$' || true)
    [[ -n "$ports" ]] || ports="22"
    echo "$ports"
}

# =============================================================================
# Hosting control panel detection (cPanel / Plesk)
# =============================================================================
# Recommended service profiles based on the panels' official firewall requirements.
# Administrators should remove ports for services they do not use.
# SSH is detected separately and always kept open.
CPANEL_TCP_IN="20,21,25,53,80,110,143,443,465,587,993,995,2077,2078,2079,2080,2082,2083,2086,2087,2095,2096"
CPANEL_TCP_OUT="20,21,25,37,43,53,80,110,113,443,465,587,873,993,995,2086,2087,2089,2703"
CPANEL_UDP_IN="53,853"
CPANEL_UDP_OUT="53,113,123,873,6277,24441"

PLESK_TCP_IN="21,25,53,80,110,143,443,465,587,990,993,995,8443,8447,8880"
PLESK_TCP_OUT="25,37,43,53,80,113,443,465,587,993,995,8443"
PLESK_UDP_IN="53,443,8443"
PLESK_UDP_OUT="53,123"

detect_panel() {
    PANEL=""
    PANEL_NAME=""
    if [[ -d /usr/local/cpanel ]] || command -v whmapi1 &>/dev/null; then
        PANEL="cpanel"; PANEL_NAME="cPanel/WHM"
    elif [[ -f /usr/local/psa/version || -f /opt/psa/version ]] || command -v plesk &>/dev/null; then
        PANEL="plesk"; PANEL_NAME="Plesk"
    fi
}

_apply_panel_profile() {
    # Returns 0 when the panel profile was applied (generic prompts skipped);
    # returns 1 when the user prefers to open ports on demand.
    local tcp_in tcp_out udp_in udp_out
    case "$PANEL" in
        cpanel) tcp_in="$CPANEL_TCP_IN"; tcp_out="$CPANEL_TCP_OUT"
                udp_in="$CPANEL_UDP_IN"; udp_out="$CPANEL_UDP_OUT" ;;
        plesk)  tcp_in="$PLESK_TCP_IN";  tcp_out="$PLESK_TCP_OUT"
                udp_in="$PLESK_UDP_IN";  udp_out="$PLESK_UDP_OUT" ;;
        *)      return 1 ;;
    esac

    echo ""
    ok "${PANEL_NAME} detected on this server."
    info "fwsec can apply the recommended ${PANEL_NAME} service-port profile:"
    echo "      TCP IN : ${tcp_in}"
    echo "      TCP OUT: ${tcp_out}"
    echo "      UDP IN : ${udp_in}"
    echo "      UDP OUT: ${udp_out}"
    info "Or start minimal and open ports on demand later"
    info "(edit /etc/fwsec/fwsec.conf and run: fwsec -r)."
    warn "Remove ports for panel services that are disabled or not used."

    if [[ -t 0 ]]; then
        local answer=""
        read -r -p "$(echo -e "  ${BOLD}Apply the recommended ${PANEL_NAME} port profile?${NC} [Y/n]: ")" answer || answer=""
        if [[ "${answer,,}" == "n" || "${answer,,}" == "no" ]]; then
            info "Keeping minimal ports — choose them in the next step (open on demand later)."
            return 1
        fi
    else
        info "Non-interactive shell: applying the ${PANEL_NAME} profile so the panel keeps working."
    fi

    set_conf_value "TCP_IN"  "$tcp_in"
    set_conf_value "TCP_OUT" "$tcp_out"
    set_conf_value "UDP_IN"  "$udp_in"
    set_conf_value "UDP_OUT" "$udp_out"
    ok "${PANEL_NAME} port profile applied to ${CONFIG_DIR}/fwsec.conf."
    ok "The SSH port is detected automatically and stays open."
    return 0
}

# =============================================================================
# Interactive port configuration
# =============================================================================
DEFAULT_TCP_OUT="80,443,53,853"   # HTTP, HTTPS, DNS, DNS-over-TLS
DEFAULT_UDP_OUT="53,123,443"      # DNS, NTP, QUIC/HTTP3

_list_listeners() {
    # $1 = t|u — prints "port service" pairs, skipping loopback-only listeners.
    # Uses ss (iproute2); falls back to netstat (busybox/bsd variant) when ss
    # is unavailable or produces no output.
    local out=""
    if command -v ss &>/dev/null; then
        out=$(ss -H "-${1}lnp" 2>/dev/null | awk '
        {
            n = split($4, a, ":"); port = a[n]
            addr = substr($4, 1, length($4) - length(port) - 1)
            if (addr ~ /^127\./ || addr == "[::1]") next
            if (port !~ /^[0-9]+$/) next
            svc = "-"
            if (match($0, /\(\("[^"]+"/)) svc = substr($0, RSTART + 3, RLENGTH - 4)
            if (!seen[port]++) print port, svc
        }' | sort -n || true)
    fi
    if [[ -z "$out" ]] && command -v netstat &>/dev/null; then
        if [[ "$1" == "t" ]]; then
            out=$(netstat -tln 2>/dev/null | awk '
            $1 ~ /^tcp/ && $6 == "LISTEN" {
                n = split($4, a, ":"); port = a[n]
                addr = substr($4, 1, length($4) - length(port) - 1)
                if (addr ~ /^127\./ || addr == "[::1]") next
                if (port !~ /^[0-9]+$/) next
                if (!seen[port]++) print port, "-"
            }' | sort -n || true)
        else
            out=$(netstat -uln 2>/dev/null | awk '
            $1 ~ /^udp/ {
                n = split($4, a, ":"); port = a[n]
                addr = substr($4, 1, length($4) - length(port) - 1)
                if (addr ~ /^127\./ || addr == "[::1]") next
                if (port !~ /^[0-9]+$/) next
                if (!seen[port]++) print port, "-"
            }' | sort -n || true)
        fi
    fi
    if [[ -z "$out" ]]; then
        warn "Could not list listening ports (ss/netstat unavailable or empty)." >&2
    fi
    printf '%s\n' "$out"
}

set_conf_value() {
    local key="$1" value="$2"
    sed -i -E "s|^(${key}[[:space:]]*=).*|\\1 ${value}|" "${CONFIG_DIR}/fwsec.conf"
}

_prompt_ports() {
    # $1 = label, $2 = suggested default — echoes the chosen list (may be empty)
    local input=""
    read -r -p "$(echo -e "  ${BOLD}$1${NC} [${2:-none}]: ")" input || input=""
    input="${input//[[:space:]]/}"
    [[ -z "$input" ]] && input="$2"
    if [[ "$input" == "none" ]]; then
        echo ""
        return 0
    fi
    if [[ -n "$input" && ! "$input" =~ ^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$ ]]; then
        warn "Invalid port list '${input}'. Keeping suggested value: ${2:-none}" >&2
        input="$2"
        [[ "$input" == "none" ]] && input=""
    fi
    echo "$input"
}

configure_ports() {
    local conf="${CONFIG_DIR}/fwsec.conf"
    [[ -f "$conf" ]] || return 0

    # Hosting panel (cPanel/Plesk): offer the panel's port profile first.
    # Applied -> done; declined -> fall through to the generic port prompts.
    detect_panel
    if [[ -n "$PANEL" ]]; then
        if _apply_panel_profile; then
            return 0
        fi
    fi

    local ssh_ports ssh_port
    ssh_ports=$(_detect_ssh_ports_bash | tr '\n' ',' | sed -E 's/,$//' || true)
    ssh_port="${ssh_ports%%,*}"

    echo ""
    echo -e "${BOLD}${CYAN}--------------------------------------------${NC}"
    echo -e "${BOLD}${CYAN}  Port configuration${NC}"
    echo -e "${BOLD}${CYAN}--------------------------------------------${NC}"

    local tcp_listeners udp_listeners
    tcp_listeners=$(_list_listeners t)
    udp_listeners=$(_list_listeners u)

    echo ""
    info "Services currently listening on this system:"
    printf "    %-8s %-6s %s\n" "PORT" "PROTO" "SERVICE"
    local port svc
    while read -r port svc; do
        [[ -n "$port" ]] || continue
        if [[ " ${ssh_ports//,/ } " == *" $port "* ]]; then
            printf "    %-8s %-6s %s  ${GREEN}(SSH — always kept open)${NC}\n" "$port" "tcp" "$svc"
        else
            printf "    %-8s %-6s %s\n" "$port" "tcp" "$svc"
        fi
    done <<< "$tcp_listeners"
    while read -r port svc; do
        [[ -n "$port" ]] || continue
        printf "    %-8s %-6s %s\n" "$port" "udp" "$svc"
    done <<< "$udp_listeners"

    # Suggested inbound defaults = detected listeners (SSH is handled separately)
    local tcp_in_default udp_in_default
    tcp_in_default=$(awk -v ssh_ports="$ssh_ports" '
        BEGIN { n = split(ssh_ports, p, ","); for (i = 1; i <= n; i++) if (p[i] != "") skip[p[i]] = 1 }
        !($1 in skip) { printf "%s%s", sep, $1; sep = "," }
    ' <<< "$tcp_listeners")
    udp_in_default=$(awk '{printf "%s%s", sep, $1; sep=","}' <<< "$udp_listeners")

    local tcp_in udp_in tcp_out udp_out
    if [[ -t 0 ]]; then
        echo ""
        info "Choose which ports stay open. Press Enter to accept the suggested value,"
        info "type a comma-separated list (ranges like 8000:8080 allowed), or 'none'."
        info "SSH port(s) (${ssh_ports}) are detected automatically and always stay open."
        echo ""
        tcp_in=$(_prompt_ports  "Inbound  TCP (TCP_IN)  — detected services" "$tcp_in_default")
        udp_in=$(_prompt_ports  "Inbound  UDP (UDP_IN)  — detected services" "$udp_in_default")
        tcp_out=$(_prompt_ports "Outbound TCP (TCP_OUT) — 80/443 web, 53 DNS, 853 DNS-over-TLS" "$DEFAULT_TCP_OUT")
        udp_out=$(_prompt_ports "Outbound UDP (UDP_OUT) — 53 DNS, 123 NTP, 443 QUIC" "$DEFAULT_UDP_OUT")
    else
        echo ""
        warn "Non-interactive shell: applying detected inbound ports and safe outbound defaults."
        tcp_in="$tcp_in_default"
        udp_in="$udp_in_default"
        tcp_out="$DEFAULT_TCP_OUT"
        udp_out="$DEFAULT_UDP_OUT"
    fi

    set_conf_value "TCP_IN"  "$tcp_in"
    set_conf_value "UDP_IN"  "$udp_in"
    set_conf_value "TCP_OUT" "$tcp_out"
    set_conf_value "UDP_OUT" "$udp_out"

    echo ""
    ok "Ports saved to ${conf}:"
    ok "  TCP_IN = ${tcp_in:-none}  |  UDP_IN = ${udp_in:-none}"
    ok "  TCP_OUT = ${tcp_out:-none}  |  UDP_OUT = ${udp_out:-none}"
}

# =============================================================================
# Container support (Docker / Podman / nerdctl)
# =============================================================================
detect_container_runtimes() {
    CONTAINER_RUNTIMES=""
    local rt
    for rt in docker podman nerdctl; do
        if command -v "$rt" &>/dev/null; then
            CONTAINER_RUNTIMES="${CONTAINER_RUNTIMES:+${CONTAINER_RUNTIMES} }${rt}"
        fi
    done
}

_list_published_ports() {
    # Prints "HOSTPORT/PROTO -> container:port [runtime]" for running containers
    local rt
    for rt in $CONTAINER_RUNTIMES; do
        "$rt" ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null | while IFS=$'\t' read -r name ports; do
            grep -oE '[^ ,]*:[0-9]+->[0-9]+/(tcp|udp)' <<< "$ports" | \
            while read -r map; do
                # Strip the host address (v4 or v6) — keep "HOSTPORT->CPORT/proto"
                echo "    ${map##*:}  ${name} [${rt}]"
            done
        done
    done | sort -u
}

_container_subnets() {
    # Prints one container network subnet (CIDR) per line, all runtimes
    local rt ids
    for rt in $CONTAINER_RUNTIMES; do
        ids=$("$rt" network ls -q 2>/dev/null) || continue
        [[ -n "$ids" ]] || continue
        # Docker/nerdctl: IPAM.Config[].Subnet — Podman: subnets[].subnet
        "$rt" network inspect $ids 2>/dev/null | \
            grep -oE '"([Ss]ubnet)":[[:space:]]*"[^"]+"' | \
            sed -E 's/.*"([^"]+)"$/\1/'
    done | sort -u
}

print_container_recommendations() {
    echo ""
    echo -e "  ${BOLD}Container security recommendations:${NC}"
    echo -e "    • Bind internal-only services to localhost: ${BOLD}-p 127.0.0.1:5432:5432${NC}"
    echo -e "      (never expose databases/admin panels on 0.0.0.0)."
    echo -e "    • Published ports (-p) bypass the input firewall — fwsec covers them"
    echo -e "      on the forward hook, and ${BOLD}CONTAINER_POLICY = filtered${NC} can restrict"
    echo -e "      them to the allow list."
    echo -e "    • Never expose the container engine socket (docker.sock/podman.sock)"
    echo -e "      to containers or to the network."
    echo -e "    • Prefer rootless mode (Podman rootless / Docker rootless) when possible."
    echo -e "    • Keep images updated and from trusted registries only."
    echo -e "    • Enable CrowdSec log acquisition for containers so attacks against"
    echo -e "      containerized apps also generate bans."
}

configure_containers() {
    local conf="${CONFIG_DIR}/fwsec.conf"
    [[ -f "$conf" ]] || return 0

    detect_container_runtimes

    echo ""
    echo -e "${BOLD}${CYAN}--------------------------------------------${NC}"
    echo -e "${BOLD}${CYAN}  Container support${NC}"
    echo -e "${BOLD}${CYAN}--------------------------------------------${NC}"
    echo ""

    local container_mode=0
    if [[ -n "$CONTAINER_RUNTIMES" ]]; then
        ok "Container runtime(s) detected: ${BOLD}${CONTAINER_RUNTIMES}${NC}"
        container_mode=1
        local published
        published=$(_list_published_ports)
        if [[ -n "$published" ]]; then
            echo ""
            info "Published container ports (host -> container):"
            echo "$published"
        fi
    else
        ok "No container runtime detected."
        if [[ -t 0 ]]; then
            local answer=""
            read -r -p "$(echo -e "  ${BOLD}Do you plan to run containers (Docker/Podman) on this host?${NC} [y/N]: ")" answer || answer=""
            if [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
                container_mode=1
                info "Container mode will be pre-enabled so the firewall does not break"
                info "container networking when you install a runtime later."
            fi
        fi
    fi

    if [[ "$container_mode" -eq 0 ]]; then
        set_conf_value "CONTAINER_MODE" "0"
        ok "Container mode: disabled (forward chain drops all traffic)."
        return 0
    fi

    # Ensure the [containers] section exists (older configs may lack it)
    if ! grep -q '^\[containers\]' "$conf"; then
        printf '\n[containers]\nCONTAINER_MODE = 0\nCONTAINER_POLICY = open\n' >> "$conf"
    fi
    set_conf_value "CONTAINER_MODE" "1"
    ok "Container mode: enabled (CONTAINER_MODE = 1)."

    # Published port policy
    local policy="open"
    if [[ -t 0 ]]; then
        local answer=""
        echo ""
        info "CONTAINER_POLICY controls who can reach published container ports:"
        info "  open     — any source (Docker's default behavior)"
        info "  filtered — only IPs in the fwsec allow list"
        read -r -p "$(echo -e "  ${BOLD}Restrict published container ports to the allow list?${NC} [y/N]: ")" answer || answer=""
        if [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
            policy="filtered"
        fi
    fi
    set_conf_value "CONTAINER_POLICY" "$policy"
    ok "Published container port policy: ${policy}."

    # Exempt container networks from automatic bans (internal traffic must
    # never be banned — a busy internal proxy is a classic false positive)
    local subnets
    subnets=$(_container_subnets)
    if [[ -n "$subnets" ]]; then
        local s added=0
        touch "${CONFIG_DIR}/fwsec.ignore"
        while read -r s; do
            [[ -n "$s" ]] || continue
            if ! grep -qF "$s" "${CONFIG_DIR}/fwsec.ignore"; then
                echo "${s}  # container network (auto-added by installer)" >> "${CONFIG_DIR}/fwsec.ignore"
                added=$((added + 1))
            fi
        done <<< "$subnets"
        if [[ "$added" -gt 0 ]]; then
            ok "Added ${added} container network(s) to fwsec.ignore (exempt from bans)."
        fi
    fi

    print_container_recommendations
}

# =============================================================================
# CrowdSec container log acquisition
# =============================================================================
configure_crowdsec_container_logs() {
    [[ -n "${CONTAINER_RUNTIMES:-}" ]] || return 0
    command -v cscli &>/dev/null || return 0
    [[ -d /etc/crowdsec ]] || return 0

    local acquis="/etc/crowdsec/acquis.d/fwsec-docker.yaml"
    if [[ -f "$acquis" ]]; then
        ok "CrowdSec container log acquisition already configured."
        return 0
    fi

    local enable=0
    if [[ -t 0 ]]; then
        local answer=""
        echo ""
        read -r -p "$(echo -e "${CYAN}[*]${NC} Enable CrowdSec log analysis for containers (bans attacks against containerized apps)? [Y/n]: ")" answer || answer=""
        if [[ -z "$answer" || "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
            enable=1
        fi
    else
        enable=1
    fi
    [[ "$enable" -eq 1 ]] || return 0

    mkdir -p /etc/crowdsec/acquis.d
    cat > "$acquis" << 'ACQEOF'
# Managed by fwsec installer — CrowdSec reads logs from labeled containers.
# The log type comes from container labels (e.g. crowdsec.labels.type=nginx);
# use_container_labels is mutually exclusive with container_name filters. See:
# https://docs.crowdsec.net/docs/data_sources/docker
source: docker
use_container_labels: true
ACQEOF
    svc_restart crowdsec
    ok "CrowdSec container log acquisition enabled (${acquis})."
    info "Label your containers (e.g. crowdsec.labels.type=nginx) so CrowdSec"
    info "parses their logs with the right scenario collection."
}

configure_ports_if_needed() {
    if [[ "${CONF_IS_NEW:-0}" -eq 1 ]]; then
        configure_ports
    elif [[ -t 0 ]]; then
        local answer=""
        read -r -p "$(echo -e "${CYAN}[*]${NC} fwsec.conf already exists. Reconfigure allowed ports? [y/N]: ")" answer || answer=""
        if [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
            configure_ports
        else
            ok "Keeping the existing port configuration."
        fi
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    # Parse flags
    FORCE=0
    UPGRADE=0
    INSTALL_ONLY=0
    NO_CROWDSEC=0
    CONF_IS_NEW=0
    MIGRATION_APPROVE=""
    for arg in "$@"; do
        case "$arg" in
            --force)       FORCE=1 ;;
            --upgrade)     UPGRADE=1 ;;
            --no-crowdsec) NO_CROWDSEC=1 ;;
            --install-only) INSTALL_ONLY=1 ;;
            --migration-approve=*) MIGRATION_APPROVE="${arg#*=}" ;;
        esac
    done

    # Standalone execution (curl | bash): fetch the source tree first
    bootstrap_source

    echo ""
    echo -e "${BOLD}${CYAN}============================================${NC}"
    echo -e "${BOLD}${CYAN}  fwsec ${FWSEC_VERSION} — Installer${NC}"
    echo -e "${BOLD}${CYAN}  nftables + CrowdSec firewall manager${NC}"
    echo -e "${BOLD}${CYAN}============================================${NC}"
    echo ""

    # Skip if already installed unless --force or --upgrade is set
    if [[ "$FORCE" -eq 0 && "$UPGRADE" -eq 0 ]]; then
        check_already_installed
    elif [[ "$FORCE" -eq 1 ]]; then
        warn "--force mode: reinstalling over the existing installation."
    elif [[ "$UPGRADE" -eq 1 ]]; then
        info "--upgrade mode: checking the repository for a newer version..."
    fi

    detect_os
    detect_init
    ok "Init system: ${INIT_SYSTEM}."
    detect_migration_source

    # Upgrade: consult the repository and install a newer release when available.
    # Only the package and executable change; configuration is preserved.
    if [[ "$UPGRADE" -eq 1 ]]; then
        run_upgrade
    fi

    # Explicit code-only mode for image building / unprivileged CI containers.
    # No source-firewall migration, service changes, config writes or rule apply.
    if [[ "$INSTALL_ONLY" -eq 1 ]]; then
        install_base_deps
        install_python
        install_uv
        install_fwsec_package
        install_binary
        ok "Code installed only; firewall policy/services/configuration unchanged."
        return 0
    fi

    install_base_deps
    install_python
    install_uv
    configure_selinux
    configure_apparmor
    run_migration_stage
    disable_competing_firewalls
    install_crowdsec
    enable_nftables
    install_fwsec_package
    install_config_files
    configure_ports_if_needed
    [[ "$MIGRATION_STAGED" -eq 1 ]] || configure_containers
    configure_crowdsec_container_logs
    install_binary
    install_service

    echo ""
    info "Starting fwsec for the first time..."
    local -a start_cmd=(fwsec -s)
    if [[ "$MIGRATION_STAGED" -eq 1 ]]; then
        start_cmd=(fwsec --apply-safe --timeout 120)
    fi
    if "${start_cmd[@]}"; then
        ok "fwsec started successfully."
        remove_migrated_firewall
    else
        warn "fwsec failed to start. Run it manually: fwsec -s"
        if [[ "$MIGRATION_STAGED" -eq 1 ]]; then
            warn "The previous firewall was NOT removed (fwsec is not filtering)."
        fi
        die "Firewall application failed; installation is NOT complete."
    fi

    echo ""
    info "Running the post-installation check..."
    post_install_check || true
    migration_report

    local ssh_ports
    ssh_ports=$(_detect_ssh_ports_bash | tr '\n' ',' | sed -E 's/,$//' || true)

    echo ""
    echo -e "${BOLD}${GREEN}============================================${NC}"
    echo -e "${BOLD}${GREEN}  fwsec installed successfully!${NC}"
    echo -e "${BOLD}${GREEN}============================================${NC}"
    echo -e "  Config dir  : ${CONFIG_DIR}/"
    echo -e "  Executable  : ${BIN}"
    echo -e "  SSH port(s) : ${ssh_ports:-22}"
    echo ""
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "    fwsec -s              Start the firewall"
    echo -e "    fwsec -r              Reload rules"
    echo -e "    fwsec -l              List rules"
    echo -e "    fwsec -c              Validate the configuration"
    echo -e "    fwsec -d IP [reason]  Block an IP address"
    echo -e "    fwsec -a IP [reason]  Allow an IP address"
    echo -e "    fwsec -g IP           Search for an IP address"
    echo -e "    fwsec -h              Show full help"
    echo -e "${BOLD}${GREEN}============================================${NC}"
    echo ""
}

main "$@"
