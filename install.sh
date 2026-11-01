#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# =============================================================================
# fwsec installer
# Supported systems: Ubuntu 24+ | Rocky Linux 8 / 9 / 10
# =============================================================================
set -euo pipefail

FWSEC_VERSION="1.1.0"
REPO="saulolimabrito/fwsec"
INSTALL_DIR="/opt/fwsec"
CONFIG_DIR="/etc/fwsec"
BIN="/usr/local/bin/fwsec"
SERVICE="/etc/systemd/system/fwsec.service"
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
# Operating system detection
# =============================================================================
detect_os() {
    [[ -f /etc/os-release ]] || die "/etc/os-release was not found."
    . /etc/os-release

    OS_ID="${ID:-}"
    OS_VERSION="${VERSION_ID:-0}"
    OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)

    case "$OS_ID" in
        ubuntu)
            [[ "$OS_MAJOR" -ge 24 ]] || die "Ubuntu ${OS_VERSION} is not supported. Minimum version: 24."
            OS_FAMILY="debian"
            ok "Detected Ubuntu ${OS_VERSION}."
            ;;
        rocky)
            [[ "$OS_MAJOR" -ge 8 ]] || die "Rocky Linux ${OS_VERSION} is not supported. Minimum version: 8."
            OS_FAMILY="rhel"
            ok "Detected Rocky Linux ${OS_VERSION}."
            ;;
        rhel|almalinux|ol)
            [[ "$OS_MAJOR" -ge 8 ]] || die "${PRETTY_NAME} is not supported. Minimum version: 8."
            OS_FAMILY="rhel"
            warn "Detected a Rocky-compatible distribution (${PRETTY_NAME}). Continuing..."
            ;;
        *)
            die "Operating system '${OS_ID}' is not supported. Use Ubuntu 24+ or Rocky Linux 8+."
            ;;
    esac
}

# =============================================================================
# Base dependency installation
# =============================================================================
install_base_deps() {
    info "Installing base dependencies..."
    case "$OS_FAMILY" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            # A broken unrelated third-party repo must not abort the install
            apt-get update -qq 2>/dev/null || warn "apt-get update reported errors from an unrelated repository; continuing."
            apt-get install -y -qq \
                curl tar gzip ca-certificates gnupg \
                nftables \
                python3 python3-pip \
                2>/dev/null
            ;;
        rhel)
            dnf install -y -q \
                curl tar gzip ca-certificates \
                nftables \
                2>/dev/null
            ;;
    esac
    ok "Base dependencies installed."
}

# =============================================================================
# Python 3.11+
# =============================================================================
install_python() {
    info "Checking for Python 3.11+..."

    # Find an installed Python version >= 3.11
    PYTHON=""
    for py in python3.13 python3.12 python3.11; do
        if command -v "$py" &>/dev/null; then
            PYTHON=$(command -v "$py")
            break
        fi
    done

    if [[ -n "$PYTHON" ]]; then
        PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        ok "Found Python ${PY_VER} at ${PYTHON}."
        return
    fi

    info "Python 3.11+ was not found. Installing it..."
    case "$OS_FAMILY" in
        debian)
            # Ubuntu 24 provides Python 3.12 through apt
            apt-get install -y -qq python3.12 python3.12-venv 2>/dev/null || \
            apt-get install -y -qq python3.11 python3.11-venv 2>/dev/null || \
            die "Could not install Python 3.11+."
            ;;
        rhel)
            case "$OS_MAJOR" in
                8)
                    # Rocky 8 provides Python 3.11 through AppStream
                    dnf module reset python39 -y -q 2>/dev/null || true
                    dnf install -y -q python3.11 python3.11-pip 2>/dev/null || {
                        # Fallback: EPEL
                        dnf install -y -q epel-release 2>/dev/null || true
                        dnf install -y -q python3.11 2>/dev/null || \
                        die "Could not install Python 3.11 on Rocky Linux 8."
                    }
                    ;;
                9|10)
                    # Rocky 9/10 provide Python 3.11 through AppStream
                    dnf install -y -q python3.11 python3.11-pip 2>/dev/null || \
                    dnf install -y -q python3.12 python3.12-pip 2>/dev/null || \
                    die "Could not install Python 3.11+ on Rocky Linux ${OS_MAJOR}."
                    ;;
            esac
            ;;
    esac

    # Detect Python again after installation
    for py in python3.13 python3.12 python3.11; do
        if command -v "$py" &>/dev/null; then
            PYTHON=$(command -v "$py")
            break
        fi
    done
    [[ -n "$PYTHON" ]] || die "Python 3.11+ was not found after installation."

    PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    ok "Installed Python ${PY_VER} at ${PYTHON}."
}

# =============================================================================
# uv package and virtual environment manager
# =============================================================================
install_uv() {
    if command -v uv &>/dev/null; then
        ok "uv is already installed: $(uv --version)."
        return
    fi

    info "Installing uv..."

    # Ensure tar is available; minimal containers may omit it
    case "$OS_FAMILY" in
        debian) command -v tar &>/dev/null || apt-get install -y -qq tar ;;
        rhel)   command -v tar &>/dev/null || dnf install -y -q tar ;;
    esac

    curl -fsSL https://astral.sh/uv/install.sh | env HOME=/root sh >/dev/null 2>&1
    export PATH="/root/.local/bin:$PATH"

    command -v uv &>/dev/null || die "uv was not found after installation."
    ok "Installed uv: $(uv --version)."
}

# =============================================================================
# CrowdSec
# =============================================================================
install_crowdsec() {
    if command -v crowdsec &>/dev/null; then
        ok "CrowdSec is already installed."
    else
        info "Installing CrowdSec..."
        case "$OS_FAMILY" in
            debian)
                curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash >/dev/null 2>&1
                apt-get install -y -qq crowdsec
                ;;
            rhel)
                curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash >/dev/null 2>&1
                dnf install -y -q crowdsec
                ;;
        esac
        ok "CrowdSec installed."
    fi

    if command -v crowdsec-firewall-bouncer &>/dev/null || \
       [[ -f /usr/bin/crowdsec-firewall-bouncer ]]; then
        ok "The CrowdSec firewall bouncer is already installed."
    else
        info "Installing the CrowdSec nftables bouncer..."
        case "$OS_FAMILY" in
            debian) apt-get install -y -qq crowdsec-firewall-bouncer-nftables ;;
            rhel)   dnf install -y -q crowdsec-firewall-bouncer-nftables ;;
        esac
        ok "CrowdSec nftables bouncer installed."
    fi

    # Enable and start CrowdSec
    systemctl enable crowdsec --now 2>/dev/null || true

    # Configure the bouncer if it is not running
    _configure_crowdsec_bouncer
}

_configure_crowdsec_bouncer() {
    local bouncer_conf="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    [[ -f "$bouncer_conf" ]] || { warn "Bouncer configuration was not found."; return; }

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

    systemctl enable crowdsec-firewall-bouncer --now 2>/dev/null || \
    systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
    ok "CrowdSec bouncer configured."
}

# =============================================================================
# SELinux (Rocky 8/9/10)
# =============================================================================
configure_selinux() {
    [[ "$OS_FAMILY" == "rhel" ]] || return 0
    command -v sestatus &>/dev/null || return 0
    sestatus 2>/dev/null | grep -q "enabled" || return 0

    info "Configuring SELinux for nftables and Python..."

    if ! command -v semanage &>/dev/null; then
        dnf install -y -q policycoreutils-python-utils 2>/dev/null || true
    fi

    # Detect the configured SSH port
    local ssh_port
    ssh_port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "22")

    if [[ "$ssh_port" != "22" ]]; then
        semanage port -a -t ssh_port_t -p tcp "$ssh_port" 2>/dev/null || \
        semanage port -m -t ssh_port_t -p tcp "$ssh_port" 2>/dev/null || true
    fi

    ok "SELinux configured."
}

# =============================================================================
# AppArmor (Ubuntu)
# =============================================================================
configure_apparmor() {
    [[ "$OS_FAMILY" == "debian" ]] || return 0
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

# =============================================================================
# Disable competing firewalls
# =============================================================================
disable_competing_firewalls() {
    info "Checking for competing firewalls (nftables must be managed only by fwsec)..."

    # firewalld — checked on every distro, not only RHEL-family
    if systemctl is-active --quiet firewalld 2>/dev/null || \
       systemctl is-enabled --quiet firewalld 2>/dev/null; then
        systemctl stop firewalld 2>/dev/null || true
        systemctl disable firewalld 2>/dev/null || true
        systemctl mask firewalld 2>/dev/null || true
        ok "firewalld stopped, disabled and masked."
    else
        ok "firewalld is not active."
    fi

    # UFW — checked on every distro, not only Debian-family
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "^Status: active"; then
            ufw --force disable >/dev/null 2>&1 || true
            ok "UFW disabled."
        else
            ok "UFW is installed but not active."
        fi
        systemctl stop ufw 2>/dev/null || true
        systemctl disable ufw 2>/dev/null || true
        systemctl mask ufw 2>/dev/null || true
    else
        ok "UFW is not installed."
    fi

    # Legacy iptables rule restorers — they would fight fwsec's ruleset at boot
    local svc
    for svc in iptables ip6tables netfilter-persistent; do
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            warn "${svc}.service disabled (it restored iptables rules at boot)."
        fi
    done

    ok "nftables will be managed exclusively by fwsec."
}

# =============================================================================
# Install the fwsec package in a virtual environment
# =============================================================================
install_fwsec_package() {
    info "Creating a virtual environment at ${INSTALL_DIR}..."
    export PATH="/root/.local/bin:$PATH"

    rm -rf "${INSTALL_DIR}/venv"
    uv venv "${INSTALL_DIR}/venv" --python "$PYTHON" --quiet

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
    cat > "$BIN" << WRAPPER
#!/usr/bin/env bash
exec "${INSTALL_DIR}/venv/bin/python" -m fwsec "\$@"
WRAPPER
    chmod +x "$BIN"
    ok "Executable installed: ${BIN}."
}

# =============================================================================
# systemd service
# =============================================================================
install_service() {
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

    systemctl daemon-reload
    systemctl enable fwsec.service
    ok "fwsec.service installed and enabled at boot."
}

# =============================================================================
# Ensure the nftables service is enabled at boot
# =============================================================================
enable_nftables() {
    systemctl enable nftables 2>/dev/null || true
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
    systemctl is-enabled fwsec &>/dev/null && ok "  fwsec.service: enabled" || { warn "  fwsec.service: not enabled"; }

    if systemctl is-active --quiet firewalld 2>/dev/null; then
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
    v=$(curl -fsSL --max-time 15 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 \
        | sed -E 's/.*"v?([0-9][^"]*)"$/\1/') || true
    # Fallback: version declared in pyproject.toml on main
    if [[ -z "$v" ]]; then
        v=$(curl -fsSL --max-time 15 "https://raw.githubusercontent.com/${REPO}/main/pyproject.toml" 2>/dev/null \
            | grep -E '^version[[:space:]]*=' | head -1 \
            | sed -E 's/.*"([^"]+)".*/\1/') || true
    fi
    echo "$v"
}

download_source() {
    # Downloads and extracts the source for version $1; echoes the source dir.
    local ver="$1" tmp dir
    tmp=$(mktemp -d /tmp/fwsec-upgrade.XXXXXX)
    if ! curl -fsSL --max-time 60 -o "${tmp}/src.tar.gz" \
            "https://github.com/${REPO}/archive/refs/tags/v${ver}.tar.gz" 2>/dev/null; then
        # No tag for this version — fall back to the main branch tarball
        curl -fsSL --max-time 60 -o "${tmp}/src.tar.gz" \
            "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" \
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
    command -v curl &>/dev/null || die "curl is required for the standalone install."
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
    command -v curl &>/dev/null || die "curl is required for --upgrade."

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
    install_fwsec_package
    install_binary
    rm -rf "$(dirname "$src_dir")"

    echo ""
    info "Reloading rules with the new version..."
    fwsec -r 2>/dev/null || true
    ok "fwsec upgraded to ${remote}. Configuration files were preserved."
    fwsec -v
    echo ""
    exit 0
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
    # $1 = t|u — prints "port service" pairs, skipping loopback-only listeners
    ss -H "-${1}lnp" 2>/dev/null | awk '
    {
        n = split($4, a, ":"); port = a[n]
        addr = substr($4, 1, length($4) - length(port) - 1)
        if (addr ~ /^127\./ || addr == "[::1]") next
        if (port !~ /^[0-9]+$/) next
        svc = "-"
        if (match($0, /\(\("[^"]+"/)) svc = substr($0, RSTART + 3, RLENGTH - 4)
        if (!seen[port]++) print port, svc
    }' | sort -n
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

    local ssh_port
    # `|| true`: sshd_config without an explicit Port line must not abort (set -e + pipefail)
    ssh_port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || true)
    ssh_port="${ssh_port:-22}"

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
        if [[ "$port" == "$ssh_port" ]]; then
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
    tcp_in_default=$(awk -v ssh="$ssh_port" '$1 != ssh {printf "%s%s", sep, $1; sep=","}' <<< "$tcp_listeners")
    udp_in_default=$(awk '{printf "%s%s", sep, $1; sep=","}' <<< "$udp_listeners")

    local tcp_in udp_in tcp_out udp_out
    if [[ -t 0 ]]; then
        echo ""
        info "Choose which ports stay open. Press Enter to accept the suggested value,"
        info "type a comma-separated list (ranges like 8000:8080 allowed), or 'none'."
        info "The SSH port (${ssh_port}) is detected automatically and always stays open."
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
    local rt line
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
    systemctl restart crowdsec 2>/dev/null || true
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
    CONF_IS_NEW=0
    for arg in "$@"; do
        case "$arg" in
            --force)   FORCE=1 ;;
            --upgrade) UPGRADE=1 ;;
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

    # Upgrade: consult the repository and install a newer release when available.
    # Only the package and executable change; configuration is preserved.
    if [[ "$UPGRADE" -eq 1 ]]; then
        run_upgrade
    fi

    install_base_deps
    install_python
    install_uv
    configure_selinux
    configure_apparmor
    disable_competing_firewalls
    install_crowdsec
    enable_nftables
    install_fwsec_package
    install_config_files
    configure_ports_if_needed
    configure_containers
    configure_crowdsec_container_logs
    install_binary
    install_service

    echo ""
    info "Starting fwsec for the first time..."
    if fwsec -s; then
        ok "fwsec started successfully."
    else
        warn "fwsec failed to start. Run it manually: fwsec -s"
    fi

    echo ""
    info "Running the post-installation check..."
    post_install_check || true

    local ssh_port
    ssh_port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "22")

    echo ""
    echo -e "${BOLD}${GREEN}============================================${NC}"
    echo -e "${BOLD}${GREEN}  fwsec installed successfully!${NC}"
    echo -e "${BOLD}${GREEN}============================================${NC}"
    echo -e "  Config dir  : ${CONFIG_DIR}/"
    echo -e "  Executable  : ${BIN}"
    echo -e "  SSH port    : ${ssh_port}"
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
