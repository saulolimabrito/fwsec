# fwsec

**nftables + CrowdSec firewall manager** — a CSF-style command-line interface for managing a modern Linux firewall.

fwsec is distributed and maintained as an independent project. This repository contains all source code, configuration templates, and installation resources required to use it.

> Supported systems: Debian 12+ · Ubuntu 22.04+ · RHEL-family 8+ (Rocky, Alma, RHEL, CentOS Stream, Oracle Linux, Fedora 40+, Amazon Linux 2023) · openSUSE Leap 15.4+ / SLES 15 SP4+ · Arch · Alpine 3.17+

## Supported distributions

| Family | Distributions | Package manager | Init |
|---|---|---|---|
| Debian | Debian 12+, Ubuntu 22.04+, Linux Mint, Pop!_OS, Devuan, Kali, Raspbian | apt | systemd |
| RHEL | Rocky 8+, Alma 8+, RHEL 8+, CentOS Stream 9+, Oracle Linux 8+, Fedora 40+, Amazon Linux 2023 | dnf / yum | systemd |
| SUSE | openSUSE Leap 15.4+, Tumbleweed, SLES 15 SP4+ | zypper | systemd |
| Arch | Arch, Manjaro, EndeavourOS | pacman | systemd |
| Alpine | 3.17+ (musl) | apk | OpenRC |

Requirements on every distribution: **nftables ≥ 0.9.0** (kernel ≥ 4.18 — the floor of RHEL 8 / Debian 10 / Ubuntu 18.04) and **Python 3.8+**. When the distribution's Python is older than 3.8 (e.g. SLES 15), the installer provisions a standalone CPython through [uv](https://docs.astral.sh/uv/) instead — no manual step is needed. Boot persistence uses systemd, or OpenRC on Alpine; systems with neither are installed without the boot service (start fwsec manually).

Notes:

- Known derivatives of a supported family are allowed with a warning; EOL releases (Ubuntu ≤ 20.04, Debian ≤ 11, CentOS 7, Amazon Linux 2, Rocky/Alma/RHEL ≤ 7) are rejected.
- Kernels without nf_tables support — **OpenVZ/Virtuozzo containers**, some stripped-down VPS kernels — cannot run fwsec; `fwsec -s` reports this explicitly instead of failing cryptically.
- On Arch, CrowdSec is only available through the AUR; install it manually or run the installer with `--no-crowdsec`. fwsec works fully without it.

## Quick install

No git required — the installer downloads the latest fwsec release by itself:

```bash
curl -fsSL https://raw.githubusercontent.com/saulolimabrito/fwsec/main/install.sh | sudo bash
```

When piped like this the install is non-interactive: detected inbound ports and safe outbound defaults are applied automatically. To answer the interactive prompts (port selection, container policy), download the installer first and run it from a terminal:

```bash
curl -fsSLO https://raw.githubusercontent.com/saulolimabrito/fwsec/main/install.sh
sudo bash install.sh
```

## Updating

### Safe rule application (development)

Rule reloads now validate configuration, compile all fwsec rules and set
elements, run `nft --check`, and apply one nftables transaction. A rejected
transaction does not partially change the live firewall. Concurrent fwsec
writers are serialized by a root-owned lock; writers are refused during a
pending safe apply.

```bash
sudo fwsec --dry-run                  # validate/print; no rules/configuration changed
sudo fwsec --apply-safe --timeout 120 # trial; do NOT close your original SSH session
# Open a NEW SSH connection and confirm the ID printed by the command:
sudo fwsec --confirm TRANSACTION_ID
```

Without confirmation the detached watchdog restores the previous fwsec
table and affected filter chains. The watchdog is independent of the SSH
terminal and does not require systemd (also works on OpenRC). It is not a
reboot/power-loss recovery service: do not reboot or upgrade during a trial.
Snapshots, confirmation/rollback status and worker logs are retained in
`/var/lib/fwsec/transactions/<ID>/`. A failed rollback is recorded in
`rollback-error`, retried, and continues to block other fwsec writers.

**Ownership and existing installations:** only `inet fwsec` and the marked
`input`, `forward`, `output` base chains of `inet filter` are managed. Other
tables/chains and existing CrowdSec sets/elements are not flushed. The shared
filter table itself is never flushed. Old installations lack ownership
markers: inspect them first, then deliberately adopt only if those objects
really belong to fwsec:

```bash
sudo fwsec --dry-run --adopt-legacy
sudo fwsec --apply-safe --adopt-legacy --timeout 120
```

Do not use adoption to overwrite a third-party firewall. This development
change intentionally refuses an unattended reload of unmarked legacy rules;
it must be tested and adopted before a production upgrade can be released.

Boot persistence uses `/etc/nftables/fwsec.nft`, included by the distro's
loader, with scoped/idempotent commands instead of `flush ruleset`. Existing
administrator includes are kept. An administrator-owned loader containing a
global flush is refused before applying rules and must be reviewed manually.
Safe applies defer persistence until confirmation; persistence failure keeps
rollback armed. Rollback also restores persistence/config files as captured
at invocation (not configuration edits the operator made before invocation).

Local unit tests use mocks; the separate Linux CI job runs real nftables
only inside a disposable network namespace, including a watchdog test after
the launching process exits. No production server is used for these tests.

```bash
sudo fwsec --upgrade
```

fwsec checks the GitHub repository for a newer release; when one is available it downloads it and updates the code, features, and executable. **Local configuration is never overwritten**: `fwsec.conf`, the allow/deny/ignore lists, and the temporary-block state in `/etc/fwsec` stay exactly as they are, and the rules are reloaded from them after the update. If nothing newer exists, it reports that fwsec is up to date. (`sudo bash install.sh --upgrade` remains available and does the same.)

## Installation from source

```bash
git clone https://github.com/saulolimabrito/fwsec.git
cd fwsec
sudo bash install.sh
```

| Flag | Behavior |
|---|---|
| *(no flags)* | Installs fwsec. If it is already installed, displays its status and exits. |
| `--upgrade` | Queries the GitHub repository for the latest version. When a newer release is available, downloads it and upgrades the package and executable while preserving configuration files; otherwise reports that fwsec is up to date. |
| `--force` | Performs a complete reinstallation. |
| `--install-only` | Installs code/dependencies only (image building/CI); does not migrate/configure/start the firewall or alter services. |
| `--no-crowdsec` | Installs fwsec without the CrowdSec integration (CrowdSec and its nftables bouncer can be added later; every fwsec command degrades gracefully when they are absent). |

The installer detects CSF, UFW and firewalld before changing their policy.
It no longer stops/masks them or runs blanket teardown scripts during
installation. A reviewed migration keeps its source active during a safe
trial; unsupported/ambiguous policies abort without retiring the source.

### Interactive port selection

During installation, the installer scans the system with `ss` and lists every service currently listening (port, protocol, and service name). It then asks which ports to keep open for each direction:

- **Inbound TCP / UDP** — defaults to the detected listening services. The SSH port is detected automatically and always stays open.
- **Outbound TCP** — suggests `80,443,53,853` (HTTP, HTTPS, DNS, DNS-over-TLS).
- **Outbound UDP** — suggests `53,123,443` (DNS, NTP, QUIC/HTTP3).

Legacy mode retains its existing OUTPUT ACCEPT behavior: these outbound
lists are not an egress deny-by-default policy unless `OUTPUT_POLICY = drop`
is explicitly set. That opt-in mode keeps loopback, established/related
replies and ICMP/ICMPv6 control traffic permitted and restricts new TCP/UDP
egress to TCP_OUT/UDP_OUT. In inherited-policy mode the original IPv4/IPv6
OUTPUT policies and ordered egress rules are authoritative instead.

At each prompt, press Enter to accept the suggestion, type a comma-separated list (ranges like `8000:8080` are allowed), or type `none`. The choices are written to `/etc/fwsec/fwsec.conf`. In non-interactive shells the detected inbound ports and the safe outbound defaults are applied automatically. If `fwsec.conf` already exists, the installer asks before reconfiguring ports.

### Hosting control panels (cPanel / Plesk)

The installer detects **cPanel/WHM** and **Plesk**. When one is found, it shows a recommended service-port profile based on the panel's official firewall requirements and asks whether to apply it:

- **Apply the profile** (default, and automatic in non-interactive installs) — common TCP/UDP ports for mail, FTP, DNS, webmail, and the panel UI (2082–2096 for cPanel; 8443/8447/8880 for Plesk) are pre-opened. Remove ports for services that are disabled or not used.
- **Open on demand** — decline the profile and fall through to the regular minimal port selection; add panel ports later by editing `/etc/fwsec/fwsec.conf` and running `fwsec -r`.

The SSH port is detected separately and always stays open in either mode.

## Migrating from CSF / UFW / firewalld

Migration uses complete **live `iptables-save` / `ip6tables-save` snapshots**,
not a union of configured ports or a human-readable status summary. The JSON
intermediate model preserves IPv4/IPv6, ordered actions/jumps, source and
destination CIDRs, input/output interfaces, protocol, port ranges,
connection states and INPUT/OUTPUT/FORWARD default policies. Thus an IPv6
permission does not silently open IPv4, a source-specific allowance does
not become global, and OUTPUT DROP does not become OUTPUT ACCEPT.

```bash
sudo fwsec --migration-plan ufw --migration-output /root/migration.json
sudo fwsec --migration-report --migration-output /root/migration.json
# Only after reviewing the exact ownership warnings:
sudo fwsec --migration-plan ufw --migration-output /root/migration.json \
  --migration-approve FINGERPRINT_FROM_REPORT
```

The report distinguishes translated rules, ownership requiring approval,
and unsupported rules. Approval applies only to that exact fingerprint; it
**cannot override unsupported semantics**. NAT, raw/mangle rules, ipsets,
rate limits, logging/reject extensions, interface wildcards, third-party
chains and native nftables firewalld policies are conservatively blocked,
not dropped or guessed. This first strict adapter supports a subset of
xtables filter policies, not arbitrary firewall configurations. An active
firewalld daemon also requires a reviewed backend-specific retirement;
the finalizer refuses to tear it down automatically.

The installer saves config/live snapshots and the complete report under
`/root/fwsec-migration-<timestamp>.<random>/`. If the plan is ready, it sets
`INHERITED_POLICY = /etc/fwsec/inherited.json` and starts a **120-second safe
trial**. Existing fwsec configurations are never implicitly merged. Multiple
sources or unidentified active hooks/rules are refused. A source needing
ownership approval can be retried with
`bash install.sh --migration-approve=FINGERPRINT`; the fingerprint is rechecked.

After applying a ready policy:

```bash
# From a NEW SSH session, confirm the transaction ID printed by the installer:
sudo fwsec --confirm TRANSACTION_ID
sudo fwsec --migration-report
sudo fwsec --migration-finalize
```

Finalization requires the exact confirmed policy to remain active and the
source snapshots to remain unchanged. Both retirement batches are checked
first. Retirement uses `iptables-restore --noflush` / `ip6tables-restore
--noflush` with exact rule deletions and only reviewed source-chain names;
there is no global `-F`, `-X`, uninstall script or ruleset flush. Source
startup is disabled without executing its firewall teardown (LFD is stopped;
CSF cron entries are backed up). Packages/configs remain for recovery. A
failure is reported, never presented as a successful complete migration.

With `INHERITED_POLICY` active, that snapshot is authoritative for ports and
directional defaults; changing legacy TCP_IN/OUT fields does not edit the
inherited policy. CrowdSec remains an additional protection layer. The
normal non-migration default configuration is unchanged.

## Quick reference

### Firewall lifecycle

```bash
fwsec -s          # Start the firewall
fwsec -f          # Stop the firewall and flush its rules
fwsec -r          # Restart or reload the rules
fwsec -e          # Enable fwsec
fwsec -x          # Disable fwsec
fwsec -c          # Validate the configuration
fwsec -l          # List loaded rules and allowed ports (in/out, TCP/UDP)
fwsec -v          # Show fwsec, CrowdSec, and nftables versions
```

### Deny IP addresses

```bash
# Block permanently
fwsec -d 1.2.3.4
fwsec -d 1.2.3.4 "SSH attack"
fwsec -d 192.168.0.0/24 "Suspicious network"

# Block temporarily
fwsec -td 1.2.3.4 3600                  # 1 hour
fwsec -td 1.2.3.4 86400 "Brute force"  # 24 hours
fwsec -td 1.2.3.4 300 "Port scan"      # 5 minutes

# Remove a permanent block
fwsec -dr 1.2.3.4

# Remove a temporary block
fwsec -tr 1.2.3.4

# Show active temporary blocks
fwsec -t
```

### Allow IP addresses

```bash
# Add to the allow list
fwsec -a 1.2.3.4
fwsec -a 1.2.3.4 "São Paulo office"
fwsec -a 10.0.0.0/8 "Internal network"

# Remove from the allow list
fwsec -ar 1.2.3.4
```

> Allow-listed IP addresses have the highest priority and are accepted before every blocking rule, including CrowdSec rules.

### Search for an IP address or domain

```bash
fwsec -g 1.2.3.4         # Search every list and CrowdSec
fwsec -g 192.168.1.0/24  # Search for a CIDR range
fwsec -g example.com     # Resolve the domain and search for its IP addresses
```

The result identifies whether the address appears in `fwsec.allow`, `fwsec.deny`, temporary blocks, or CrowdSec decisions.

## Command reference

| Command | Description |
|---|---|
| `fwsec -v` | Show version information |
| `fwsec --upgrade` | Update fwsec from the GitHub repository, preserving all local configuration |
| `fwsec --geo-update` | Refresh country zone data and reload the geo sets |
| `fwsec --geo-status` | Show the geo policy status (mode, countries, CIDR counts) |
| `fwsec -l` | Show loaded rules, including every allowed port (TCP/UDP, inbound and outbound, plus the auto-detected SSH port and ICMP state) |
| `fwsec -s` | Start the firewall |
| `fwsec -f` | Stop the firewall |
| `fwsec -x` | Disable fwsec |
| `fwsec -e` | Enable fwsec |
| `fwsec -r` | Restart or reload the rules |
| `fwsec -c` | Validate the configuration |
| `fwsec -d IP` | Block an IP address permanently |
| `fwsec -d IP "reason"` | Block an IP address with a comment |
| `fwsec -td IP seconds "reason"` | Block an IP address temporarily |
| `fwsec -t` | Show temporary blocks |
| `fwsec -tr IP` | Remove a temporary block |
| `fwsec -dr IP` | Remove a permanent block |
| `fwsec -a IP` | Add an IP address to the allow list |
| `fwsec -a IP "reason"` | Add an IP address to the allow list with a comment |
| `fwsec -ar IP` | Remove an IP address from the allow list |
| `fwsec -g IP` | Search for an IP address in lists and rules |
| `fwsec -g domain` | Search for a domain |

## Country blocking (geo)

fwsec can enforce a country policy using nftables interval sets fed with
public CIDR zone data (ipdeny.com by default — no API key). Two modes,
mutually exclusive, set in `/etc/fwsec/fwsec.conf`:

```ini
[firewall]
GEO_BLOCK = "cn,ru"   # deny-list: drop traffic from the listed countries
GEO_ALLOW  = "br"     # deny all: drop everyone EXCEPT the listed countries
GEO_FORWARD = 0       # 1 = also apply the policy on the forward hook
```

The geo chain runs at priority -40 — after the fwsec deny list (-50) and
before the main filter (0). IPs in `fwsec.allow` **always override** the geo
policy (they are accepted first), so an admin IP listed there keeps access
regardless of country. In allow mode ("deny all"), loopback, link-local,
private and CGNAT ranges are always exempt — VM/container internal traffic
and DHCP keep working.

Workflow:

```bash
# 1. Set GEO_BLOCK or GEO_ALLOW in /etc/fwsec/fwsec.conf
# 2. Download the zone data and reload the sets:
sudo fwsec --geo-update
# 3. Check status (mode, countries, CIDR counts, data age):
sudo fwsec --geo-status
```

`fwsec -g IP` reports whether an IP is in the geo set and its country;
`fwsec -l` shows the active geo policy. Zone data older than 30 days is
flagged by `fwsec -c` and `--geo-status`. A failed download never removes
the currently applied sets — zones are written atomically and only flushed
once new data is fully in place.

## Configuration files

| File | Description |
|---|---|
| `/etc/fwsec/fwsec.conf` | Main configuration: ports, CrowdSec, and logging |
| `/etc/fwsec/fwsec.allow` | Permanent allow list containing IP addresses and CIDR ranges |
| `/etc/fwsec/fwsec.deny` | Permanent deny list containing IP addresses and CIDR ranges |
| `/etc/fwsec/fwsec.ignore` | IP addresses exempt from automatic bans |
| `/etc/fwsec/fwsec.state.json` | Internal state for temporary blocks and metadata |
| `/var/log/fwsec.log` | Operation log |

### Main `fwsec.conf` options

```ini
[firewall]
ENABLED    = 1           # 1 = enabled, 0 = disabled
TCP_IN     = 1157        # Allowed inbound TCP ports
TCP_OUT    = 80,443,53   # Allowed outbound TCP ports
UDP_IN     = 53          # Allowed inbound UDP ports
UDP_OUT    = 53,123      # Allowed outbound UDP ports
ICMP_IN    = 1           # Allow inbound ping
IPV6       = 1           # Enable IPv6 support

[containers]
CONTAINER_MODE   = 0     # 1 = host runs containers (Docker/Podman/nerdctl)
CONTAINER_POLICY = open  # open | filtered (restrict published ports to the allow list)

[crowdsec]
ENABLED    = 1           # Enable CrowdSec integration
SYNC_DENY  = 1           # Synchronize fwsec -d bans with CrowdSec decisions
```

## nftables architecture

fwsec operates with two parallel nftables tables:

```text
Inbound packet
      |
      v
+---------------------------------------------+
| table inet fwsec / chain whitelist          | priority -100
| ip saddr @allow4 -> ACCEPT immediately      |
+---------------------------------------------+
      | (not allow-listed)
      v
+---------------------------------------------+
| table inet fwsec / chain blacklist          | priority -50
| ip saddr @deny4 -> DROP                     |
+---------------------------------------------+
      | (not deny-listed)
      v
+---------------------------------------------+
| table inet filter / chain input             | priority 0
| established/related -> ACCEPT               |
| @crowdsec-blacklists -> DROP                |
| tcp dport <SSH> -> ACCEPT                   |
| policy: DROP                                |
+---------------------------------------------+
```

- **`@allow4` / `@allow6`** — sets managed by `fwsec -a`
- **`@deny4` / `@deny6`** — sets managed by `fwsec -d` and `fwsec -td`, with native timeouts
- **`@crowdsec-blacklists`** — sets managed automatically by the CrowdSec bouncer

The same allow/deny sets are also enforced on the **forward hook** (`whitelist_forward` at priority -100 and `blacklist_forward` at -50), so bans and allow rules cover traffic that is NATed to containers and never traverses the input hook.

## Container hosts (Docker / Podman / nerdctl)

Ports published by a container (`-p 80:80`) are DNATed before the input hook, so a conventional host firewall never sees that traffic — this is the classic "Docker bypasses the firewall" problem. fwsec addresses it natively:

- **Bans always reach containers.** The `fwsec -d` / `fwsec -td` deny sets and CrowdSec decisions are enforced on the forward hook as well, so a banned IP cannot reach a published container port.
- **`CONTAINER_MODE = 1`** keeps the main forward chain permissive (container networking keeps working) while still dropping CrowdSec-banned sources on forwarded traffic. With `CONTAINER_MODE = 0` the forward chain drops everything, which is correct for hosts without containers.
- **`CONTAINER_POLICY = filtered`** additionally restricts every externally published container port to the fwsec allow list: `fwsec -s` discovers the published ports at start time and builds a `containers` chain (priority -60) that drops new connections to them from any source not in `@allow4`/`@allow6`. Matching uses the original (pre-NAT) destination port via conntrack. `open` (the default) keeps Docker's normal behavior.
- **Container-aware commands.** `fwsec -l` lists port mappings of running containers (flagging localhost-only bindings), `fwsec -g IP` reports whether an IP belongs to a container or a container network, and `fwsec -c` warns when a runtime is detected but `CONTAINER_MODE` is off, and when published ports are unrestricted.
- **Safe persistence.** fwsec persists only its own tables to `/etc/nftables.conf`, never the full ruleset — persisting everything would freeze the dynamic rules Docker/Podman manage and restore stale copies of them at boot.

### Installer behavior on container hosts

During installation, fwsec detects Docker, Podman, and nerdctl. When a runtime is found (or when you answer that you plan to run containers later), the installer:

1. Enables `CONTAINER_MODE = 1` so the firewall never breaks container networking.
2. Lists the ports currently published by running containers.
3. Asks whether published ports should be restricted to the allow list (`CONTAINER_POLICY = filtered`).
4. Adds the detected container network subnets to `fwsec.ignore`, so internal container traffic is never banned (a busy internal proxy is a classic false positive).
5. Offers to enable CrowdSec log acquisition for containers (`/etc/crowdsec/acquis.d/fwsec-docker.yaml`, using `use_container_labels: true`), so attacks against containerized applications also generate bans. Label your containers (e.g. `crowdsec.labels.type=nginx`) so CrowdSec parses their logs with the right collection.
6. Prints default security recommendations: bind internal-only services to localhost (`-p 127.0.0.1:5432:5432`), never expose the engine socket (`docker.sock`), prefer rootless mode, and keep images from trusted registries.

## CrowdSec integration

When `SYNC_DENY = 1` (the default), `fwsec -d` and `fwsec -td` also create CrowdSec decisions:

```bash
fwsec -d 1.2.3.4 "SSH attack"
# -> nftables set deny4: immediate block
# -> cscli decisions add --ip 1.2.3.4: propagated to the bouncer

fwsec -td 1.2.3.4 3600 "Brute force"
# -> nftables set deny4 timeout 3600s: expires automatically
# -> cscli decisions add --duration 3600s
```

Show active CrowdSec decisions:

```bash
cscli decisions list
cscli alerts list
cscli metrics
```

## systemd service

```bash
systemctl status fwsec        # Show service status
systemctl start fwsec         # Start
systemctl stop fwsec          # Stop
systemctl restart fwsec       # Restart
systemctl enable fwsec        # Enable at boot
systemctl disable fwsec       # Disable at boot
journalctl -u fwsec -f        # Follow logs
```

On Alpine Linux the boot service is an OpenRC script instead: `rc-service fwsec start`, `rc-service fwsec stop`, `rc-update show default`.

## Practical examples

```bash
# Block an attacker for 24 hours and record the reason
fwsec -td 203.0.113.99 86400 "SSH brute force detected"

# Permanently allow an office IP address
fwsec -a 177.20.10.5 "Rio de Janeiro office"

# Check every list before allowing an IP address
fwsec -g 203.0.113.99

# Permanently block the address after investigation
fwsec -d 203.0.113.99 "Confirmed malicious"

# Reload every rule after manually editing fwsec.allow
fwsec -r

# Show the complete firewall state
fwsec -c && fwsec -l
```

## Development and governance

See [CONTRIBUTING.md](CONTRIBUTING.md) before preparing a change. Changes are submitted through pull requests and reviewed by the project maintainer, `@saulolimabrito`.

Do not disclose security vulnerabilities in public issues. Use **Security → Report a vulnerability** and follow [SECURITY.md](SECURITY.md).

## License

fwsec is licensed under the [GNU General Public License version 2 only](LICENSE), identified by the SPDX expression `GPL-2.0-only`. This is the same base license used by the Linux kernel; the kernel-specific syscall exception is not part of this project.
