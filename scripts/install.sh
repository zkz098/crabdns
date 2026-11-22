#!/bin/sh
# CrabDNS automatic deployment script for Linux (systemd) and OpenWrt (procd).
set -eu

REPO="${CRABDNS_REPO:-zkz098/crabdns}"
VERSION="${CRABDNS_VERSION:-latest}"
MIRROR="${CRABDNS_MIRROR:-}"
LOCAL_BIN=""
INSTALL_BIN="/usr/bin/crabdns"
CONFIG_DIR="/etc/crabdns"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DATA_DIR=""
DNS_LISTEN=""
WEB_LISTEN="0.0.0.0:3000"
OPENWRT_DNSMASQ="none"
UNINSTALL=0
PURGE=0

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Deploy or upgrade CrabDNS on Linux (systemd) or OpenWrt (procd).

Options:
  --version <tag>            Release tag to install (default: latest)
  --repo <owner/repo>        GitHub repository (default: zkz098/crabdns)
  --mirror <prefix>          Download mirror prefix (e.g. https://gh-proxy.com/)
  --bin <path>               Install from a local binary instead of downloading
  --install-path <path>      Target binary path (default: /usr/bin/crabdns)
  --config <path>            Config file path (default: /etc/crabdns/config.toml)
  --data-dir <path>          Data directory (default: /etc/crabdns/data on OpenWrt, /var/lib/crabdns on Linux)
  --dns-listen <addr>        DNS listen address (default: 0.0.0.0:5353, or 0.0.0.0:53 with takeover)
  --web-listen <addr>        Web UI listen address (default: 0.0.0.0:3000)
  --openwrt-dnsmasq <mode>   OpenWrt dnsmasq integration: none | upstream | takeover (default: none)
  --uninstall                Stop, disable, and remove CrabDNS binary and service
  --purge                    Also remove config and data directory when uninstalling
  -h, --help                 Show this help message
EOF
}

log() {
    printf '[crabdns-install] %s\n' "$*"
}

err() {
    printf '[crabdns-install] ERROR: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"
}

is_openwrt() {
    [ -f /etc/openwrt_release ] || [ -x /sbin/procd ]
}

detect_platform() {
    os="$(uname -s)"
    arch="$(uname -m)"
    [ "$os" = "Linux" ] || err "Unsupported OS: $os (this script supports Linux/OpenWrt only)"

    case "$arch" in
        x86_64|amd64)
            printf 'linux-x86_64'
            ;;
        aarch64|arm64)
            printf 'linux-aarch64'
            ;;
        *)
            err "Unsupported architecture: $arch"
            ;;
    esac
}

http_get() {
    url="$1"
    out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url"
    else
        err "Neither curl nor wget is available"
    fi
}

resolve_latest_tag() {
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    tmp_json="$1"
    http_get "$api_url" "$tmp_json"
    tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp_json" | head -n 1)"
    [ -n "$tag" ] || err "Failed to resolve latest release tag from $api_url"
    printf '%s' "$tag"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || err "--version requires an argument"
            VERSION="$2"
            shift 2
            ;;
        --repo)
            [ $# -ge 2 ] || err "--repo requires an argument"
            REPO="$2"
            shift 2
            ;;
        --mirror)
            [ $# -ge 2 ] || err "--mirror requires an argument"
            MIRROR="$2"
            shift 2
            ;;
        --bin)
            [ $# -ge 2 ] || err "--bin requires an argument"
            LOCAL_BIN="$2"
            shift 2
            ;;
        --install-path)
            [ $# -ge 2 ] || err "--install-path requires an argument"
            INSTALL_BIN="$2"
            shift 2
            ;;
        --config)
            [ $# -ge 2 ] || err "--config requires an argument"
            CONFIG_FILE="$2"
            CONFIG_DIR="$(dirname "$CONFIG_FILE")"
            shift 2
            ;;
        --data-dir)
            [ $# -ge 2 ] || err "--data-dir requires an argument"
            DATA_DIR="$2"
            shift 2
            ;;
        --dns-listen)
            [ $# -ge 2 ] || err "--dns-listen requires an argument"
            DNS_LISTEN="$2"
            shift 2
            ;;
        --web-listen)
            [ $# -ge 2 ] || err "--web-listen requires an argument"
            WEB_LISTEN="$2"
            shift 2
            ;;
        --openwrt-dnsmasq)
            [ $# -ge 2 ] || err "--openwrt-dnsmasq requires an argument"
            OPENWRT_DNSMASQ="$2"
            shift 2
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            ;;
    esac
done

[ "$(id -u)" -eq 0 ] || err "Please run as root (or via sudo)"

if [ -z "$DATA_DIR" ]; then
    if is_openwrt; then
        DATA_DIR="/etc/crabdns/data"
    else
        DATA_DIR="/var/lib/crabdns"
    fi
fi

if [ -z "$DNS_LISTEN" ]; then
    if [ "$OPENWRT_DNSMASQ" = "takeover" ]; then
        DNS_LISTEN="0.0.0.0:53"
    else
        DNS_LISTEN="0.0.0.0:5353"
    fi
fi

uninstall_crabdns() {
    if is_openwrt; then
        if [ -x /etc/init.d/crabdns ]; then
            /etc/init.d/crabdns stop >/dev/null 2>&1 || true
            /etc/init.d/crabdns disable >/dev/null 2>&1 || true
            rm -f /etc/init.d/crabdns
        fi
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl stop crabdns >/dev/null 2>&1 || true
        systemctl disable crabdns >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/crabdns.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    rm -f "$INSTALL_BIN"
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$CONFIG_DIR" "$DATA_DIR"
        log "Uninstalled CrabDNS and purged config/data."
    else
        log "Uninstalled CrabDNS binary and service (preserved $CONFIG_DIR and $DATA_DIR)."
    fi
}

if [ "$UNINSTALL" -eq 1 ]; then
    uninstall_crabdns
    exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ -n "$LOCAL_BIN" ]; then
    [ -f "$LOCAL_BIN" ] || err "Local binary not found: $LOCAL_BIN"
    SRC_BIN="$LOCAL_BIN"
    log "Using local binary: $SRC_BIN"
else
    require_cmd tar
    require_cmd sha256sum
    PLATFORM="$(detect_platform)"

    if [ "$VERSION" = "latest" ]; then
        log "Resolving latest release from $REPO..."
        VERSION="$(resolve_latest_tag "${TMP_DIR}/release.json")"
    fi
    case "$VERSION" in
        v*) ;;
        *) VERSION="v${VERSION}" ;;
    esac

    ARCHIVE="crabdns-${VERSION}-${PLATFORM}.tar.gz"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    ARCHIVE_URL="${MIRROR}${BASE_URL}/${ARCHIVE}"
    SHA_URL="${MIRROR}${BASE_URL}/${ARCHIVE}.sha256"

    log "Downloading ${ARCHIVE}..."
    http_get "$ARCHIVE_URL" "${TMP_DIR}/${ARCHIVE}"
    http_get "$SHA_URL" "${TMP_DIR}/${ARCHIVE}.sha256"

    (
        cd "$TMP_DIR"
        sha256sum -c "${ARCHIVE}.sha256"
    )

    tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
    SRC_BIN="${TMP_DIR}/crabdns"
    [ -f "$SRC_BIN" ] || err "Extracted archive does not contain crabdns binary"
fi

# Stop existing service before replacing binary
if is_openwrt && [ -x /etc/init.d/crabdns ]; then
    /etc/init.d/crabdns stop >/dev/null 2>&1 || true
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet crabdns 2>/dev/null; then
    systemctl stop crabdns || true
fi

mkdir -p "$(dirname "$INSTALL_BIN")" "$CONFIG_DIR" "$DATA_DIR"
cp "$SRC_BIN" "${INSTALL_BIN}.new"
chmod 0755 "${INSTALL_BIN}.new"
mv "${INSTALL_BIN}.new" "$INSTALL_BIN"
log "Installed binary to $INSTALL_BIN"

if [ ! -f "$CONFIG_FILE" ]; then
    cat >"$CONFIG_FILE" <<EOF
listen_dns = "${DNS_LISTEN}"
listen_web = "${WEB_LISTEN}"
data_dir = "${DATA_DIR}"
EOF
    log "Created default config at $CONFIG_FILE"
else
    log "Preserving existing config at $CONFIG_FILE"
fi

configure_openwrt_dnsmasq() {
    mode="$1"
    [ "$mode" = "none" ] && return 0
    require_cmd uci

    case "$mode" in
        upstream)
            dns_port="${DNS_LISTEN##*:}"
            uci set dhcp.@dnsmasq[0].noresolv='1'
            uci delete dhcp.@dnsmasq[0].server >/dev/null 2>&1 || true
            uci add_list "dhcp.@dnsmasq[0].server=127.0.0.1#${dns_port}"
            uci commit dhcp
            /etc/init.d/dnsmasq restart
            log "Configured dnsmasq to forward DNS queries to 127.0.0.1#${dns_port}"
            ;;
        takeover)
            uci set dhcp.@dnsmasq[0].port='0'
            uci commit dhcp
            /etc/init.d/dnsmasq restart
            log "Disabled dnsmasq DNS (port=0); CrabDNS will handle port 53 directly"
            ;;
        *)
            err "Invalid --openwrt-dnsmasq mode: $mode (expected: none, upstream, takeover)"
            ;;
    esac
}

if is_openwrt; then
    cat >/etc/init.d/crabdns <<EOF
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

PROG="${INSTALL_BIN}"
CONF="${CONFIG_FILE}"

start_service() {
    procd_open_instance
    procd_set_param command "\$PROG" --config "\$CONF"
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param limits nofile="65536 65536"
    procd_close_instance
}
EOF
    chmod 0755 /etc/init.d/crabdns
    configure_openwrt_dnsmasq "$OPENWRT_DNSMASQ"
    /etc/init.d/crabdns enable
    /etc/init.d/crabdns restart
    log "OpenWrt procd service enabled and started."
    if [ "$OPENWRT_DNSMASQ" = "none" ]; then
        log "Note: dnsmasq was not modified. Configure dnsmasq forwarding or re-run with --openwrt-dnsmasq upstream|takeover."
    fi
elif command -v systemctl >/dev/null 2>&1; then
    cat >/etc/systemd/system/crabdns.service <<EOF
[Unit]
Description=CrabDNS Ad-blocking DNS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_BIN} --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable crabdns
    systemctl restart crabdns
    log "systemd service enabled and started."
else
    log "No procd or systemd detected. Start manually with: $INSTALL_BIN --config $CONFIG_FILE"
fi

log "Deployment complete. Web UI listening on http://${WEB_LISTEN} (DNS: ${DNS_LISTEN})."
