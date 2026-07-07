# hunt-common.sh — shared helpers for the hunt-land toolkit
# Sourced by every hunt-* tool. Must stay bash 3.2 compatible (macOS default).

HUNT_VERSION="1.0.0"

case "$(uname -s)" in
    Linux)  HUNT_PLATFORM="linux" ;;
    Darwin) HUNT_PLATFORM="macos" ;;
    *)      HUNT_PLATFORM="unknown" ;;
esac

# Colors only when stdout is a terminal
if [ -t 1 ]; then
    C_RED=$(printf '\033[31m'); C_YEL=$(printf '\033[33m')
    C_GRN=$(printf '\033[32m'); C_CYN=$(printf '\033[36m')
    C_BLD=$(printf '\033[1m');  C_RST=$(printf '\033[0m')
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_BLD=""; C_RST=""
fi

# Findings accumulate here (TSV: severity, ATT&CK id, message).
# The orchestrator exports HUNT_FINDINGS so all phases share one file.
if [ -z "${HUNT_FINDINGS:-}" ]; then
    HUNT_FINDINGS=$(mktemp "${TMPDIR:-/tmp}/hunt-findings.XXXXXX")
fi

hunt_ts()      { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
hunt_header()  { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_RST"; }
hunt_info()    { printf '%s[*]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
hunt_ok()      { printf '%s[ok]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
hunt_warn()    { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }

# finding <HIGH|MEDIUM|LOW> <ATT&CK-id> <message>
finding() {
    _sev=$1; _atk=$2; shift 2
    case "$_sev" in
        HIGH)   _c=$C_RED ;;
        MEDIUM) _c=$C_YEL ;;
        *)      _c=$C_CYN ;;
    esac
    printf '%s[%s]%s (%s) %s\n' "$_c" "$_sev" "$C_RST" "$_atk" "$*"
    printf '%s\t%s\t%s\n' "$_sev" "$_atk" "$*" >> "$HUNT_FINDINGS"
}

finding_summary() {
    _h=$(grep -c '^HIGH'   "$HUNT_FINDINGS" 2>/dev/null); _h=${_h:-0}
    _m=$(grep -c '^MEDIUM' "$HUNT_FINDINGS" 2>/dev/null); _m=${_m:-0}
    _l=$(grep -c '^LOW'    "$HUNT_FINDINGS" 2>/dev/null); _l=${_l:-0}
    hunt_header "Findings summary"
    printf '  %sHIGH: %s%s   %sMEDIUM: %s%s   LOW: %s\n' \
        "$C_RED" "$_h" "$C_RST" "$C_YEL" "$_m" "$C_RST" "$_l"
    if [ "$_h" -eq 0 ] && [ "$_m" -eq 0 ] && [ "$_l" -eq 0 ]; then
        hunt_ok "nothing suspicious recorded by this tool"
    fi
}

require_root_or_warn() {
    if [ "$(id -u)" -ne 0 ]; then
        hunt_warn "not running as root — some processes/sockets/files will be invisible; findings are a lower bound"
    fi
}

# is_private_ip <ipv4> → 0 if RFC1918/loopback/link-local
is_private_ip() {
    case "$1" in
        10.*|192.168.*|127.*|169.254.*|0.0.0.0|::1|fe80:*|::) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    esac
    return 1
}
