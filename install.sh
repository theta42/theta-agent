#!/bin/bash
set -e

# --- Configuration ---
# In a real environment, these would be derived from the script's download URL
# or passed as additional arguments. For now, we use the most recent release.
BINARY_URL="https://github.com/theta42/theta-agent/releases/latest/download/theta-agent-linux-amd64"
CONFIG_DIR="/etc/theta42"
CONFIG_FILE="$CONFIG_DIR/agent.yml"
BIN_PATH="/usr/local/bin/theta-agent"
SERVICE_FILE="/etc/systemd/system/theta-agent.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1"; exit 1; }

# 1. Root check
if [ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]; then
  error "This script must be run as root."
fi

# Install SSSD and PAM integration packages if missing
install_sssd_deps() {
  if ! command -v sssd >/dev/null 2>&1; then
    log "Installing SSSD and PAM integration dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sssd sssd-ldap libnss-sss libpam-sss libsss-sudo libpam-runtime || \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sssd sssd-ldap libnss-sss libpam-sss || true
      if command -v pam-auth-update >/dev/null 2>&1; then
        pam-auth-update --package --enable mkhomedir sss || pam-auth-update --enable mkhomedir || true
      fi
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y sssd sssd-ldap sssd-tools || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y sssd sssd-ldap sssd-tools || true
    elif command -v pacman >/dev/null 2>&1; then
      pacman -S --noconfirm sssd || true
    elif command -v zypper >/dev/null 2>&1; then
      zypper in -y sssd || true
    fi
  else
    log "SSSD is already installed."
  fi
  mkdir -p /etc/sssd
  chmod 755 /etc/sssd
}

# Install the WireGuard userspace tools if missing.
#
# The kernel module ships with every supported kernel, so it is easy to assume
# WireGuard "is there" -- but `wg` and `wg-quick` come from a separate package
# that a Debian/Ubuntu desktop image does not include. Without them the agent
# enrols into the mesh, is allocated an address, gets a peer at the gateway and
# receives its pushed config, and then fails at `wg-quick up` with an exec
# error nobody sees. Every visible layer says the mesh is fine.
#
# Best-effort like install_sssd_deps: an air-gapped or unusual host must still
# finish installing the agent. But unlike SSSD this is not optional-by-flag,
# because the wireguard capability is on by default in the config written below.
install_wireguard_deps() {
  if command -v wg-quick >/dev/null 2>&1 && command -v wg >/dev/null 2>&1; then
    log "WireGuard tools are already installed."
    return 0
  fi
  log "Installing WireGuard userspace tools (wg, wg-quick)..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y wireguard-tools || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm wireguard-tools || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper in -y wireguard-tools || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache wireguard-tools || true
  fi
  if ! command -v wg-quick >/dev/null 2>&1; then
    # Not fatal -- everything except the mesh works without it -- but it must
    # not be silent, which is exactly how this got missed the first time.
    echo -e "${RED}[!]${NC} wg-quick is still not installed. The agent will enrol into the mesh but cannot bring the tunnel up; install your distribution's wireguard-tools package and restart theta-agent."
  fi
}

# 2. Argument Parsing
URL=""
TOKEN=""
JOIN_KEY=""
PUBLIC_KEY=""
B64_CONFIG=""
INSTALL_SSSD=0
# Discard the credentials this host already holds and enroll again from the
# join key, even when nothing else about the configuration changed.
RESET_KEYS=0
# auto | yes | no -- whether to install the desktop tray companion.
INSTALL_TRAY="auto"

while [ $# -gt 0 ]; do
  case $1 in
    --url)
      URL="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    # Base64 of the SSO's raw Ed25519 public key. The agent verifies high-risk
    # commands (reboot, configure_ldap, arbitrary_bash, update_binary) against
    # it and REFUSES them when it is absent, so an install without this key can
    # stream telemetry but cannot be acted on.
    --public-key)
      PUBLIC_KEY="$2"
      shift 2
      ;;
    # The one credential an operator hands out. The server exchanges it for a
    # per-agent token on first connect, which the agent writes back into
    # agent.yml -- so this is all you need to add a host.
    --join-key)
      JOIN_KEY="$2"
      shift 2
      ;;
    --install-sssd|--ldap)
      INSTALL_SSSD=1
      shift
      ;;
    # The tray is only useful where somebody can see it. Detection is automatic
    # (see host_is_desktop below); these override it either way.
    --tray)
      INSTALL_TRAY="yes"
      shift
      ;;
    --reset-keys|--reset-enrollment)
      RESET_KEYS=1
      shift
      ;;
    --no-tray|--headless)
      INSTALL_TRAY="no"
      shift
      ;;
    *)
      B64_CONFIG="$1"
      shift
      ;;
  esac
done

# Validation: require credentials ONLY if config file does not already exist.
# --url may be omitted when --join-key is given: `theta-agent discover` (below,
# after the binary download) can fill it in automatically when there is
# exactly one theta-suite site on the local network -- the common case for a
# fresh machine on a site's own LAN, and always admin-driven/one-time, never
# automatic once the agent is actually enrolled and running.
if [ ! -f "$CONFIG_FILE" ] && [ -z "$B64_CONFIG" ] && [ -z "$URL" ] && [ -z "$JOIN_KEY" ] && [ -z "$TOKEN" ]; then
  error "Missing required configuration. Provide a base64 encoded config, --join-key (URL optional, auto-discovered if omitted), or --url with --token."
  echo "Usage examples:"
  echo "  sh install.sh \"BASE64_CONFIG\""
  echo "  sh install.sh --join-key \"<your-join-key>\" --install-sssd    # auto-discovers --url if there's one site on the LAN"
  echo "  sh install.sh --url \"https://sso.local\" --join-key \"<your-join-key>\" --install-sssd"
  echo "  sh install.sh --url \"https://sso.local\" --token \"ISSUED_TOKEN\" --public-key \"BASE64_KEY\""
  echo ""
  echo "--join-key is the normal path: the host enrolls itself on first connect"
  echo "and the SSO issues it its own token + public key, which the agent writes"
  echo "back into agent.yml. Get a key from Directory -> Install Agent."
  exit 1
fi
# --token identifies a specific, already-issued credential for a specific
# server -- unlike --join-key, there's no "the one site on the LAN" fallback
# that makes sense here, so --url stays required for it.
if [ ! -f "$CONFIG_FILE" ] && [ -z "$B64_CONFIG" ] && [ -z "$URL" ] && [ -n "$TOKEN" ]; then
  error "--token requires --url (auto-discovery only applies to --join-key)."
fi

log "Starting Theta Agent installation..."

# Dependencies. install_sssd_deps existed here from the beginning and was
# never called once -- --install-sssd/--ldap set INSTALL_SSSD and nothing ever
# read it, so the flag documented in the usage text did nothing at all.
if [ "$INSTALL_SSSD" -eq 1 ]; then
  install_sssd_deps
fi
install_wireguard_deps

# Architecture and OS detection
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_NAME="$(uname -m)"
BINARY_NAME="theta-agent-linux-amd64"

case "$OS_NAME" in
  linux*)
    case "$ARCH_NAME" in
      x86_64|amd64) BINARY_NAME="theta-agent-linux-amd64" ;;
      aarch64|arm64) BINARY_NAME="theta-agent-linux-arm64" ;;
      armv7*|armhf) BINARY_NAME="theta-agent-linux-armv7" ;;
      *) BINARY_NAME="theta-agent-linux-amd64" ;;
    esac
    ;;
  darwin*)
    case "$ARCH_NAME" in
      x86_64|amd64) BINARY_NAME="theta-agent-darwin-amd64" ;;
      arm64|aarch64) BINARY_NAME="theta-agent-darwin-arm64" ;;
      *) BINARY_NAME="theta-agent-darwin-arm64" ;;
    esac
    ;;
  mingw*|msys*|cygwin*)
    case "$ARCH_NAME" in
      aarch64|arm64) BINARY_NAME="theta-agent-windows-arm64.exe" ;;
      *) BINARY_NAME="theta-agent-windows-amd64.exe" ;;
    esac
    ;;
esac

BINARY_URL="https://github.com/theta42/theta-agent/releases/latest/download/${BINARY_NAME}"

# 2b. Stop an agent that is already running before touching its binary.
#
# Re-running the installer on a managed host is the normal way to re-point or
# re-key it, and this step was missing: the new binary was moved over the old
# one while the old one was still executing. On Linux that leaves the RUNNING
# process on the previous inode, so the host keeps running the old agent until
# something restarts it -- an upgrade that reports success and changes nothing.
# The tray, which is a per-user unit, was never touched at all and kept talking
# to a socket the restarted daemon had replaced.
#
# Recorded, not assumed: a host where the agent was deliberately stopped should
# not be started by an upgrade.
AGENT_WAS_RUNNING=0
AGENT_WAS_INSTALLED=0
if command -v systemctl >/dev/null 2>&1; then
  # Ask systemd, not the filesystem.
  #
  # This used to be gated on `[ -f "$SERVICE_FILE" ]`, which is only ONE of the
  # places a theta-agent unit can live: a unit installed under /lib/systemd,
  # /usr/lib/systemd, or /etc/systemd/system/multi-user.target.wants (and a unit
  # whose file was deleted while the service kept running) all left
  # AGENT_WAS_INSTALLED at 0 -- so the running agent was never stopped and the
  # binary was replaced underneath it. `systemctl cat` finds the unit wherever
  # it is, and is-active answers for the process rather than for a path.
  if systemctl cat theta-agent.service >/dev/null 2>&1; then
    AGENT_WAS_INSTALLED=1
  fi
  if systemctl is-active --quiet theta-agent 2>/dev/null; then
    AGENT_WAS_INSTALLED=1
    AGENT_WAS_RUNNING=1
    log "An agent is already running -- stopping theta-agent before upgrading it."
    systemctl stop theta-agent >/dev/null 2>&1 || true
    # A stop can hang on an agent wedged in a syscall, and `systemctl stop`
    # reports failure only after its own timeout (90s by default). Give it a
    # bounded window and then take the unit down hard: the goal is an idle
    # binary, not a graceful shutdown.
    _waited=0
    while systemctl is-active --quiet theta-agent 2>/dev/null; do
      [ "$_waited" -ge 15 ] && break
      sleep 1
      _waited=$((_waited + 1))
    done
    if systemctl is-active --quiet theta-agent 2>/dev/null; then
      log "theta-agent did not stop within ${_waited}s -- killing it."
      systemctl kill -s KILL theta-agent >/dev/null 2>&1 || true
      sleep 1
    fi
  elif [ "$AGENT_WAS_INSTALLED" -eq 1 ]; then
    log "theta-agent is installed but not running -- upgrading in place."
  fi

  # Per-user tray units. They talk to the daemon over its IPC socket, so a tray
  # left running across an upgrade holds a stale connection.
  for _u in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
    systemctl --user --machine="${_u}@.host" stop theta-agent-tray.service >/dev/null 2>&1 || true
  done
fi

# Anything still executing the binary we are about to replace.
#
# systemd is not the only way an agent ends up running: a hand-started
# `theta-agent run`, an agent left over from a unit that was since removed, or
# one supervised by something other than systemd all keep the old inode alive.
# On Linux `mv -f` over a running binary SUCCEEDS and the live process carries
# on from the old inode, so the installer reports an upgrade that did not
# happen. Matched on the resolved executable path via /proc/<pid>/exe rather
# than on a name, so an unrelated process that merely mentions "theta-agent" in
# its command line is never signalled.
stop_stray_agents() {
  [ -x "$BIN_PATH" ] || return 0
  _target="$(readlink -f "$BIN_PATH" 2>/dev/null || echo "$BIN_PATH")"
  _found=0
  for _pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$_pid" = "$$" ] && continue
    _exe="$(readlink -f "/proc/$_pid/exe" 2>/dev/null || true)"
    [ "$_exe" = "$_target" ] || continue
    _found=1
    AGENT_WAS_RUNNING=1
    log "Found a stray agent still running as PID $_pid -- stopping it."
    kill "$_pid" 2>/dev/null || true
  done
  [ "$_found" -eq 0 ] && return 0
  # Same bounded-wait-then-kill shape as the unit above.
  _waited=0
  while [ "$_waited" -lt 10 ]; do
    _left=0
    for _pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
      [ "$_pid" = "$$" ] && continue
      _exe="$(readlink -f "/proc/$_pid/exe" 2>/dev/null || true)"
      [ "$_exe" = "$_target" ] && _left=1
    done
    [ "$_left" -eq 0 ] && return 0
    sleep 1
    _waited=$((_waited + 1))
  done
  for _pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$_pid" = "$$" ] && continue
    _exe="$(readlink -f "/proc/$_pid/exe" 2>/dev/null || true)"
    [ "$_exe" = "$_target" ] && kill -9 "$_pid" 2>/dev/null || true
  done
  sleep 1
}
stop_stray_agents

# 3. Install binary
log "Detected OS: $OS_NAME ($ARCH_NAME) -> Downloading binary $BINARY_NAME..."
curl -fsSL "$BINARY_URL" -o "$BIN_PATH.tmp" || error "Failed to download binary from $BINARY_URL"
chmod +x "$BIN_PATH.tmp"
mv -f "$BIN_PATH.tmp" "$BIN_PATH"

# 3b. Auto-discover --url via mDNS when it was omitted (join-key path only --
# see the validation above). Read-only lookup (`theta-agent discover
# --urls-only`, AGENT_LOCAL_DISCOVERY_SPEC.md); this script decides what to
# do with the result, the agent binary never acts on it by itself. Only ever
# auto-selects when there is EXACTLY one candidate -- ambiguity is a reason
# to ask the operator to be explicit, not a reason to guess.
if [ -z "$URL" ] && [ -n "$JOIN_KEY" ] && [ -z "$B64_CONFIG" ] && [ ! -f "$CONFIG_FILE" ]; then
  log "No --url given -- looking for a theta-suite site on the local network (mDNS)..."
  DISCOVERED="$("$BIN_PATH" discover --urls-only --timeout 3s 2>/dev/null || true)"
  DISCOVERED_COUNT="$(printf '%s\n' "$DISCOVERED" | grep -c . || true)"
  if [ "$DISCOVERED_COUNT" -eq 1 ]; then
    URL="$(printf '%s\n' "$DISCOVERED" | head -n1)"
    log "Found one site -- using $URL"
  elif [ "$DISCOVERED_COUNT" -gt 1 ]; then
    error "Found $DISCOVERED_COUNT theta-suite sites on the local network -- re-run with --url to pick one:
$DISCOVERED"
  else
    error "No theta-suite site found on the local network and --url was not given. Re-run with --url \"https://sso.example.com\", or check that this host can reach the site's LAN (mDNS doesn't cross routers/VLANs)."
  fi
fi

# 4. Setup configuration
log "Preparing configuration directory $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"

if [ -n "$B64_CONFIG" ]; then
  log "Decoding and writing configuration from base64..."
  echo "$B64_CONFIG" | base64 -d > "$CONFIG_FILE" || error "Failed to decode base64 configuration."
elif [ ! -f "$CONFIG_FILE" ]; then
  log "Generating minimal configuration from arguments..."
  cat <<EOF > "$CONFIG_FILE"
server_url: "$URL"
auth_token: "$TOKEN"
join_key: "$JOIN_KEY"
public_key: "$PUBLIC_KEY"
location: "default"
services: []
capabilities:
  telemetry: true
  configure_ldap: true
  ldap_tunnel: true
  service_registration: true
  # Mesh tunnel: auto-VPN, mesh enrolment, and the signed
  # wireguard_apply/remove commands. This key used to be omitted entirely,
  # which left the capability false by accident rather than by choice -- and
  # since it gates the whole auto-VPN path, the tray's "auto-connect VPN when
  # away" checkbox silently did nothing on every install.
  wireguard: true
  reboot: false
  service_control: []
  arbitrary_bash: false
EOF
else
  log "Merging into existing configuration at $CONFIG_FILE"
  # A config that already exists must not be clobbered, but a freshly supplied
  # --url/--token/--join-key/--public-key must not be silently dropped either:
  # re-running the installer with a new join key (or repairing a config that
  # never had one) is exactly when those flags are used.
  #
  # This used to be `sed -i "s|^key:.*|key: value|"` per key, which only
  # substitutes when the key is ALREADY in the file -- so the "repairing a
  # config that never had one" case silently dropped the value, and operators
  # had to delete agent.yml before new settings took effect. The agent binary
  # does the merge now: it appends keys that are missing, leaves comments and
  # every other setting alone, and validates the result parses before replacing
  # the file.
  # Does this re-run re-point the host at a different directory, or hand it a
  # different join key? If so the credentials it is holding are dead, and
  # keeping them is not neutral -- Config.Credential() PREFERS auth_token over
  # join_key, so a stale token from the previous directory is presented (and
  # rejected) on every single connect while the working join key beside it is
  # never tried. public_key fails the same way in the other direction: it is
  # the directory's Ed25519 signing key, so a rebuilt directory signs commands
  # this host cannot verify. Read the stored values BEFORE config-set
  # overwrites them.
  PRIOR_URL="$(sed -n 's/^server_url:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CONFIG_FILE" | head -n1)"
  PRIOR_JOIN_KEY="$(sed -n 's/^join_key:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CONFIG_FILE" | head -n1)"
  NEEDS_REENROLL=0
  if [ "$RESET_KEYS" -eq 1 ]; then
    NEEDS_REENROLL=1
    log "--reset-keys given -- this host will enroll from scratch."
  elif [ -n "$JOIN_KEY" ] && [ "$JOIN_KEY" != "$PRIOR_JOIN_KEY" ]; then
    NEEDS_REENROLL=1
    log "A different join key was supplied -- clearing the credentials issued under the old one."
  elif [ -n "$URL" ] && [ -n "$PRIOR_URL" ] && [ "$URL" != "$PRIOR_URL" ]; then
    NEEDS_REENROLL=1
    log "This host is being re-pointed from $PRIOR_URL to $URL -- clearing the old directory's credentials."
  fi

  CONFIG_SET_ARGS=""
  if [ -n "$URL" ];        then CONFIG_SET_ARGS="$CONFIG_SET_ARGS server_url=$URL"; fi
  if [ -n "$TOKEN" ];      then CONFIG_SET_ARGS="$CONFIG_SET_ARGS auth_token=$TOKEN"; fi
  if [ -n "$JOIN_KEY" ];   then CONFIG_SET_ARGS="$CONFIG_SET_ARGS join_key=$JOIN_KEY"; fi
  if [ -n "$PUBLIC_KEY" ]; then CONFIG_SET_ARGS="$CONFIG_SET_ARGS public_key=$PUBLIC_KEY"; fi

  if [ -n "$CONFIG_SET_ARGS" ]; then
    # shellcheck disable=SC2086 -- values are shell-word-safe (URLs, hex tokens,
    # base64 keys, a location slug) and must expand to separate arguments.
    if ! "$BIN_PATH" config-set --path "$CONFIG_FILE" $CONFIG_SET_ARGS; then
      error "Failed to merge new settings into $CONFIG_FILE."
    fi
  else
    log "No new settings supplied; leaving $CONFIG_FILE untouched."
  fi

  # After config-set, so the new join key is already in the file for the agent
  # to fall back on. reset-enrollment refuses when there is no join_key -- that
  # is a warning here rather than a failure, because a --url-only re-point of a
  # token-authenticated host is a legitimate thing to do; the operator just has
  # to supply the new token themselves.
  if [ "$NEEDS_REENROLL" -eq 1 ]; then
    RESET_FLAGS=""
    [ "$RESET_KEYS" -eq 1 ] && RESET_FLAGS="--keys"
    # shellcheck disable=SC2086 -- RESET_FLAGS is one optional literal flag.
    if ! "$BIN_PATH" reset-enrollment --path "$CONFIG_FILE" $RESET_FLAGS; then
      log "Could not clear the previous enrollment automatically -- if this host does not connect, check auth_token/public_key in $CONFIG_FILE."
    fi
  fi
fi
# 4b. Check the configuration is actually usable before installing a service
# around it.
#
# A config carrying a public_key that does not decode, or no credential at all,
# produces an agent that starts, connects, and then rejects every signed command
# the Directory sends -- visible only in the journal, on a host the operator was
# just told had installed successfully. `theta-agent verify` exits non-zero when
# something will stop the agent working, so the installer can say so here
# instead.
log "Verifying configuration and keys..."
if ! "$BIN_PATH" verify --path "$CONFIG_FILE"; then
  error "The configuration at $CONFIG_FILE will not work (see above). Fix it, or re-run with --url/--token/--join-key/--public-key to replace the bad values."
fi

# Ensure theta-secrets & theta groups exist for non-root secret access
log "Configuring non-root secret access groups (theta-secrets)..."
if command -v groupadd >/dev/null 2>&1; then
  getent group theta-secrets >/dev/null 2>&1 || groupadd -r theta-secrets 2>/dev/null || true
  getent group theta >/dev/null 2>&1 || groupadd -r theta 2>/dev/null || true
fi
SECRETS_GROUP="root"
if getent group theta-secrets >/dev/null 2>&1; then
  SECRETS_GROUP="theta-secrets"
elif getent group theta >/dev/null 2>&1; then
  SECRETS_GROUP="theta"
fi
chown -R "root:$SECRETS_GROUP" "$CONFIG_DIR" 2>/dev/null || true
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_FILE"

# 4c. Setup Desktop Tray Icon companion
TRAY_BINARY_NAME="theta-agent-tray-${OS_NAME}-${ARCH_NAME}"
case "$OS_NAME" in
  linux*)
    case "$ARCH_NAME" in
      aarch64|arm64) TRAY_BINARY_NAME="theta-agent-tray-linux-arm64" ;;
      *) TRAY_BINARY_NAME="theta-agent-tray-linux-amd64" ;;
    esac
    ;;
  windows*) TRAY_BINARY_NAME="theta-agent-tray-windows-amd64.exe" ;;
esac
TRAY_BIN_PATH="/usr/local/bin/theta-agent-tray"
TRAY_URL="https://github.com/theta42/theta-agent/releases/latest/download/${TRAY_BINARY_NAME}"

# host_is_desktop reports whether this machine has a graphical environment a
# tray icon could appear in.
#
# The installer used to download the tray and install a user unit on every host,
# headless servers included -- so a rack machine got a systray binary, a
# graphical-session.target unit that can never activate, and a line in the
# install log promising it "will start at the next desktop login" that was never
# going to happen.
#
# No single signal is reliable on its own: a desktop can be mid-boot with no
# session yet, and a machine being provisioned over SSH has no session for the
# installer to look at. So several are consulted and any one is sufficient.
#
# `systemctl get-default` is deliberately NOT one of them. It looks like the
# authoritative answer and is not: measured on two headless theta-suite servers,
# both reported graphical.target as their default while having no display
# manager, no /usr/share/xsessions entries, no wayland sessions and no X socket.
# Plenty of server images ship that default. Using it would call every one of
# those hosts a desktop, which is the bug being fixed.
host_is_desktop() {
  # 1. A logind session that is graphical RIGHT NOW. Conclusive when it fires.
  #    Type matters: a headless server being provisioned over SSH also has
  #    sessions, they are just tty ones.
  if command -v loginctl >/dev/null 2>&1; then
    for _sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
      case "$(loginctl show-session "$_sid" -p Type --value 2>/dev/null)" in
        x11|wayland|mir) DESKTOP_REASON="a graphical session is running"; return 0 ;;
      esac
    done
  fi

  # 2. An enabled display manager: a GUI is meant to run here, even if nobody
  #    is logged into it at the moment.
  if command -v systemctl >/dev/null 2>&1; then
    for _dm in gdm gdm3 sddm lightdm xdm lxdm slim greetd ly cosmic-greeter; do
      if systemctl is-enabled --quiet "${_dm}.service" 2>/dev/null; then
        DESKTOP_REASON="display manager ${_dm} is enabled"
        return 0
      fi
    done
  fi

  # 3. Installed session definitions -- a desktop environment is present to be
  #    logged into, whatever manages the login.
  for _d in /usr/share/xsessions /usr/share/wayland-sessions; do
    if [ -d "$_d" ] && [ -n "$(ls -A "$_d" 2>/dev/null)" ]; then
      DESKTOP_REASON="desktop sessions are installed in $_d"
      return 0
    fi
  done

  # 4. A live X display socket. Catches a running X server that logind does not
  #    know about (a bare startx, an X session outside a seat).
  if [ -n "$(ls -A /tmp/.X11-unix 2>/dev/null)" ]; then
    DESKTOP_REASON="an X display socket is present"
    return 0
  fi

  return 1
}

DESKTOP_REASON=""
INSTALL_TRAY_DECIDED="$INSTALL_TRAY"
if [ "$INSTALL_TRAY" = "auto" ]; then
  if host_is_desktop; then
    INSTALL_TRAY_DECIDED="yes"
    log "This host looks like a desktop ($DESKTOP_REASON) -- installing the tray companion."
  else
    INSTALL_TRAY_DECIDED="no"
    log "No graphical environment detected -- skipping the desktop tray companion."
    log "Install it anyway with: --tray"
  fi
fi

# Guard first so the tray binary is not even downloaded on a headless host.
# Written as a no-op branch rather than by wrapping everything below, which
# would re-indent the whole block for no benefit.
if [ "$INSTALL_TRAY_DECIDED" != "yes" ]; then
  :
elif curl -fsSL "$TRAY_URL" -o "$TRAY_BIN_PATH.tmp" 2>/dev/null; then
  log "Installing desktop tray companion ($TRAY_BINARY_NAME)..."
  chmod +x "$TRAY_BIN_PATH.tmp"
  mv -f "$TRAY_BIN_PATH.tmp" "$TRAY_BIN_PATH"

  # A systemd *user* unit rather than an XDG autostart entry. The old
  # /etc/xdg/autostart/.desktop only fired at the next desktop login, so the
  # installer left the machine with no tray until the user logged out and back
  # in -- and over SSH there was no session to fire it at all. A user unit can
  # be enabled for all future sessions AND started in the sessions running
  # right now. Remove the old autostart file so the two do not both launch.
  rm -f /etc/xdg/autostart/theta-agent-tray.desktop
  mkdir -p /etc/systemd/user
  cat <<EOF > /etc/systemd/user/theta-agent-tray.service
[Unit]
Description=Theta Agent Desktop Tray Companion
# Only meaningful inside a graphical session; without this the unit would also
# be started for plain SSH/user managers, where the tray just exits.
PartOf=graphical-session.target
After=graphical-session.target

[Service]
Type=simple
ExecStart=$TRAY_BIN_PATH
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  # Enable for every future user session.
  systemctl --global enable theta-agent-tray.service >/dev/null 2>&1 || true

  # Start it in the graphical sessions that already exist, so the tray shows up
  # without a re-login. Ask logind which sessions those are rather than guessing
  # at DISPLAY -- the user manager already holds the right session environment.
  started_any=0
  if command -v loginctl >/dev/null 2>&1; then
    while read -r _sid _uid _user _rest; do
      [ -n "${_user:-}" ] || continue
      _type="$(loginctl show-session "$_sid" --property=Type --value 2>/dev/null || true)"
      case "$_type" in
        x11|wayland|mir) ;;
        *) continue ;;
      esac
      # Already running for this user? Leave it alone.
      if pgrep -u "$_user" -x theta-agent-tray >/dev/null 2>&1; then
        started_any=1
        continue
      fi
      if systemctl --user --machine="${_user}@.host" daemon-reload >/dev/null 2>&1 &&
         systemctl --user --machine="${_user}@.host" start theta-agent-tray.service >/dev/null 2>&1; then
        log "Started tray in ${_user}'s $_type session."
        started_any=1
      fi
    done <<LOGINCTL
$(loginctl list-sessions --no-legend 2>/dev/null || true)
LOGINCTL
  fi

  if [ "$started_any" -eq 1 ]; then
    log "Desktop tray companion installed at $TRAY_BIN_PATH and running."
  else
    log "Desktop tray companion installed at $TRAY_BIN_PATH; it will start at the next desktop login."
  fi
else
  # Only reachable when the tray was wanted and the download failed. Not fatal
  # -- the agent itself is installed and working -- but it used to pass in
  # silence, which is how a desktop ended up with no tray and no explanation.
  log "Could not download the tray companion from $TRAY_URL -- the agent is installed without it."
fi

# 5. Setup systemd service
log "Creating systemd service unit..."
# Man page. Generated by the binary itself from the same command registry that
# backs `theta-agent help`, so `man theta-agent` cannot describe a different CLI
# than the one installed.
if command -v mandb >/dev/null 2>&1 || [ -d /usr/share/man ]; then
  MAN_DIR="/usr/share/man/man8"
  if mkdir -p "$MAN_DIR" 2>/dev/null && "$BIN_PATH" help --man > "$MAN_DIR/theta-agent.8" 2>/dev/null; then
    chmod 644 "$MAN_DIR/theta-agent.8"
    # Best-effort: an out-of-date index only costs `man -k`, and mandb is slow
    # enough that failing the install over it would be the wrong trade.
    mandb -q >/dev/null 2>&1 || true
    log "Installed man page: man theta-agent"
  else
    log "Could not install the man page (continuing)."
  fi
fi

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Theta Agent Unified Endpoint Management
After=network.target

[Service]
Type=simple
ExecStart=$BIN_PATH
Restart=always
RestartSec=5
SyslogIdentifier=theta-agent

[Install]
WantedBy=multi-user.target
EOF

# 6. Start the agent
#
# On a fresh install, always. On an upgrade, only if it was running when we
# started -- an operator who had deliberately stopped the agent on this host
# should not find it running again because they installed a newer build.
log "Enabling and starting Theta Agent..."
systemctl daemon-reload
systemctl enable theta-agent
if [ "$AGENT_WAS_INSTALLED" -eq 0 ] || [ "$AGENT_WAS_RUNNING" -eq 1 ]; then
  systemctl start theta-agent
else
  log "theta-agent was stopped before this upgrade -- leaving it stopped."
  log "Start it with: systemctl start theta-agent"
fi

log "Theta Agent installation complete!"
log "Verify status with: systemctl status theta-agent"
log "Check logs with: journalctl -u theta-agent -f"

# --- 7. Install shell tab-completion for the CLI ----------------------------
log "Installing shell tab-completion for theta-agent..."
mkdir -p /usr/share/bash-completion/completions
cp -f "$(dirname "$0")/../completions/theta-agent.bash" /usr/share/bash-completion/completions/theta-agent 2>/dev/null \
  || curl -fsSL "https://github.com/theta42/theta-agent/releases/latest/download/theta-agent.bash" -o /usr/share/bash-completion/completions/theta-agent 2>/dev/null \
  || true

mkdir -p /usr/share/zsh/site-functions
cp -f "$(dirname "$0")/../completions/theta-agent.zsh" /usr/share/zsh/site-functions/_theta-agent 2>/dev/null \
  || curl -fsSL "https://github.com/theta42/theta-agent/releases/latest/download/theta-agent.zsh" -o /usr/share/zsh/site-functions/_theta-agent 2>/dev/null \
  || true

if [ -d /etc/bash_completion.d ]; then
  ln -sf /usr/share/bash-completion/completions/theta-agent /etc/bash_completion.d/theta-agent 2>/dev/null || true
fi
log "Shell tab-completion installed."
