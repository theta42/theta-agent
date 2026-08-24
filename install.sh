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

# 2. Argument Parsing
URL=""
TOKEN=""
JOIN_KEY=""
PUBLIC_KEY=""
B64_CONFIG=""
INSTALL_SSSD=0

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
location: "unknown"
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

log "Attempting to install desktop tray companion ($TRAY_BINARY_NAME)..."
if curl -fsSL "$TRAY_URL" -o "$TRAY_BIN_PATH.tmp" 2>/dev/null; then
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
fi

# 5. Setup systemd service
log "Creating systemd service unit..."
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
log "Enabling and starting Theta Agent..."
systemctl daemon-reload
systemctl enable theta-agent
systemctl start theta-agent

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
