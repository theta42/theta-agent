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

# Validation: require credentials ONLY if config file does not already exist
if [ ! -f "$CONFIG_FILE" ] && [ -z "$B64_CONFIG" ] && { [ -z "$URL" ] || { [ -z "$TOKEN" ] && [ -z "$JOIN_KEY" ]; }; }; then
  error "Missing required configuration. Provide a base64 encoded config, or --url with either --join-key or --token."
  echo "Usage examples:"
  echo "  sh install.sh \"BASE64_CONFIG\""
  echo "  sh install.sh --url \"https://sso.local\" --join-key \"tjk_...\" --install-sssd"
  echo "  sh install.sh --url \"https://sso.local\" --token \"ISSUED_TOKEN\" --public-key \"BASE64_KEY\""
  echo ""
  echo "--join-key is the normal path: the host enrolls itself on first connect"
  echo "and the SSO issues it its own token + public key, which the agent writes"
  echo "back into agent.yml. Get a key from Directory -> Install Agent."
  exit 1
fi

log "Starting Theta Agent installation..."

# 3. Install binary
log "Downloading binary from $BINARY_URL..."
curl -fsSL "$BINARY_URL" -o "$BIN_PATH.tmp" || error "Failed to download binary."
chmod +x "$BIN_PATH.tmp"
mv -f "$BIN_PATH.tmp" "$BIN_PATH"

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
capabilities:
  telemetry: true
  configure_ldap: true
  ldap_tunnel: true
  reboot: false
  service_control: []
  arbitrary_bash: false
EOF
else
  log "Preserving existing configuration at $CONFIG_FILE"
fi
chmod 600 "$CONFIG_FILE"

# An agent with no public_key cannot verify signed commands and will refuse
# every one of them. That is the safe default, but it is silent at run time, so
# say it plainly here where the operator is watching.
if ! grep -qE '^public_key:[[:space:]]*"[^"]+"' "$CONFIG_FILE" 2>/dev/null; then
  log "WARNING: no public_key configured — this agent will report telemetry but"
  log "         REFUSE reboot / configure_ldap / arbitrary_bash / update_binary."
  log "         Re-run with --public-key \"<base64 key>\" (shown at enrollment)."
fi

# 4b. Ensure SSSD dependencies are installed if configure_ldap is enabled
if [ "$INSTALL_SSSD" -eq 1 ] || grep -qE -i 'configure_ldap:[[:space:]]*true' "$CONFIG_FILE" 2>/dev/null; then
  install_sssd_deps
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
