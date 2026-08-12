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
  # A config that already exists must not be clobbered, but a freshly supplied
  # --url/--token/--join-key/--public-key must not be silently dropped either:
  # re-running the installer with a new join key (or repairing a config that
  # never had one) is exactly when those flags are used. Update just the lines
  # the operator actually provided, leaving everything else untouched.
  if [ -n "$URL" ]; then
    sed -i "s|^server_url:.*|server_url: \"$URL\"|" "$CONFIG_FILE"
  fi
  if [ -n "$TOKEN" ]; then
    sed -i "s|^auth_token:.*|auth_token: \"$TOKEN\"|" "$CONFIG_FILE"
  fi
  if [ -n "$JOIN_KEY" ]; then
    sed -i "s|^join_key:.*|join_key: \"$JOIN_KEY\"|" "$CONFIG_FILE"
  fi
  if [ -n "$PUBLIC_KEY" ]; then
    sed -i "s|^public_key:.*|public_key: \"$PUBLIC_KEY\"|" "$CONFIG_FILE"
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
  mkdir -p /etc/xdg/autostart
  cat <<EOF > /etc/xdg/autostart/theta-agent-tray.desktop
[Desktop Entry]
Type=Application
Name=Theta Agent Tray
Comment=Theta Agent Desktop Tray Companion
Exec=/usr/local/bin/theta-agent-tray
Icon=network-workgroup
Terminal=false
Categories=Utility;System;
X-GNOME-Autostart-enabled=true
EOF
  log "Desktop tray companion installed at $TRAY_BIN_PATH with autostart."
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
