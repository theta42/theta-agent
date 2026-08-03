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
if [ "$EUID" -ne 0 ]; then
  error "This script must be run as root."
fi

# 2. Argument Parsing
URL=""
TOKEN=""
B64_CONFIG=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --url)
      URL="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    *)
      B64_CONFIG="$1"
      shift
      ;;
  esac
done

# Validation
if [ -z "$B64_CONFIG" ] && [ -z "$URL" ] || [ -z "$B64_CONFIG" ] && [ -z "$TOKEN" ]; then
  error "Missing required configuration. Either provide a base64 encoded config, or both --url and --token."
  echo "Usage examples:"
  echo "  sh install.sh \"BASE64_CONFIG\""
  echo "  sh install.sh --url \"https://sso.local\" --token \"secret-token\""
  exit 1
fi

log "Starting Theta Agent installation..."

# 3. Install binary
log "Downloading binary from $BINARY_URL..."
curl -fsSL "$BINARY_URL" -o "$BIN_PATH" || error "Failed to download binary."
chmod +x "$BIN_PATH"

# 4. Setup configuration
log "Preparing configuration directory $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"

if [ -n "$B64_CONFIG" ]; then
  log "Decoding and writing configuration from base64..."
  echo "$B64_CONFIG" | base64 -d > "$CONFIG_FILE" || error "Failed to decode base64 configuration."
else
  log "Generating minimal configuration from arguments..."
  # Create a minimal yaml with the provided URL and Token
  cat <<EOF > "$CONFIG_FILE"
server_url: "$URL"
auth_token: "$TOKEN"
location: "unknown"
capabilities:
  telemetry: true
  configure_ldap: false
  reboot: false
  service_control: []
  arbitrary_bash: false
EOF
fi
chmod 600 "$CONFIG_FILE"

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
StandardOutput=syslog
StandardError=syslog
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
