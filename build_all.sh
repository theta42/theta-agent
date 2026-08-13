#!/usr/bin/env bash
set -e

# Cross-compilation script for Theta Agent across Linux (amd64, arm64, armv7), Windows (amd64, arm64), and macOS (amd64, arm64).

DIST_DIR="./dist"
mkdir -p "$DIST_DIR"

LDFLAGS="-s -w"
# Windows GUI binaries (tray, helper) build as GUI-subsystem so no console
# window pops up when the installer starts the tray or the service spawns the
# helper. The agent stays a console app (handy for foreground debugging; as a
# Windows service it never shows a console anyway).
GUI_LDFLAGS="$LDFLAGS -H=windowsgui"

echo "Building Theta Agent binaries..."

echo "  -> linux/amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-linux-amd64"

echo "  -> linux/arm64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-linux-arm64"

echo "  -> linux/armv7..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-linux-armv7"

echo "  -> windows/amd64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-windows-amd64.exe"

echo "  -> windows/arm64..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-windows-arm64.exe"

echo "  -> windows/amd64 helper..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$GUI_LDFLAGS" -o "$DIST_DIR/theta-agent-helper-windows-amd64.exe" ./cmd/theta-agent-helper/

echo "  -> windows/arm64 helper..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$GUI_LDFLAGS" -o "$DIST_DIR/theta-agent-helper-windows-arm64.exe" ./cmd/theta-agent-helper/

echo "  -> darwin/amd64 (macOS Intel)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-darwin-amd64"

echo "  -> darwin/arm64 (macOS Apple Silicon)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-darwin-arm64"

echo "Building Theta Agent Tray binaries..."
echo "  -> linux/amd64 tray..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-tray-linux-amd64" ./cmd/theta-agent-tray/

echo "  -> linux/arm64 tray..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-tray-linux-arm64" ./cmd/theta-agent-tray/

echo "  -> windows/amd64 tray..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$GUI_LDFLAGS" -o "$DIST_DIR/theta-agent-tray-windows-amd64.exe" ./cmd/theta-agent-tray/

echo "  -> windows/arm64 tray..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="$GUI_LDFLAGS" -o "$DIST_DIR/theta-agent-tray-windows-arm64.exe" ./cmd/theta-agent-tray/

echo "Copying shell tab-completion scripts..."
cp completions/theta-agent.bash "$DIST_DIR/theta-agent.bash"
cp completions/theta-agent.zsh "$DIST_DIR/theta-agent.zsh"

echo ""
echo "Build complete! Artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"
