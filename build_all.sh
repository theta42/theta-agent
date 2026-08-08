#!/usr/bin/env bash
set -e

# Cross-compilation script for Theta Agent across Linux (amd64, arm64, armv7), Windows (amd64, arm64), and macOS (amd64, arm64).

DIST_DIR="./dist"
mkdir -p "$DIST_DIR"

LDFLAGS="-s -w"

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

echo "  -> darwin/amd64 (macOS Intel)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-darwin-amd64"

echo "  -> darwin/arm64 (macOS Apple Silicon)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$DIST_DIR/theta-agent-darwin-arm64"

echo ""
echo "Build complete! Artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"
