#!/bin/sh
# Build target/Sweep.app: the Rust core (static lib) + the SwiftUI front end, ad-hoc signed.
# Needs only the Command Line Tools (no Xcode).
set -eu
cd "$(dirname "$0")/.."
cargo build --release -p sweep-ffi -p sweep-cli
swift build -c release --package-path macos
APP=target/Sweep.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers"
# The CLI, used by the background watch LaunchAgent (`sweep watch --install` points the agent at this copy).
cp target/release/sweep "$APP/Contents/Helpers/sweep"
codesign --force --sign - --options runtime --entitlements macos/Sweep.entitlements "$APP/Contents/Helpers/sweep"
cp "$(swift build -c release --package-path macos --show-bin-path)/Sweep" "$APP/Contents/MacOS/Sweep"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.sweep.Sweep</string>
  <key>CFBundleName</key><string>Sweep</string>
  <key>CFBundleExecutable</key><string>Sweep</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - --options runtime --entitlements macos/Sweep.entitlements "$APP"
echo "built $APP"
