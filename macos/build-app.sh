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
# App icon, drawn by macos/icon/make-icon.swift (regenerated only when the script changes).
ICON=target/icon/AppIcon.icns
if [ ! -f "$ICON" ] || [ macos/icon/make-icon.swift -nt "$ICON" ]; then
  rm -rf target/icon && mkdir -p target/icon/AppIcon.iconset
  swift macos/icon/make-icon.swift target/icon/icon-1024.png >/dev/null
  for s in 16 32 128 256 512; do
    sips -z $s $s target/icon/icon-1024.png --out "target/icon/AppIcon.iconset/icon_${s}x${s}.png" >/dev/null
    sips -z $((s*2)) $((s*2)) target/icon/icon-1024.png --out "target/icon/AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns target/icon/AppIcon.iconset -o "$ICON"
fi
mkdir -p "$APP/Contents/Resources"
cp "$ICON" "$APP/Contents/Resources/AppIcon.icns"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.sweep.Sweep</string>
  <key>CFBundleName</key><string>Sweep</string>
  <key>CFBundleExecutable</key><string>Sweep</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - --options runtime --entitlements macos/Sweep.entitlements "$APP"
echo "built $APP"
