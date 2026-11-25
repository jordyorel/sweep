#!/bin/sh
# Build target/Sweep-<version>.dmg for a GitHub Release: Sweep.app, a link to /Applications to drag it onto,
# and a short note on opening an app that is not notarized. Prints the SHA-256 for the release notes.
set -eu
cd "$(dirname "$0")/.."
macos/build-app.sh
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DMG="target/Sweep-$VERSION.dmg"
STAGE=target/dmg
rm -rf "$STAGE" "$DMG"
mkdir -p "$STAGE"
ditto target/Sweep.app "$STAGE/Sweep.app"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/If macOS blocks Sweep.txt" <<'EOF'
Sweep is not notarized by Apple yet, so macOS blocks it the first time you open it.

1. Drag Sweep to Applications, then try to open it once and click "Done" on the warning.
2. Open System Settings > Privacy & Security.
3. Scroll down to the message about Sweep, click "Open Anyway", and confirm with your password.

You only need to do this once. The source code is public:
https://github.com/jordyorel/sweep
EOF
hdiutil create -volname "Sweep $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$DMG" >/dev/null
rm -rf "$STAGE"
echo "built $DMG ($(du -h "$DMG" | cut -f1 | tr -d ' '))"
echo "sha256: $(shasum -a 256 "$DMG" | cut -d' ' -f1)"
