#!/bin/sh
# Build Sweep and install it in /Applications. Run again after an update.
# If the background watch is on, it is re-pointed at the installed copy.
set -eu
cd "$(dirname "$0")/.."
macos/build-app.sh
DEST=/Applications/Sweep.app
if pgrep -f "$DEST/Contents/MacOS/Sweep" >/dev/null; then
  echo "Sweep is running from $DEST: quit it first, then run this again." >&2
  exit 1
fi
# Replace the previous copy (moved to the Trash, never deleted).
if [ -e "$DEST" ]; then
  mv "$DEST" "$HOME/.Trash/Sweep $(date +%Y-%m-%d_%H%M%S).app"
fi
ditto target/Sweep.app "$DEST"
echo "installed $DEST"
# Background watch: re-install so its LaunchAgent runs the installed helper, keeping the current frequency.
if [ -f "$HOME/Library/LaunchAgents/dev.sweep.watch.plist" ]; then
  hours=$(( $(plutil -extract StartInterval raw "$HOME/Library/LaunchAgents/dev.sweep.watch.plist") / 3600 ))
  "$DEST/Contents/Helpers/sweep" watch --install --every-hours "$hours"
fi
