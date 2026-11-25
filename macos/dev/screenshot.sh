#!/bin/sh
# Capture the app's window without disturbing the user: starts a separate Sweep instance in the background
# (no focus change), captures only its window, then quits that instance.
# usage: macos/dev/screenshot.sh out.png [launch args...]   e.g. --security --security-page launch --expand
# Env: WAIT=seconds before capture (default 6); APP=path of the app to capture (default: target/Sweep.app;
# use /Applications/Sweep.app when the installed copy matters, e.g. it owns the background watch).
set -eu
out=$1; shift
dir=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$dir/../.." && pwd)
bin="$repo/target/dev/winid"
mkdir -p "$repo/target/dev"
[ "$bin" -nt "$dir/winid.swift" ] 2>/dev/null || swiftc -O "$dir/winid.swift" -o "$bin"
app=${APP:-$repo/target/Sweep.app}
open -n -g "$app" --args "$@"
sleep 1
pid=$(pgrep -n -f "$app/Contents/MacOS/Sweep")
trap 'kill "$pid" 2>/dev/null' EXIT # always quit our instance, even on error
# The first launch after a rebuild is slow: wait (up to 20 s) for the window to exist.
id=""
for _ in $(seq 1 40); do
  id=$("$bin" "$pid")
  [ -n "$id" ] && break
  sleep 0.5
done
[ -n "$id" ] || { echo "no window for pid $pid" >&2; exit 1; }
sleep "${WAIT:-6}" # let the content load (scans, audits)
screencapture -x -o -l "$id" "$out"
echo "$out"
