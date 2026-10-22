#!/bin/bash
# Builds build/ClaudeSwitcher.app (ad-hoc signed).
set -euo pipefail
cd "$(dirname "$0")"
APP=build/ClaudeSwitcher.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp Info.plist "$APP/Contents/Info.plist"
xcrun swiftc -O -swift-version 5 -parse-as-library -target "$(uname -m)-apple-macos13.0" \
  Sources/ClaudeSwitcher.swift -o "$APP/Contents/MacOS/ClaudeSwitcher"
codesign --force --sign - "$APP" >/dev/null
echo "Built $APP"
