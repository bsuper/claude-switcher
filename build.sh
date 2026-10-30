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

# Sign with a stable local identity so macOS privacy grants and Keychain "Always Allow" survive rebuilds.
# (Ad-hoc signatures change every build, and macOS treats each build as a new app.) The identity lives in
# its own keychain file; its password only guards this self-signed, local-only certificate.
SIGN_DIR="$HOME/Library/Application Support/ClaudeSwitcher/signing"
KC="$SIGN_DIR/signing.keychain-db"; KC_PW="claude-switcher-local"; IDENTITY="Claude Switcher Local"
if ! security find-identity -p codesigning "$KC" 2>/dev/null | grep -q "$IDENTITY"; then
  echo "→ Creating a local signing identity (one time)…"
  mkdir -p "$SIGN_DIR"; TMP=$(mktemp -d)
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/k.pem" -out "$TMP/c.pem" -days 3650 \
    -subj "/CN=$IDENTITY" -addext "extendedKeyUsage=critical,codeSigning" \
    -addext "keyUsage=critical,digitalSignature" -addext "basicConstraints=critical,CA:false" 2>/dev/null
  openssl pkcs12 -export -inkey "$TMP/k.pem" -in "$TMP/c.pem" -out "$TMP/id.p12" -passout pass:x -legacy 2>/dev/null \
    || openssl pkcs12 -export -inkey "$TMP/k.pem" -in "$TMP/c.pem" -out "$TMP/id.p12" -passout pass:x
  security delete-keychain "$KC" 2>/dev/null || true
  security create-keychain -p "$KC_PW" "$KC"
  security set-keychain-settings "$KC"
  security unlock-keychain -p "$KC_PW" "$KC"
  security import "$TMP/id.p12" -k "$KC" -P x -T /usr/bin/codesign >/dev/null
  security set-key-partition-list -S apple-tool:,apple: -s -k "$KC_PW" "$KC" >/dev/null
  rm -rf "$TMP"
fi
security unlock-keychain -p "$KC_PW" "$KC"
if ! codesign --force --keychain "$KC" --sign "$IDENTITY" "$APP" >/dev/null 2>&1; then
  echo "! Stable signing failed; falling back to ad-hoc (permissions will reset on each rebuild)" >&2
  codesign --force --sign - "$APP" >/dev/null
fi
echo "Built $APP"
