#!/bin/bash
# Builds Claude Switcher from source, installs it to ~/Applications and launches it.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "✗ $*" >&2; exit 1; }

[[ "$(uname)" == "Darwin" ]] || fail "Claude Switcher only runs on macOS."
major=$(sw_vers -productVersion | cut -d. -f1)
(( major >= 13 )) || fail "macOS 13 (Ventura) or later is required (you have $(sw_vers -productVersion))."
if ! xcrun --find swiftc >/dev/null 2>&1; then
  echo "✗ The Swift compiler isn't installed. Install Apple's Command Line Tools:" >&2
  echo "    xcode-select --install" >&2
  fail "then run ./install.sh again."
fi
if [[ -z "$(mdfind "kMDItemCFBundleIdentifier == 'com.anthropic.claudefordesktop'" 2>/dev/null)" && ! -d /Applications/Claude.app ]]; then
  echo "! Claude Desktop wasn't found — get it from https://claude.ai/download" >&2
fi

echo "→ Building…"
./build.sh

echo "→ Installing to ~/Applications…"
mkdir -p "$HOME/Applications"
pkill -x ClaudeSwitcher 2>/dev/null && sleep 1 || true
rm -rf "$HOME/Applications/ClaudeSwitcher.app"
cp -R build/ClaudeSwitcher.app "$HOME/Applications/"
open "$HOME/Applications/ClaudeSwitcher.app"

cat <<'MSG'
✓ Claude Switcher is running — look for the ring icon in your menu bar.

macOS is about to ask for permissions, one at a time. Approve each one now so
nothing interrupts you later:
  - Access to Claude Desktop's data: Allow
  - "Claude Safe Storage" in Keychain: Always Allow
The menu bar panel shows a checklist of what's been granted. Switching the Chrome
extension also needs Full Disk Access; the panel's Grant Access button walks you through it.

Next:
  1. Click the icon → "Import Current Login" and name the account you're signed in with.
  2. "Add Account" → Claude reopens signed out → sign in with your next account.
MSG
