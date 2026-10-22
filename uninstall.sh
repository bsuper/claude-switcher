#!/bin/bash
# Removes Claude Switcher. Pass --purge to also delete its saved logins and settings.
# Claude Desktop keeps whichever account is signed in right now either way.
set -euo pipefail

pkill -x ClaudeSwitcher 2>/dev/null || true
rm -rf "$HOME/Applications/ClaudeSwitcher.app"
echo "✓ Removed ~/Applications/ClaudeSwitcher.app"

DATA="$HOME/Library/Application Support/ClaudeSwitcher"
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$DATA"
  echo "✓ Deleted saved logins, backups and settings ($DATA)"
else
  echo "  Saved logins and settings are kept in: $DATA"
  echo "  Run ./uninstall.sh --purge to delete them too."
fi
