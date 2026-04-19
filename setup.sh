#!/usr/bin/env bash
# NetWatcher — one-shot installer.
# Verifies prerequisites, enables pnpm via corepack, installs deps,
# and prints the pfctl sudoers hint. Does NOT touch sudoers itself.

set -euo pipefail

cd "$(dirname "$0")"

YELLOW=$'\033[1;33m'
GREEN=$'\033[1;32m'
RED=$'\033[1;31m'
DIM=$'\033[2m'
RESET=$'\033[0m'

info()  { printf "%s==>%s %s\n" "$GREEN" "$RESET" "$*"; }
warn()  { printf "%s!!%s  %s\n" "$YELLOW" "$RESET" "$*"; }
fail()  { printf "%sxx%s  %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }

# ─── Platform ───────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "NetWatcher is macOS-only (requires lsof + pfctl). Detected: $(uname -s)"
fi
info "Platform: macOS $(sw_vers -productVersion)"

# ─── Required tools ─────────────────────────────────────────────────────
for tool in node corepack lsof ps /sbin/pfctl sudo; do
  if ! command -v "$tool" >/dev/null 2>&1 && [[ ! -x "$tool" ]]; then
    fail "Missing required tool: $tool"
  fi
done

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if (( NODE_MAJOR < 20 )); then
  fail "Node.js >= 20 required. Detected: $(node --version)"
fi
info "Node.js: $(node --version)"

# ─── Enable pnpm via corepack ───────────────────────────────────────────
info "Enabling pnpm via corepack…"
corepack enable >/dev/null 2>&1 || warn "corepack enable failed (may need sudo on system Node). Continuing."
# This installs the exact pnpm version pinned in package.json.
corepack prepare --activate >/dev/null 2>&1 || true

if ! command -v pnpm >/dev/null 2>&1; then
  fail "pnpm not on PATH after corepack enable. Try: corepack enable --install-directory ~/.local/bin"
fi
info "pnpm: $(pnpm --version)"

# ─── Install dependencies ───────────────────────────────────────────────
info "Installing dependencies (pnpm install)…"
pnpm install --frozen-lockfile

# ─── Typecheck sanity ───────────────────────────────────────────────────
info "Running typecheck…"
pnpm typecheck

# ─── Optional: VirusTotal CLI ───────────────────────────────────────────
if command -v vt >/dev/null 2>&1; then
  info "VirusTotal CLI found: $(vt --version 2>&1 | head -n1)"
else
  warn "VirusTotal CLI (\`vt\`) not installed — the 'VT' button will show an install hint."
  printf "   %sInstall with: brew install virustotal-cli && vt init%s\n" "$DIM" "$RESET"
fi

# ─── pfctl sudoers hint ─────────────────────────────────────────────────
SUDOERS_FILE="/etc/sudoers.d/netwatcher"
if sudo -n /sbin/pfctl -s info >/dev/null 2>&1; then
  info "Passwordless sudo for pfctl: OK"
else
  warn "Passwordless sudo for pfctl is NOT configured."
  printf "   The Block/Unblock buttons will fail until you add a sudoers entry.\n"
  printf "   %sRun:%s\n" "$DIM" "$RESET"
  printf "     sudo visudo -f %s\n" "$SUDOERS_FILE"
  printf "   %sAdd (replace %s\$USER%s with your username):%s\n" "$DIM" "$RESET" "$DIM" "$RESET"
  printf "     Cmnd_Alias NETWATCHER_PFCTL = /sbin/pfctl -a netwatcher *, /sbin/pfctl -e\n"
  printf "     %s  ALL=(root) NOPASSWD: NETWATCHER_PFCTL\n" "$USER"
fi

echo
info "Setup complete."
printf "   Start the dev server: %spnpm dev%s  (then open http://localhost:3847)\n" "$GREEN" "$RESET"
