#!/usr/bin/env bash
# NetWatcher — one-shot installer.
# Verifies prerequisites, enables pnpm via corepack, installs deps,
# and prints the pfctl sudoers hint. Does NOT touch sudoers itself.
#
# Flags:
#   -y, --yes    Skip the pre-run confirmation prompt.
#   -h, --help   Show this help and exit.

set -euo pipefail

cd "$(dirname "$0")"

# ─── Constants ──────────────────────────────────────────────────────────
TOTAL_STEPS=7
CURRENT_USER="${USER:-$(id -un)}"

YELLOW=$'\033[1;33m'
GREEN=$'\033[1;32m'
RED=$'\033[1;31m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

# ─── Helpers ────────────────────────────────────────────────────────────
info()  { printf "%s==>%s %s\n" "$GREEN" "$RESET" "$*"; }
warn()  { printf "%s!!%s  %s\n" "$YELLOW" "$RESET" "$*"; }
fail()  { printf "%sxx%s  %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }
step()  { printf "\n%s==>%s %s[%s/%s]%s %s\n" "$GREEN" "$RESET" "$BOLD" "$1" "$TOTAL_STEPS" "$RESET" "$2"; }

print_help() {
  # Self-document by emitting the leading comment block.
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

# ─── Arg parsing ────────────────────────────────────────────────────────
AUTO_YES=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) AUTO_YES=1 ;;
    -h|--help) print_help; exit 0 ;;
    *) fail "Unknown flag: $arg (try --help)" ;;
  esac
done

# ─── Pre-run summary ────────────────────────────────────────────────────
cat <<EOF
${BOLD}NetWatcher setup — will run ${TOTAL_STEPS} steps:${RESET}

  ${GREEN}1.${RESET} Platform check        — confirm macOS (Darwin)
  ${GREEN}2.${RESET} Tool check            — node, corepack, lsof, ps, /sbin/pfctl, sudo on PATH
  ${GREEN}3.${RESET} Node version          — require >= 20
  ${GREEN}4.${RESET} pnpm via corepack     — enable + activate the version pinned in package.json
  ${GREEN}5.${RESET} Install dependencies  — ${BOLD}pnpm install --frozen-lockfile${RESET} (writes node_modules/)
  ${GREEN}6.${RESET} Typecheck             — ${BOLD}pnpm typecheck${RESET} sanity run
  ${GREEN}7.${RESET} Post-install checks   — detect ${BOLD}vt${RESET} CLI and passwordless pfctl sudo;
                            ${DIM}print sudoers hint if needed (does NOT modify sudoers)${RESET}

${DIM}Writes to this directory (node_modules/) and to your user-global caches:
corepack → ~/.cache/node/corepack, pnpm store → ~/Library/pnpm/store
(or ~/.local/share/pnpm/store). Nothing is written as root.${RESET}
EOF

# ─── Confirmation ───────────────────────────────────────────────────────
if [[ "$AUTO_YES" -eq 0 ]]; then
  printf "\nContinue? [y/N] "
  if ! read -r reply; then
    # EOF (e.g. Ctrl-D or a non-interactive invocation without -y)
    printf "\n"; info "Aborted (no input)."; exit 130
  fi
  case "$reply" in
    y|Y|yes|YES) ;;
    *) info "Aborted."; exit 130 ;;
  esac
fi

# ─── 1. Platform ────────────────────────────────────────────────────────
step 1 "Platform check"
if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "NetWatcher is macOS-only (requires lsof + pfctl). Detected: $(uname -s)"
fi
info "macOS $(sw_vers -productVersion)"

# ─── 2. Required tools ──────────────────────────────────────────────────
step 2 "Tool check"
for tool in node corepack lsof ps /sbin/pfctl sudo; do
  if ! command -v "$tool" >/dev/null 2>&1 && [[ ! -x "$tool" ]]; then
    fail "Missing required tool: $tool"
  fi
done
info "All required tools present"

# ─── 3. Node version ────────────────────────────────────────────────────
step 3 "Node version"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if (( NODE_MAJOR < 20 )); then
  fail "Node.js >= 20 required. Detected: $(node --version)"
fi
info "Node.js $(node --version)"

# ─── 4. pnpm via corepack ───────────────────────────────────────────────
step 4 "Enable pnpm via corepack"
corepack enable >/dev/null 2>&1 || warn "corepack enable failed (may need sudo on system Node). Continuing."
corepack prepare --activate >/dev/null 2>&1 || true
if ! command -v pnpm >/dev/null 2>&1; then
  fail "pnpm not on PATH after corepack enable. Try: corepack enable --install-directory ~/.local/bin"
fi
info "pnpm $(pnpm --version)"

# ─── 5. Install dependencies ────────────────────────────────────────────
step 5 "Install dependencies"
pnpm install --frozen-lockfile

# ─── 6. Typecheck ───────────────────────────────────────────────────────
step 6 "Typecheck"
pnpm typecheck

# ─── 7. Post-install checks ─────────────────────────────────────────────
step 7 "Post-install checks"

if command -v vt >/dev/null 2>&1; then
  info "VirusTotal CLI found: $(vt --version 2>&1 | head -n1)"
else
  warn "VirusTotal CLI (\`vt\`) not installed — the 'VT' button will show an install hint."
  printf "   %sInstall with: brew install virustotal-cli && vt init%s\n" "$DIM" "$RESET"
fi

SUDOERS_FILE="/etc/sudoers.d/netwatcher"
if sudo -n /sbin/pfctl -s info >/dev/null 2>&1; then
  info "Passwordless sudo for pfctl: OK"
else
  warn "Passwordless sudo for pfctl is NOT configured."
  printf "   The Block/Unblock buttons will fail until you add a sudoers entry.\n"
  printf "   %sRun:%s\n" "$DIM" "$RESET"
  printf "     sudo visudo -f %s\n" "$SUDOERS_FILE"
  printf "   %sAdd (using your current username %s%s%s):%s\n" "$DIM" "$BOLD" "$CURRENT_USER" "$RESET$DIM" "$RESET"
  printf "     Cmnd_Alias NETWATCHER_PFCTL = /sbin/pfctl -a netwatcher *, /sbin/pfctl -e\n"
  printf "     %s  ALL=(root) NOPASSWD: NETWATCHER_PFCTL\n" "$CURRENT_USER"
fi

echo
info "Setup complete."
printf "   Start the dev server: %spnpm dev%s  (then open http://localhost:3847)\n" "$GREEN" "$RESET"
