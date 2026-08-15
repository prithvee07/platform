#!/bin/sh
# openbin installer — https://openbin.ai/install.sh
#
#   curl -fsSL https://openbin.ai/install.sh | sh
#
# Installs the `openbin` CLI (decompile APKs and native binaries on your own
# machine, upload the result to your OpenAPK/OpenBin account). POSIX sh, no
# dependencies beyond curl/tar that every Unix already has.
#
# What it does:
#   1. Detects your OS (linux/macos) + CPU arch (amd64/arm64).
#   2. Downloads the matching CLI binary from the latest GitHub release
#      (just the binary — ~10 MB; the Docker worker images are pulled
#      lazily the first time you decompile).
#   3. Installs to ~/.local/bin (no sudo) and makes sure it's on your PATH.
#
# Env overrides:
#   OPENBIN_INSTALL_DIR   where to put the binary   (default ~/.local/bin)
#   OPENBIN_RELEASE_BASE  release asset base URL    (default GitHub latest)
set -eu

REPO="openbin-ai/platform"
RELEASE_BASE="${OPENBIN_RELEASE_BASE:-https://github.com/$REPO/releases/latest/download}"
INSTALL_DIR="${OPENBIN_INSTALL_DIR:-$HOME/.local/bin}"

info() { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  MINGW*|MSYS*|CYGWIN*) die "this is the Unix installer. On Windows, run in PowerShell:
    irm https://openbin.ai/install.ps1 | iex" ;;
  *) die "unsupported OS '$os' — openbin ships for Linux, macOS, and Windows.
On Windows, run in PowerShell:  irm https://openbin.ai/install.ps1 | iex" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "unsupported CPU arch '$arch' (need x86_64 or arm64)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required but not found"
command -v tar  >/dev/null 2>&1 || die "tar is required but not found"

ASSET="openbin-${OS}-${ARCH}.tar.gz"
URL="$RELEASE_BASE/$ASSET"

# --- download + extract ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "Downloading $ASSET from the latest release..."
if ! curl -fSL --progress-bar "$URL" -o "$tmp/$ASSET"; then
  die "download failed: $URL
Is there a published release yet? See https://github.com/$REPO/releases"
fi

# Verify against the published sha256 sidecar before running anything from
# this archive. Fail closed: no sidecar (or a mismatch) aborts the install
# rather than trusting bytes off the wire on TLS alone.
info "Verifying checksum..."
if ! curl -fsSL "$URL.sha256" -o "$tmp/$ASSET.sha256"; then
  die "could not fetch $URL.sha256 — refusing to install an unverified binary"
fi
expected="$(awk '{print $1}' "$tmp/$ASSET.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$ASSET" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$ASSET" | awk '{print $1}')"
else
  die "need sha256sum or shasum to verify the download"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $ASSET: expected $expected, got $actual — refusing to install a tampered download"

info "Extracting..."
tar -xzf "$tmp/$ASSET" -C "$tmp"
# Tarball extracts to openbin-<os>-<arch>/openbin — find the binary wherever
# it landed so we don't hard-depend on the directory layout.
bin="$(find "$tmp" -type f -name openbin | head -n1)"
[ -n "$bin" ] || die "could not find the openbin binary inside $ASSET"
chmod +x "$bin"

# --- install ---------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
mv "$bin" "$INSTALL_DIR/openbin"
info "Installed openbin to $INSTALL_DIR/openbin"

ver="$("$INSTALL_DIR/openbin" --version 2>/dev/null || echo 'openbin (version unknown)')"
info "$ver"

# --- PATH setup ------------------------------------------------------------
# If INSTALL_DIR is already on PATH we're done. Otherwise append an export to
# the user's shell rc files (idempotently) so new shells pick it up, and tell
# them how to use it in the current shell right now.
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    path_ok=1 ;;
  *)
    path_ok=0 ;;
esac

if [ "$path_ok" -eq 0 ]; then
  line="export PATH=\"$INSTALL_DIR:\$PATH\""
  marker="# added by openbin install.sh"
  changed=0
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    # Only touch rc files that exist, plus always ensure ~/.profile as the
    # POSIX fallback so a login shell gets it even with no bash/zsh rc.
    if [ -f "$rc" ] || [ "$rc" = "$HOME/.profile" ]; then
      if ! grep -qF "$marker" "$rc" 2>/dev/null; then
        printf '\n%s\n%s\n' "$marker" "$line" >> "$rc"
        changed=1
      fi
    fi
  done
  [ "$changed" -eq 1 ] && info "Added $INSTALL_DIR to your PATH in your shell profile."
  warn "$INSTALL_DIR isn't on your PATH in THIS shell yet. Either open a new terminal, or run:"
  printf '    export PATH="%s:$PATH"\n' "$INSTALL_DIR"
fi

# --- next steps ------------------------------------------------------------
cat <<EOF

openbin is installed. Next steps:

  openbin login                 # one-time browser sign-in
  openbin apk app-release.apk   # decompile an APK locally, upload the result
  openbin decompile firmware.elf  # native binary (Ghidra)

The first decompile downloads the worker Docker image (one-time, cached after).
Docker must be installed and running. Questions / sponsorship: husam@openbin.ai
EOF
