#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/furkanyild09/PurgeKit.git"
INSTALL_ROOT="${PURGEKIT_HOME:-$HOME/.purgekit}"
VENV_DIR="$INSTALL_ROOT/venv"
BIN_DIR="$HOME/.local/bin"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "PurgeKit is designed for macOS." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required. Install Xcode Command Line Tools or Python 3.9+." >&2
  exit 1
fi

echo "Installing PurgeKit into $VENV_DIR..."
mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet --upgrade "git+$REPO_URL"

ln -sf "$VENV_DIR/bin/purgekit" "$BIN_DIR/purgekit"
if [ ! -e "$BIN_DIR/PurgeKit" ]; then
  ln -sf "$VENV_DIR/bin/purgekit" "$BIN_DIR/PurgeKit"
fi

ZSHRC="$HOME/.zshrc"
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
if [ -f "$ZSHRC" ]; then
  if ! grep -qs '\.local/bin' "$ZSHRC"; then
    printf '\n# Added by PurgeKit installer\n%s\n' "$PATH_LINE" >> "$ZSHRC"
  fi
else
  printf '# Added by PurgeKit installer\n%s\n' "$PATH_LINE" > "$ZSHRC"
fi

echo ""
echo "PurgeKit installed successfully!"
if ! command -v purgekit >/dev/null 2>&1; then
  echo "Run 'source ~/.zshrc' (or open a new terminal), then type:"
else
  echo "Launch anytime by typing:"
fi
echo "  purgekit"
