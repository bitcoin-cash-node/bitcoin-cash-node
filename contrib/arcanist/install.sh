#!/usr/bin/env bash

export LC_ALL=C

set -eu

ARC_REPO="https://github.com/phorgeit/arcanist.git"
ARC_REF="63de5a2953b79dbe6aac4ed92bdb64b45cad53d6" # 2026.27

ARC_INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/arcanist"
ARC_BIN_DIR="$HOME/.local/bin"
ARC_BIN="$ARC_INSTALL_DIR/bin/arc"
ARC_LINK="$ARC_BIN_DIR/arc"

got_requirements="yes"

install_hint() {
    echo "Install it with:"
    echo "    $1"
}

need_command() {
    cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi
    got_requirements="no"
    echo "Error: Required command not found: $cmd"
    if command -v apt-get >/dev/null 2>&1; then
        if [[ "$cmd" == "php" ]]; then
            cmd="php-cli"
        fi
        install_hint "sudo apt-get update && sudo apt-get install $cmd"
    elif command -v brew >/dev/null 2>&1; then
        install_hint "brew install $cmd"
    elif command -v dnf >/dev/null 2>&1; then
        if [[ "$cmd" == "php" ]]; then
            cmd="php-cli"
        fi
        install_hint "sudo dnf install $cmd"
    else
        echo "Please install '$cmd' using your system package manager."
    fi
}

need_php_extension() {
    ext="$1"
    if php -r "exit(extension_loaded('$ext') ? 0 : 1);" >/dev/null 2>&1; then
        return 0
    fi
    got_requirements="no"
    echo "Error: Required PHP extension not available: $ext"
    if command -v apt-get >/dev/null 2>&1; then
        install_hint "sudo apt-get update && sudo apt-get install php-$ext"
    elif command -v brew >/dev/null 2>&1; then
        install_hint "brew install php-$ext"
    elif command -v dnf >/dev/null 2>&1; then
        install_hint "sudo dnf install php-$ext"
    else
        echo "Please install/enable the PHP '$ext' extension for the PHP binary on your PATH."
    fi
}

need_command git
need_command php
need_php_extension curl

if [[ $got_requirements != "yes" ]]; then
    exit 1
fi

mkdir -p "$ARC_BIN_DIR"

if [ -d "$ARC_INSTALL_DIR/.git" ]; then
    echo "Updating Arcanist in $ARC_INSTALL_DIR"
    git -C "$ARC_INSTALL_DIR" fetch --tags --prune origin
else
    echo "Installing Arcanist into $ARC_INSTALL_DIR"
    mkdir -p "$(dirname "$ARC_INSTALL_DIR")"
    git clone "$ARC_REPO" "$ARC_INSTALL_DIR"
fi

echo "Checking out Arcanist ref: $ARC_REF"
git -C "$ARC_INSTALL_DIR" -c advice.detachedHead=false checkout "$ARC_REF"
git -C "$ARC_INSTALL_DIR" reset --hard "$ARC_REF"

if [ ! -x "$ARC_BIN" ]; then
    echo "Error: arc executable not found at $ARC_BIN"
    exit 1
fi

if [ -e "$ARC_LINK" ] && [ ! -L "$ARC_LINK" ]; then
    echo "Error: $ARC_LINK already exists and is not a symlink"
    echo "Please remove it or set ARC_BIN_DIR to another directory."
    exit 1
fi

ln -sf "$ARC_BIN" "$ARC_LINK"

echo "Installed arc:"
"$ARC_LINK" version || true

case ":$PATH:" in
    *":$ARC_BIN_DIR:"*)
        ;;
    *)
        echo
        echo "Warning: $ARC_BIN_DIR is not currently on your PATH."
        echo "Add this to your shell profile if needed:"
        echo
        echo "    export PATH=\"$ARC_BIN_DIR:\$PATH\""
        echo
        ;;
esac

hash -r 2>/dev/null || true

FOUND_ARC="$(command -v arc 2>/dev/null || true)"

if [ "$FOUND_ARC" != "$ARC_LINK" ]; then
    echo
    echo "Warning: The newly installed arc is not the one currently selected by your PATH."
    echo "Intended arc:"
    echo "    $ARC_LINK"
    echo
    if [ -n "$FOUND_ARC" ]; then
        echo "Current arc on PATH:"
        echo "    $FOUND_ARC"
        echo
    else
        echo "No arc is currently found on PATH."
        echo
    fi
    echo "To use the intended arc put this earlier in your PATH:"
    echo
    echo "    export PATH=\"$ARC_BIN_DIR:\$PATH\""
    echo
    echo "For example, add that line to ~/.zshrc, ~/.bashrc, or your shell profile."
    echo
else
    echo "Done. You should now be able to run:"
    echo
    echo "    arc lint"
    echo
fi
