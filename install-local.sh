#!/usr/bin/env bash
# Install the stego tools and the Python environment on Debian, Ubuntu, or Linux Mint.
# The server only looks for tools on /usr/local/bin:/usr/bin:/bin.
set -euo pipefail
cd "$(dirname "$0")"

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this as your user. It will ask for sudo to install packages."
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer uses apt."
    echo "On other systems, install Docker and run: docker compose build && ./start.sh"
    exit 1
fi

SANDBOX_PATH="/usr/local/bin:/usr/bin:/bin"

PACKAGES=(
    file
    binutils
    libimage-exiftool-perl
    imagemagick
    pngcheck
    binwalk
    foremost
    steghide
    outguess
    poppler-utils
    sox
    zbar-tools
    python3
    python3-venv
    python3-pip
)

echo "Installing packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"

if ! PATH="$SANDBOX_PATH" command -v zsteg >/dev/null 2>&1; then
    echo "Installing zsteg..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ruby ruby-dev build-essential libpng-dev zlib1g-dev
    sudo gem install zsteg --no-document
fi

if [[ ! -d backend/venv ]]; then
    python3 -m venv backend/venv
fi
(
    cd backend
    ./venv/bin/pip install -q -e .
)

missing=()
for cmd in file exiftool strings identify pngcheck binwalk foremost zsteg steghide outguess pdfinfo pdftoppm sox soxi zbarimg; do
    if ! PATH="$SANDBOX_PATH" command -v "$cmd" >/dev/null 2>&1; then
        missing+=("$cmd")
    fi
done

if ((${#missing[@]})); then
    echo "Still missing from ${SANDBOX_PATH}: ${missing[*]}"
    exit 1
fi

bw="$(PATH="$SANDBOX_PATH" binwalk -h 2>&1 | head -n 1 || true)"
case "$bw" in
    *v3*|*version\ 3*)
        echo "Warning: this bench expects binwalk 2.x. The apt package is the one that matches."
        ;;
esac

echo "Tools and the Python environment are installed."
echo "From this directory, run: ./start-local.sh"
