#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

TAR_FILE="stego-triage-0.2.0.tar"
if [ ! -f "$TAR_FILE" ]; then
    echo "Error: $TAR_FILE not found."
    exit 1
fi

echo "Verifying checksum..."
sha256sum -c "$TAR_FILE.sha256"

echo "Loading image..."
docker load -i "$TAR_FILE"
echo "Import complete."
