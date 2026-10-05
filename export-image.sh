#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Exporting image stego-triage:0.2.0..."
docker save stego-triage:0.2.0 -o stego-triage-0.2.0.tar
sha256sum stego-triage-0.2.0.tar > stego-triage-0.2.0.tar.sha256
echo "Export complete: stego-triage-0.2.0.tar"
