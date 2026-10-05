#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Stopping Stego Triage..."
docker compose down
echo "Stopped."
