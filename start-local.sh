#!/usr/bin/env bash
# Run the bench on this machine, without Docker. Listens on 127.0.0.1:8786.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

if [[ ! -x backend/venv/bin/gunicorn ]]; then
    echo "The local Python environment is missing."
    echo "From this directory, run: ./install-local.sh"
    exit 1
fi

SANDBOX_PATH="/usr/local/bin:/usr/bin:/bin"
missing=()
for cmd in file exiftool strings identify pngcheck binwalk foremost zsteg steghide outguess pdfinfo pdftoppm sox soxi zbarimg; do
    if ! PATH="$SANDBOX_PATH" command -v "$cmd" >/dev/null 2>&1; then
        missing+=("$cmd")
    fi
done
if ((${#missing[@]})); then
    echo "These checks will report unavailable: ${missing[*]}"
    echo "From this directory, run: ./install-local.sh"
fi

RUNTIME_ROOT="$ROOT/runtime"
if [[ -e "$RUNTIME_ROOT" && ! -w "$RUNTIME_ROOT" ]]; then
    echo "runtime/ is not writable. Docker created it as root."
    echo "Fix with: sudo chown -R $(id -un) runtime"
    exit 1
fi
mkdir -p "$RUNTIME_ROOT"

if command -v ss >/dev/null 2>&1; then
    if ss -tln | grep -q ":8786\\b"; then
        echo "Port 8786 is already in use."
        exit 1
    fi
fi

export RUNTIME_ROOT
export FRONTEND_ROOT="$ROOT/frontend"
export PYTHONPATH="$ROOT/backend"
export PYTHONUNBUFFERED=1

echo "Starting Stego Triage at http://127.0.0.1:8786/"
backend/venv/bin/gunicorn -w 1 -b 127.0.0.1:8786 --threads 2 stego_triage.app:app &
pid=$!

cleanup() {
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
trap cleanup INT TERM

ready=0
for _ in {1..15}; do
    if backend/venv/bin/python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8786/api/health", timeout=1)' >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" || true
        echo "The server exited before it became healthy."
        exit 1
    fi
    sleep 1
done

if [[ "$ready" -ne 1 ]]; then
    cleanup
    echo "Stego Triage did not become healthy on http://127.0.0.1:8786/"
    exit 1
fi

echo "Stego Triage is running. Press Ctrl+C to stop."
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:8786/" || true
fi
wait "$pid"
