#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not in PATH."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Cannot connect to the Docker daemon."
    echo "You may need to run this script as root, add your user to the docker group,"
    echo "or ensure the Docker service is running."
    exit 1
fi

if ! docker image inspect stego-triage:0.2.0 >/dev/null 2>&1; then
    echo "Error: The image stego-triage:0.2.0 is not built."
    echo "From this directory, run: docker compose build"
    exit 1
fi

if command -v ss >/dev/null 2>&1; then
    if ss -tln | grep -q ":8786\b"; then
        echo "Warning: Port 8786 appears to be in use. Startup may fail."
    fi
elif netstat -tln | grep -q ":8786\b"; then
    echo "Warning: Port 8786 appears to be in use. Startup may fail."
fi

echo "Starting Stego Triage..."
docker compose up -d --pull never

echo "Waiting for health check..."
for _ in {1..15}; do
    if curl -fsS http://127.0.0.1:8786/api/health >/dev/null \
        && curl -fsS http://127.0.0.1:8786/ | grep -q '<title>Stego Triage</title>'; then
        echo "Stego Triage is running!"
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open http://127.0.0.1:8786/ || true
        else
            echo "Open http://127.0.0.1:8786/ in your browser."
        fi
        exit 0
    fi
    sleep 1
done

echo "Error: Stego Triage did not become healthy on http://127.0.0.1:8786/"
exit 1
