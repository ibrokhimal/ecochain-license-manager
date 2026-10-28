#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LICENSE_UID="$(id -u)" LICENSE_GID="$(id -g)"

if [[ "${1:-}" != "--skip-build" ]]; then docker compose build license-server; fi
if [[ ! -d demo ]]; then
  docker run --rm --pull never --network none --user "$LICENSE_UID:$LICENSE_GID" \
    --mount "type=bind,source=$PWD,target=/workspace" --workdir /workspace \
    ecochain-license:local licensectl demo --out demo
fi
docker compose up --no-build -d license-server
ready=0
for _ in {1..20}; do
  if docker compose run --rm --no-deps client >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then docker compose logs license-server; exit 1; fi
if ! (exec 3<>"/dev/tcp/127.0.0.1/${LICENSE_PORT:-50051}") 2>/dev/null; then
  echo "FAIL: published loopback gRPC port is unreachable from the host" >&2; exit 1
fi
echo "PASS: loopback gRPC port is reachable from the host"

docker compose run --rm --no-deps client licensectl smoke \
  --credentials /client --endpoint https://license-server:50051

clone_log="$(mktemp)"
trap 'rm -f "$clone_log"' EXIT
if docker compose run --rm --no-deps clone-server >"$clone_log" 2>&1; then
  echo "FAIL: copied license started on another identity" >&2; exit 1
fi
if ! grep -Eq 'HARDWARE_MISMATCH|DEVICE_KEY_MISMATCH' "$clone_log"; then
  cat "$clone_log"; echo "FAIL: clone failed for an unexpected reason" >&2; exit 1
fi
echo "PASS: copied license rejected on server B"

docker compose restart license-server
ready=0
for _ in {1..20}; do
  if docker compose run --rm --no-deps client; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]]
echo "PASS: server restarted with persistent license/seat state"
echo "Demo server is running. Stop with: docker compose down"
