#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose build license-server
docker build -f Dockerfile.tpm-simulator -t ecochain-license-tpm-test:local .
# No physical TPM device, host socket, vendor credential or workspace is mounted.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /work:rw,size=64m --tmpfs /tmp:rw,size=64m ecochain-license-tpm-test:local
