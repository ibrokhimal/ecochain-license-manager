#!/usr/bin/env bash
# Read-only TPM public/state collection. Operator must authenticate its source.
set -euo pipefail
umask 077
[[ "$(uname -s)" == Linux ]] || { echo 'Linux TPM host required' >&2; exit 1; }
out="${1:?Usage: tpm-collect-trust.sh NEW_DIRECTORY ORGANIZATION}"
organization="${2:?Organization required}"
mkdir "$out"
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
case "$TPM2TOOLS_TCTI" in device:*) ;; *) echo 'Physical device TCTI required' >&2; exit 1;; esac
tpm2_readpublic -Q -c 0x81010020 -f tss -o "$out/device.pub"
tpm2_readpublic -Q -c 0x81010021 -f tss -o "$out/ak.pub" -q "$out/ak.qname"
tpm2_nvreadpublic 0x01500020 > "$out/nv.yaml"
tpm2_nvread -Q -s 8 -o "$out/counter.bin" 0x01500020
python3 - "$out" <<'PY'
import sys,struct,yaml
from pathlib import Path
p=Path(sys.argv[1]); data=yaml.safe_load((p/'nv.yaml').read_text()); index,record=next(iter(data.items()))
index=int(index,0) if isinstance(index,str) else index
policy=record.get('authorization policy') or ''
policy=bytes.fromhex(policy) if isinstance(policy,str) else bytes(policy)
body=struct.pack('>IHIH',index,record['hash algorithm']['value'],record['attributes']['value'],len(policy))+policy+struct.pack('>H',record['size'])
(p/'nv.pub').write_bytes(struct.pack('>H',len(body))+body)
(p/'nv.name').write_bytes(bytes.fromhex(record['name']))
PY
license-tpm pack-trust --ak-public "$out/ak.pub" --ak-qualified-name "$out/ak.qname" \
  --device-public "$out/device.pub" --nv-name "$out/nv.name" --nv-public "$out/nv.pub" --counter "$out/counter.bin" \
  --organization "$organization" --environment physical \
  --system-uuid "$(cat /sys/class/dmi/id/product_uuid)" --board-serial "$(cat /sys/class/dmi/id/board_serial)" \
  --output "$out/trust.json"
echo "Public manifest collected. Vendor must authenticate physical onboarding before trust-import."
