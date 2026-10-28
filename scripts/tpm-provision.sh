#!/usr/bin/env bash
# Operator-reviewed provisioning only. Never executed by Docker demo/startup.
set -euo pipefail
umask 077
if [[ "${TPM_PROVISION_CONFIRM:-}" != "CREATE_NEW_LICENSE_KEY" ]]; then
  echo 'Review docs/TPM.md, then set TPM_PROVISION_CONFIRM=CREATE_NEW_LICENSE_KEY' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux ]]; then echo 'Physical Linux TPM host required' >&2; exit 1; fi
out="${1:?Usage: tpm-provision.sh NEW_OUTPUT_DIRECTORY}"
mkdir "$out"
out="$(cd "$out" && pwd)"
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
case "$TPM2TOOLS_TCTI" in device:*) ;; *) echo 'Physical device TCTI required' >&2; exit 1;; esac
nv_index=0x01500020
key_handle=0x81010020
ak_handle=0x81010021
owner_auth=()
if [[ -n "${TPM_OWNER_AUTH_FILE:-}" ]]; then
  [[ -r "$TPM_OWNER_AUTH_FILE" ]] || { echo 'Owner authorization file is not readable' >&2; exit 1; }
  owner_auth=(-P "file:$TPM_OWNER_AUTH_FILE")
fi

# Abort before creating anything if these handles already exist.
if tpm2_nvreadpublic "$nv_index" >/dev/null 2>&1; then echo 'NV index already exists' >&2; exit 1; fi
if tpm2_readpublic -c "$key_handle" >/dev/null 2>&1; then echo 'Persistent key handle already exists' >&2; exit 1; fi
if tpm2_readpublic -c "$ak_handle" >/dev/null 2>&1; then echo 'AK handle already exists' >&2; exit 1; fi

# The hierarchy authorization is intentionally NOT changed or cleared here.
# This template assumes owner commands are allowed by the site's provisioning policy.
tpm2_nvdefine -C o "${owner_auth[@]}" -s 8 -a 'authread|ownerwrite|nt=counter' "$nv_index"
tpm2_nvincrement -C o "${owner_auth[@]}" "$nv_index"
tpm2_nvread -s 8 -o "$out/counter.bin" "$nv_index"
tpm2_startauthsession --policy-session -S "$out/session.ctx"
trap 'tpm2_flushcontext "$out/session.ctx" >/dev/null 2>&1 || true' EXIT
tpm2_policynv -S "$out/session.ctx" -i "$out/counter.bin" -L "$out/policy.bin" "$nv_index" eq
tpm2_flushcontext "$out/session.ctx"
trap - EXIT

tpm2_createprimary -C o "${owner_auth[@]}" -G ecc -c "$out/primary.ctx"
tpm2_create -C "$out/primary.ctx" -G ecc256 -u "$out/device.pub" -r "$out/device.priv" \
  -L "$out/policy.bin" -a 'fixedtpm|fixedparent|sensitivedataorigin|sign'
tpm2_load -C "$out/primary.ctx" -u "$out/device.pub" -r "$out/device.priv" -c "$out/device.ctx"
tpm2_evictcontrol -C o "${owner_auth[@]}" -c "$out/device.ctx" "$key_handle"
tpm2_readpublic -c "$key_handle" -f pem -o "$out/device.pub.pem"
tpm2_flushcontext "$out/device.ctx"
tpm2_create -C "$out/primary.ctx" -G ecc256:ecdsa-sha256:null -u "$out/ak.pub" -r "$out/ak.priv" \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign'
tpm2_load -C "$out/primary.ctx" -u "$out/ak.pub" -r "$out/ak.priv" -c "$out/ak.ctx"
tpm2_evictcontrol -C o "${owner_auth[@]}" -c "$out/ak.ctx" "$ak_handle"
tpm2_readpublic -c "$ak_handle" -q "$out/ak.qname" -f pem -o "$out/ak.pub.pem"
tpm2_flushcontext "$out/ak.ctx"
tpm2_flushcontext "$out/primary.ctx"
chmod 600 "$out"/*
cat >"$out/agent.json" <<'JSON'
{
  "key_handle": "0x81010020",
  "public_key_file": "device.pub.pem",
  "nv_index": "0x01500020",
  "expected_counter_file": "counter.bin",
  "tcti": "device:/dev/tpmrm0"
}
JSON
chmod 600 "$out/agent.json"
echo "Created a policy-bound key at $key_handle; review it before enrollment."
