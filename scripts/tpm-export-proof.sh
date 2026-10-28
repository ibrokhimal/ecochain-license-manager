#!/usr/bin/env bash
# Exports current NV state; NEVER increments or clears the TPM.
set -euo pipefail
umask 077
challenge="${1:?Usage: tpm-export-proof.sh CHALLENGE ROLE VENDOR_PUBLIC_KEY NEW_OUTPUT_PREFIX}"
role="${2:?target or old}"
public="${3:?Vendor public key}"
out="${4:?Output prefix}"
case "$role" in old|target) ;; *) echo 'Invalid role' >&2; exit 1;; esac
for suffix in nonce att sig json; do [[ ! -e "$out.$suffix" ]] || { echo 'Output exists' >&2; exit 1; }; done
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
case "$TPM2TOOLS_TCTI" in device:*) ;; *) echo 'Physical device TCTI required' >&2; exit 1;; esac
license-tpm nonce --challenge "$challenge" --public-key "$public" --role "$role" --output "$out.nonce"
tpm2_nvcertify -Q -C 0x81010021 -g sha256 -s ecdsa -f plain -q "$out.nonce" \
  --size 8 --offset 0 --attestation "$out.att" -o "$out.sig" 0x01500020
license-tpm pack-proof --attestation "$out.att" --signature "$out.sig" --output "$out.json"
