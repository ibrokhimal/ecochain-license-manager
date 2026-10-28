#!/usr/bin/env bash
# Entirely isolated swtpm state: never run against a physical host TPM.
set -euo pipefail
umask 077
cd /work
nv=0x01500020
device=0x81010020
ak=0x81010021

fail_expected() {
  local pattern="$1"; shift
  if "$@" > /work/expected-error.log 2>&1; then echo "FAIL: expected command rejection" >&2; exit 1; fi
  if ! grep -Eq "$pattern" /work/expected-error.log; then cat /work/expected-error.log; exit 1; fi
}
use_node() { export TPM2TOOLS_TCTI="swtpm:path=/work/$1/tpm.sock"; }
provision() {
  local node="$1"
  mkdir -p "$node/state"
  swtpm socket --tpm2 --tpmstate "dir=/work/$node/state" \
    --server "type=unixio,path=/work/$node/tpm.sock" \
    --ctrl "type=unixio,path=/work/$node/tpm.sock.ctrl" --flags not-need-init --daemon
  use_node "$node"
  tpm2_startup -c
  tpm2_nvdefine -Q -C o -s 8 -a 'authread|ownerwrite|nt=counter' "$nv"
  tpm2_nvincrement -Q -C o "$nv"
  tpm2_nvread -Q -s 8 -o "$node/counter.bin" "$nv"
  tpm2_nvreadpublic "$nv" > "$node/nv.yaml"
  python3 - "$node" <<'PY'
import sys, yaml, struct
from pathlib import Path
p=Path(sys.argv[1]); record=next(iter(yaml.safe_load((p/'nv.yaml').read_text()).values()))
(p/'nv.name').write_bytes(bytes.fromhex(record['name']))
index=next(iter(yaml.safe_load((p/'nv.yaml').read_text())))
index=int(index,0) if isinstance(index,str) else index
policy=record.get('authorization policy') or ''
policy=bytes.fromhex(policy) if isinstance(policy,str) else bytes(policy)
body=struct.pack('>IHIH',index,record['hash algorithm']['value'],record['attributes']['value'],len(policy))+policy+struct.pack('>H',record['size'])
(p/'nv.pub').write_bytes(struct.pack('>H',len(body))+body)
PY
  tpm2_startauthsession -Q --policy-session -S "$node/policy.ctx"
  tpm2_policynv -Q -S "$node/policy.ctx" -i "$node/counter.bin" -L "$node/policy.bin" "$nv" eq
  tpm2_flushcontext "$node/policy.ctx"
  tpm2_createprimary -Q -C o -G ecc -c "$node/primary.ctx"
  tpm2_flushcontext -t
  tpm2_create -Q -C "$node/primary.ctx" -G ecc256 -u "$node/device.pub" -r "$node/device.priv" \
    -L "$node/policy.bin" -a 'fixedtpm|fixedparent|sensitivedataorigin|sign'
  tpm2_flushcontext -t
  tpm2_load -Q -C "$node/primary.ctx" -u "$node/device.pub" -r "$node/device.priv" -c "$node/device.ctx"
  tpm2_evictcontrol -Q -C o -c "$node/device.ctx" "$device"
  tpm2_flushcontext -t
  tpm2_create -Q -C "$node/primary.ctx" -G ecc256:ecdsa-sha256:null -u "$node/ak.pub" -r "$node/ak.priv" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign'
  tpm2_flushcontext -t
  tpm2_load -Q -C "$node/primary.ctx" -u "$node/ak.pub" -r "$node/ak.priv" -c "$node/ak.ctx"
  tpm2_evictcontrol -Q -C o -c "$node/ak.ctx" "$ak"
  tpm2_flushcontext -t
  tpm2_readpublic -Q -c "$ak" -q "$node/ak.qname"
  license-tpm pack-trust --ak-public "$node/ak.pub" --ak-qualified-name "$node/ak.qname" \
    --device-public "$node/device.pub" --nv-name "$node/nv.name" --nv-public "$node/nv.pub" --counter "$node/counter.bin" \
    --organization org-1 --system-uuid aaba4679-b41d-46a8-b8af-4fa855843211 \
    --board-serial "SIM-$node" --environment simulator --output "$node/trust.json"
}
sign_policy() {
  local node="$1" message="$2" signature="$3"
  use_node "$node"
  tpm2_startauthsession -Q --policy-session -S "$node/sign.ctx"
  if ! tpm2_policynv -Q -S "$node/sign.ctx" -i "$node/counter.bin" "$nv" eq; then
    tpm2_flushcontext "$node/sign.ctx"; return 1
  fi
  if ! tpm2_sign -Q -c "$device" -p "session:$node/sign.ctx" -g sha256 -s ecdsa -f plain -o "$signature" "$message"; then
    tpm2_flushcontext "$node/sign.ctx"; return 1
  fi
  tpm2_flushcontext "$node/sign.ctx"
}
activation() {
  local node="$1"
  license-tpm prepare-activation --record "$node/trust.json" --payload-output "$node/activation-payload.json" --message-output "$node/activation-message.bin"
  sign_policy "$node" "$node/activation-message.bin" "$node/activation.sig"
  license-tpm pack-activation --payload "$node/activation-payload.json" --signature "$node/activation.sig" --output "$node/activation.json"
}
nv_proof() {
  local node="$1" challenge="$2" role="$3" prefix="$4"
  license-tpm nonce --challenge "$challenge" --public-key vendor/vendor.pub --role "$role" --output "$prefix.nonce"
  use_node "$node"
  tpm2_nvcertify -Q -C "$ak" -g sha256 -s ecdsa -f plain -q "$prefix.nonce" \
    --size 8 --offset 0 --attestation "$prefix.att" -o "$prefix.sig" "$nv"
  license-tpm pack-proof --attestation "$prefix.att" --signature "$prefix.sig" --output "$prefix.json"
}

licensectl keygen --out vendor
provision old
provision target
for node in old target; do
  fail_expected 'invalid or unsupported TPM' license-tpm trust-import --registry vendor/issuer.db --record "$node/trust.json"
  license-tpm trust-import --registry vendor/issuer.db --record "$node/trust.json" --allow-simulator
  activation "$node"
done

# Password-only authorization must not bypass the lease key's NV policy.
use_node old
fail_expected 'policy|auth|TPM|tpm' tpm2_sign -c "$device" -g sha256 -s ecdsa -f plain -o bypass.sig old/activation-message.bin

license-tpm challenge --registry vendor/issuer.db --key vendor/vendor.key --kind enroll --license-id lic-1 \
  --request old/activation.json --allow-simulator --output enroll.challenge
nv_proof old enroll.challenge target enroll-proof
python3 - <<'PY'
import json,time
with open('terms.json','w') as f: json.dump(dict(revision=1,max_users=3,modules=['inventory','analytics'],expiration_date=int(time.time())+7200),f)
PY
license-tpm complete --registry vendor/issuer.db --key vendor/vendor.key --challenge enroll.challenge \
  --request old/activation.json --target-proof enroll-proof.json --terms terms.json --allow-simulator --output old.lic
licensectl inspect --license old.lic --public-key vendor/vendor.pub > old-license.json

license-tpm challenge --registry vendor/issuer.db --key vendor/vendor.key --kind migrate --license-id lic-1 \
  --request target/activation.json --allow-simulator --output migrate.challenge
nv_proof target migrate.challenge target target-proof
nv_proof old migrate.challenge old old-active-proof
fail_expected 'has not advanced' license-tpm complete --registry vendor/issuer.db --key vendor/vendor.key \
  --challenge migrate.challenge --request target/activation.json --target-proof target-proof.json \
  --old-proof old-active-proof.json --allow-simulator --output must-not-exist.lic

use_node old
tpm2_nvincrement -Q -C o "$nv"
fail_expected 'policy|TPM|tpm' sign_policy old old/activation-message.bin old/after-deactivation.sig
nv_proof old migrate.challenge old old-inactive-proof
license-tpm complete --registry vendor/issuer.db --key vendor/vendor.key --challenge migrate.challenge \
  --request target/activation.json --target-proof target-proof.json --old-proof old-inactive-proof.json \
  --allow-simulator --output migrated.lic
license-tpm complete --registry vendor/issuer.db --key vendor/vendor.key --challenge migrate.challenge \
  --request target/activation.json --target-proof target-proof.json --old-proof old-inactive-proof.json \
  --allow-simulator --output migrated-retry.lic
cmp migrated.lic migrated-retry.lic
licensectl inspect --license migrated.lic --public-key vendor/vendor.pub > migrated-license.json
license-tpm challenge --registry vendor/issuer.db --key vendor/vendor.key --kind enroll --license-id lic-1 \
  --request target/activation.json --allow-simulator --output renew.challenge
nv_proof target renew.challenge target renew-proof
python3 - <<'PY'
import json
terms=json.load(open('terms.json')); terms['revision']=3
with open('renew-terms.json','w') as f: json.dump(terms,f)
PY
license-tpm complete --registry vendor/issuer.db --key vendor/vendor.key --challenge renew.challenge \
  --request target/activation.json --target-proof renew-proof.json --terms renew-terms.json --allow-simulator --output renewed.lic
licensectl inspect --license renewed.lic --public-key vendor/vendor.pub > renewed-license.json
python3 - <<'PY'
import json
a=json.load(open('old-license.json'))['claims']; b=json.load(open('migrated-license.json'))['claims']
assert b['revision']==2 and b['not_before']-b['issued_at']==480
assert b['allowed_modules']==a['allowed_modules'] and b['max_users']==a['max_users'] and b['expiration_date']==a['expiration_date']
assert b['server_public_key_pem']!=a['server_public_key_pem'] and b['binding_mode']=='development'
c=json.load(open('renewed-license.json'))['claims']; assert c['not_before']>=b['not_before'] and c['revision']==3
print(json.dumps({'swtpm':'passed','checks':['real-NV-policy','password-bypass-denied','restricted-AK-attestation','active-old-migration-denied','fresh-sign-after-increment-denied','one-time-migration','exact-retry','480-second-wait','renewal-preserves-wait','unchanged-entitlements','simulator-development-only']}))
PY
