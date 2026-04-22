#!/bin/bash
# Reproducibility script for F1 — verify mainnet MarketConfig + RiskParams
# reads against the deployed percolator slab.
#
# Mainnet slab: 5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB

set -euo pipefail

SLAB=5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB
RPC=${RPC:-https://api.mainnet-beta.solana.com}

curl -sS -X POST "$RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"$SLAB\",{\"encoding\":\"base64\",\"dataSlice\":{\"offset\":0,\"length\":584}}]}" \
  | python3 -c "
import sys, json, base64, struct
r = json.load(sys.stdin)
data = base64.b64decode(r['result']['value']['data'][0])

# Header magic sanity check
magic = data[0:8]
assert magic == b'TALOCREP', f'bad magic: {magic!r}'  # 'PERCOLAT' LE

# RiskParams: engine_off=536, params_off=32 → byte 568
mm = struct.unpack('<Q', data[568:576])[0]
im = struct.unpack('<Q', data[576:584])[0]

# MarketConfig walk for oracle_price_cap_e2bps
off = 136 + 32 + 32 + 32
off += 8 + 2 + 1 + 1 + 4
off += 8 + 8 + 8 + 8
off += 32
off += 8 + 8
opcap = struct.unpack('<Q', data[off:off+8])[0]; off += 8
lep   = struct.unpack('<Q', data[off:off+8])[0]; off += 8
mincap = struct.unpack('<Q', data[off:off+8])[0]

print(f'slot                 = {r[\"result\"][\"context\"][\"slot\"]}')
print(f'MM bps               = {mm} ({mm/100:.2f}%)')
print(f'IM bps               = {im} ({im/100:.2f}%)')
print(f'IM-MM spread         = {im-mm} ({(im-mm)/100:.2f}%)')
print(f'max leverage         = {10000//im}x')
print(f'oracle_price_cap     = {opcap} e2bps')
print(f'min_oracle_price_cap = {mincap} e2bps')
print(f'last_effective_e6    = {lep}')
print()
if opcap == 0:
    print('>> CIRCUIT BREAKER DISABLED. Oracle prices pass through unclamped.')
if mincap == 0:
    print('>> min_cap = 0: breaker cannot be re-enabled even if admin existed.')
"
