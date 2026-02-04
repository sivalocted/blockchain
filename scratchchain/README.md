# ScratchChain

Educational blockchain from scratch in Python.

Features:
- Proof-of-Work mining with difficulty retargeting
- Optional Proof-of-Stake mode (validator selection + block signatures + slashing evidence)
- UTXO transactions with stake locking
- ECDSA (secp256k1) signatures via `cryptography`
- Merkle roots + Merkle inclusion proofs
- Fork handling with chainwork selection + finality checkpoints
- Mempool persistence + fee prioritization + eviction + fee bumping (RBF)
- Halving schedule + max supply cap + genesis allocations
- SQLite persistence (blocks + mempool + tx index + receipts)
- Simple smart-contract VM with gas + receipts
- P2P networking with peer discovery, banscore, compact blocks, header sync, and optional TLS
- Validator registry + on-chain governance updates
- Snapshots + fast sync (signed and trusted)
- JSON-RPC server with rate limiting + optional auth token
- CLI for wallet, send, stake, contracts, proofs, history, snapshots, governance, and node
- Minimal Explorer UI
- Optional indexer service for fast block/tx lookup

## Quick start (PoW default)

Install dependencies:

```bash
python3 -m pip install -r ../requirements.txt
```

```bash
python3 -m scratchchain --data-dir ./scratchchain_data init
python3 -m scratchchain --data-dir ./scratchchain_data mine --wallet ./scratchchain_data/wallet.json
python3 -m scratchchain --data-dir ./scratchchain_data balance --wallet ./scratchchain_data/wallet.json
```

Create a second wallet and send coins:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data create-wallet --wallet ./scratchchain_data/wallet2.json
ADDR=$(python3 -m scratchchain --data-dir ./scratchchain_data address --wallet ./scratchchain_data/wallet2.json)
python3 -m scratchchain --data-dir ./scratchchain_data send --wallet ./scratchchain_data/wallet.json --to $ADDR --amount 1.5
python3 -m scratchchain --data-dir ./scratchchain_data mine --wallet ./scratchchain_data/wallet.json
python3 -m scratchchain --data-dir ./scratchchain_data balance --address $ADDR
```

## PoS mode

Set consensus to PoS in your shell:

```bash
export SCRATCHCHAIN_CONSENSUS=pos
```

Then initialize and mine using a staked validator wallet:

```bash
python3 -m scratchchain --data-dir ./scratchchain_pos init
python3 -m scratchchain --data-dir ./scratchchain_pos stake --wallet ./scratchchain_pos/wallet.json --amount 10
python3 -m scratchchain --data-dir ./scratchchain_pos mine --wallet ./scratchchain_pos/wallet.json
```

## Smart contracts (VM + gas)

Create a contract (code can be a JSON list or a plain text file with one opcode per line):

```bash
cat > /tmp/code.json <<'JSON'
["PUSH 5","PUSH 7","ADD","STORE total","LOAD total","STOP"]
JSON

python3 -m scratchchain --data-dir ./scratchchain_data contract-create \
  --wallet ./scratchchain_data/wallet.json \
  --code /tmp/code.json \
  --gas-limit 200 \
  --gas-price 1
python3 -m scratchchain --data-dir ./scratchchain_data mine --wallet ./scratchchain_data/wallet.json
```

Call a contract:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data contract-call \
  --wallet ./scratchchain_data/wallet.json \
  --contract <CONTRACT_TXID> \
  --calldata '[1,2,3]' \
  --gas-limit 200 \
  --gas-price 1
python3 -m scratchchain --data-dir ./scratchchain_data mine --wallet ./scratchchain_data/wallet.json
```

## Merkle proof

```bash
python3 -m scratchchain --data-dir ./scratchchain_data tx-proof --block <BLOCK_HASH> --txid <TXID>
python3 -m scratchchain --data-dir ./scratchchain_data verify-proof --proof '<JSON_PROOF>'
```

## Run a node with P2P + RPC

```bash
python3 -m scratchchain --data-dir ./scratchchain_data node --host 0.0.0.0 --port 9333 --rpc-port 9334
```

Start another node and connect:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data2 node --host 0.0.0.0 --port 9335 --rpc-port 9336 --peer 127.0.0.1:9333
```

Enable P2P TLS (self-signed certs are generated automatically):

```bash
export SCRATCHCHAIN_P2P_TLS=1
```

Trust only pinned peers (optional):

```bash
export SCRATCHCHAIN_P2P_TRUSTED_ONLY=1
export SCRATCHCHAIN_TRUSTED_PEERS='{"<NODE_ID>":"<FINGERPRINT>"}'
```

## RPC example

```bash
curl -s -X POST http://127.0.0.1:9334/rpc \
  -H 'Content-Type: application/json' \
  -d '{"method":"get_info","params":{}}'
```

## Validator registry

Register a validator (metadata is optional):

```bash
python3 -m scratchchain --data-dir ./scratchchain_data validator-register \
  --wallet ./scratchchain_data/wallet.json \
  --name "My Validator" \
  --website "https://example.com" \
  --commission 0.05
```

## Governance updates

Set `SCRATCHCHAIN_GOV_ADDRESS` and submit a governance update from that wallet:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data gov-update \
  --wallet ./scratchchain_data/wallet.json \
  --params '{"MAX_BLOCK_SIZE":2000000,"MAX_BLOCK_GAS":150000}'
```

## Snapshots / fast sync (signed)

Create a snapshot:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data snapshot-create
```

Load a snapshot:

```bash
python3 -m scratchchain --data-dir ./scratchchain_data snapshot-load --path <SNAPSHOT_PATH>
```

Enable trusted fast sync from peers:

```bash
export SCRATCHCHAIN_FASTSYNC=1
```

Require signed snapshots:

```bash
export SCRATCHCHAIN_REQUIRE_SIGNED_SNAPSHOT=1
export SCRATCHCHAIN_SNAPSHOT_TRUST='<NODE_ID_1>,<NODE_ID_2>'
```

## Indexer

Start the indexer (HTTP JSON API for fast search):

```bash
python3 -m scratchchain --data-dir ./scratchchain_data indexer --host 127.0.0.1 --port 9337
```

## Notes
- This is a learning project, not production-grade security.
- P2P can be authenticated and encrypted, but defaults are for local testing.
- Use a fresh data directory after upgrades.
- Only ECDSA (secp256k1) keys are supported (RSA removed).

Genesis allocations (optional):

```bash
export SCRATCHCHAIN_GENESIS_ALLOCATIONS='{"ADDR1":1000000000,"ADDR2":500000000}'
```

## Demo script

Run a full end-to-end demo (PoW, transfer, contract, merkle proof, PoS):

```bash
python3 scratchchain/demo.py
```

## Tests

```bash
python3 -m pip install -r ../requirements-dev.txt
python3 -m pytest
```

Tip: use a fresh data directory after upgrades.

## Config

Environment variables:
- `SCRATCHCHAIN_CONSENSUS` = `pow` or `pos`
- `SCRATCHCHAIN_INITIAL_DIFFICULTY` (PoW)
- `SCRATCHCHAIN_BLOCK_TIME` (seconds)
- `SCRATCHCHAIN_DIFF_INTERVAL`
- `SCRATCHCHAIN_MAX_BLOCK_SIZE`
- `SCRATCHCHAIN_MAX_BLOCK_GAS`
- `SCRATCHCHAIN_MAX_TXS_PER_BLOCK`

## More Config

- `SCRATCHCHAIN_BASE_GAS_PRICE`
- `SCRATCHCHAIN_HALVING_INTERVAL`
- `SCRATCHCHAIN_MAX_SUPPLY`
- `SCRATCHCHAIN_MIN_STAKE`
- `SCRATCHCHAIN_FINALITY_DEPTH`
- `SCRATCHCHAIN_SLASH_RATE_BPS`
- `SCRATCHCHAIN_RPC_TOKEN`
- `SCRATCHCHAIN_RPC_RATE`
- The Explorer UI can send this token via the Connection panel.
- `SCRATCHCHAIN_P2P_SECRET`
- `SCRATCHCHAIN_COMPACT_BLOCKS`
- `SCRATCHCHAIN_BLOCK_REWARD`
- `SCRATCHCHAIN_MAX_MEMPOOL_TXS`
- `SCRATCHCHAIN_MAX_MEMPOOL_BYTES`
- `SCRATCHCHAIN_MIN_RELAY_FEE_RATE`
- `SCRATCHCHAIN_RBF_MIN_FACTOR`
- `SCRATCHCHAIN_RBF_MIN_DELTA`
- `SCRATCHCHAIN_MAX_VALIDATORS`
- `SCRATCHCHAIN_META_TX_FEE`
- `SCRATCHCHAIN_GENESIS_ALLOCATIONS`
- `SCRATCHCHAIN_GOV_ADDRESS`
- `SCRATCHCHAIN_SNAPSHOT_INTERVAL`
- `SCRATCHCHAIN_SNAPSHOTS`
- `SCRATCHCHAIN_FASTSYNC`
- `SCRATCHCHAIN_SEEDS`
- `SCRATCHCHAIN_P2P_TLS`
- `SCRATCHCHAIN_P2P_TLS_VERIFY`
- `SCRATCHCHAIN_P2P_CERT`
- `SCRATCHCHAIN_P2P_KEY`
- `SCRATCHCHAIN_P2P_CA`
- `SCRATCHCHAIN_HELLO_SKEW`
- `SCRATCHCHAIN_HELLO_NONCE_TTL`
- `SCRATCHCHAIN_P2P_TRUSTED_ONLY`
- `SCRATCHCHAIN_TRUSTED_PEERS`
- `SCRATCHCHAIN_REQUIRE_SIGNED_SNAPSHOT`
- `SCRATCHCHAIN_SNAPSHOT_TRUST`
- `SCRATCHCHAIN_PRUNE_DEPTH`
- `SCRATCHCHAIN_INDEXER_CACHE_TTL`
- `SCRATCHCHAIN_INDEXER_MAX_BLOCKS`
