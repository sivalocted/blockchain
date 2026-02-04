# Public Testnet Plan (Seed Nodes + Faucet)

## Goals
- Stable public testnet with predictable block times
- Easy onboarding for developers
- Safe token distribution via faucet

## Seed nodes
Run at least 3 seed nodes in different networks.
- Each seed should have a public P2P port 9333
- RPC and indexer stay private or behind auth
- Publish the seed list in `ops/seed_peers.txt`

Example `SCRATCHCHAIN_SEEDS` on all nodes:
```
SCRATCHCHAIN_SEEDS=seed1.example.com:9333,seed2.example.com:9333,seed3.example.com:9333
```

## Node roles
- Seed nodes: stable, public P2P only
- Validator nodes: stake + mining
- Explorer nodes: RPC + indexer for UI

## Faucet workflow
1) Create a faucet wallet with funds
```bash
python3 -m scratchchain --data-dir ./scratchchain_data create-wallet --wallet ./scratchchain_data/faucet.json
```
2) Fund it by mining blocks or sending from genesis wallet
3) Run the faucet server
```bash
SCRATCHCHAIN_FAUCET_WALLET=./scratchchain_data/faucet.json \
SCRATCHCHAIN_FAUCET_AMOUNT=5 \
python3 ops/faucet.py
```
4) Protect the faucet behind nginx or a firewall

## Explorer
- Run indexer on a dedicated node
- Serve the UI via nginx or a static host
- Publish the explorer URL

## Metrics and alerts
- Run `ops/prometheus_exporter.py` on each node
- Set alert thresholds for low peer count, low height advance, or high mempool

## Security
- Enable `SCRATCHCHAIN_RPC_TOKEN`
- Limit RPC exposure (127.0.0.1 or VPN)
- Use firewall rules for public ports only

## Public checklist
- Seed list published
- Explorer URL published
- Faucet URL and rate limits published
- Contact email for bug reports published
