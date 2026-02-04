# Ops Toolkit

This folder contains runbooks, scripts, and templates for running a testnet or mainnet.

Files:
- run_local.sh: start node, indexer, and UI locally
- docker/entrypoint.sh: bootstrap chain and wallet for containers
- prometheus_exporter.py: exposes Prometheus metrics from RPC
- prometheus.yml: sample Prometheus scrape config
- systemd/: service templates for Linux
- nginx/: reverse proxy sample for RPC
- firewall/: firewall examples
- seed_peers.txt: list of seed nodes
- backup.sh: create and archive snapshots
- faucet.py: simple testnet faucet server
