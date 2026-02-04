# Bare Metal Deployment (Ubuntu 22.04 LTS)

This guide is for a production-grade self-hosted deployment on your own servers.

## Recommended hardware
- 4+ vCPU
- 16 GB RAM
- 200+ GB SSD (NVMe preferred)
- 1 Gbps network

## 1) OS preparation
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git ufw nginx
sudo adduser --disabled-password --gecos "" scratchchain
sudo mkdir -p /opt/scratchchain
sudo chown scratchchain:scratchchain /opt/scratchchain
```

## 2) Install the node
```bash
sudo -u scratchchain git clone https://github.com/sivalocted/blockchain.git /opt/scratchchain
sudo -u scratchchain python3 -m venv /opt/scratchchain/.venv
sudo -u scratchchain /opt/scratchchain/.venv/bin/pip install -r /opt/scratchchain/requirements.txt
```

## 3) Create wallet and data dir
```bash
sudo -u scratchchain mkdir -p /opt/scratchchain/data
sudo -u scratchchain /opt/scratchchain/.venv/bin/python -m scratchchain --data-dir /opt/scratchchain/data create-wallet --wallet /opt/scratchchain/data/wallet.json
```

## 4) Configure environment
Create `/etc/scratchchain.env`:
```
DATA_DIR=/opt/scratchchain/data
WALLET=/opt/scratchchain/data/wallet.json
P2P_HOST=0.0.0.0
P2P_PORT=9333
RPC_HOST=127.0.0.1
RPC_PORT=9334
INDEXER_HOST=127.0.0.1
INDEXER_PORT=9337
SCRATCHCHAIN_RPC_TOKEN=change_me
SCRATCHCHAIN_P2P_SECRET=change_me
SCRATCHCHAIN_P2P_TLS=1
SCRATCHCHAIN_P2P_TLS_VERIFY=0
SCRATCHCHAIN_SEEDS=seed1.example.com:9333,seed2.example.com:9333
```

## 5) Optional P2P TLS certs
```bash
sudo mkdir -p /opt/scratchchain/certs
sudo openssl req -x509 -newkey rsa:4096 -keyout /opt/scratchchain/certs/p2p.key -out /opt/scratchchain/certs/p2p.crt -days 365 -nodes -subj "/CN=scratchchain"
```
Then add to `/etc/scratchchain.env`:
```
SCRATCHCHAIN_P2P_CERT=/opt/scratchchain/certs/p2p.crt
SCRATCHCHAIN_P2P_KEY=/opt/scratchchain/certs/p2p.key
```

## 6) Enable systemd services
```bash
sudo cp /opt/scratchchain/ops/systemd/scratchchain-node.service /etc/systemd/system/
sudo cp /opt/scratchchain/ops/systemd/scratchchain-indexer.service /etc/systemd/system/
sudo cp /opt/scratchchain/ops/systemd/scratchchain-exporter.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable scratchchain-node scratchchain-indexer scratchchain-exporter
sudo systemctl start scratchchain-node scratchchain-indexer scratchchain-exporter
```

## 7) Firewall
```bash
sudo /opt/scratchchain/ops/firewall/ufw.sh
```
Keep RPC and indexer local or behind a reverse proxy.

## 8) Reverse proxy for RPC (optional)
Use `ops/nginx/rpc_proxy.conf` inside your nginx server block and add basic auth or IP allowlist.

## 9) Monitoring
Run the Prometheus exporter and scrape `http://127.0.0.1:9108/metrics`.

## 10) Backups
```bash
sudo -u scratchchain /opt/scratchchain/ops/backup.sh
```
Schedule daily snapshots with cron.

## 11) Explorer UI
Serve the UI from a static host or nginx:
```bash
python3 -m http.server 8080 --directory /opt/scratchchain/explorer
```

## 12) Health checks
- `systemctl status scratchchain-node`
- `curl -s http://127.0.0.1:9334/rpc` (use RPC token)
- `curl -s http://127.0.0.1:9108/metrics`
