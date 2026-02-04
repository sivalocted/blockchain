# ScratchChain

ScratchChain is an educational blockchain built from scratch in Python. It includes PoW/PoS consensus, a small VM with gas, P2P networking, snapshots, governance, and a minimal explorer.

Quick start (PoW default):

```bash
python3 -m pip install -r requirements.txt
python3 -m scratchchain --data-dir ./scratchchain_data init
python3 -m scratchchain --data-dir ./scratchchain_data mine --wallet ./scratchchain_data/wallet.json
python3 -m scratchchain --data-dir ./scratchchain_data balance --wallet ./scratchchain_data/wallet.json
```

Explorer UI lives in `explorer/`.

Full documentation: `scratchchain/README.md`

Quick docker testnet:
```bash
docker compose up --build
```

Testnet landing page lives in `web/` and serves `/explorer` alongside it.

Mainnet and ops docs:
- `docs/MAINNET_READINESS.md`
- `docs/TESTNET_LAUNCH_PLAN.md`
- `docs/SECURITY_HARDENING.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/INCIDENT_RESPONSE.md`
- `docs/GOVERNANCE.md`
- `docs/TOKENOMICS_TEMPLATE.md`
- `docs/LEGAL_CHECKLIST.md`
- `docs/BUG_BOUNTY.md`
- `docs/THREAT_MODEL.md`
- `docs/DEPLOYMENT_BARE_METAL.md`
- `docs/TESTNET_PUBLIC_PLAN.md`

Ops scripts and templates:
- `ops/run_local.sh`
- `ops/backup.sh`
- `ops/faucet.py`
- `ops/prometheus_exporter.py`
