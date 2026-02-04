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
