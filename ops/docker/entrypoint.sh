#!/usr/bin/env bash
set -euo pipefail

DATA_DIR=${DATA_DIR:-/data}
WALLET=${WALLET:-$DATA_DIR/wallet.json}

mkdir -p "$DATA_DIR"

if [ ! -f "$DATA_DIR/chain.db" ]; then
  python -m scratchchain --data-dir "$DATA_DIR" init
fi

if [ ! -f "$WALLET" ]; then
  python -m scratchchain --data-dir "$DATA_DIR" create-wallet --wallet "$WALLET"
fi

exec "$@"
