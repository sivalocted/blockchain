#!/usr/bin/env bash
set -euo pipefail

DATA_DIR=${DATA_DIR:-./scratchchain_data}
WALLET=${WALLET:-$DATA_DIR/wallet.json}
RPC_HOST=${RPC_HOST:-127.0.0.1}
RPC_PORT=${RPC_PORT:-9334}
P2P_HOST=${P2P_HOST:-0.0.0.0}
P2P_PORT=${P2P_PORT:-9333}
INDEXER_HOST=${INDEXER_HOST:-127.0.0.1}
INDEXER_PORT=${INDEXER_PORT:-9337}
UI_PORT=${UI_PORT:-8080}

mkdir -p "$DATA_DIR"

if [ ! -f "$DATA_DIR/chain.db" ]; then
  python3 -m scratchchain --data-dir "$DATA_DIR" init
fi

if [ ! -f "$WALLET" ]; then
  python3 -m scratchchain --data-dir "$DATA_DIR" create-wallet --wallet "$WALLET"
fi

python3 -m scratchchain --data-dir "$DATA_DIR" node \
  --host "$P2P_HOST" --port "$P2P_PORT" \
  --rpc-host "$RPC_HOST" --rpc-port "$RPC_PORT" \
  --mine --miner-wallet "$WALLET" &
NODE_PID=$!

python3 -m scratchchain --data-dir "$DATA_DIR" indexer --host "$INDEXER_HOST" --port "$INDEXER_PORT" &
INDEXER_PID=$!

python3 -m http.server "$UI_PORT" --directory ./explorer &
UI_PID=$!

echo "Node PID: $NODE_PID"
echo "Indexer PID: $INDEXER_PID"
echo "UI PID: $UI_PID"
echo "Explorer: http://127.0.0.1:$UI_PORT"

trap 'kill $NODE_PID $INDEXER_PID $UI_PID' EXIT
wait
