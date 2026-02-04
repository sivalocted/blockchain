#!/usr/bin/env bash
set -euo pipefail

DATA_DIR=${DATA_DIR:-./scratchchain_data}
SNAPSHOT_DIR=${SNAPSHOT_DIR:-./snapshots}
BACKUP_DIR=${BACKUP_DIR:-}

mkdir -p "$SNAPSHOT_DIR"
STAMP=$(date +%Y%m%d%H%M%S)
PATH_OUT="$SNAPSHOT_DIR/snapshot-$STAMP.json"

python3 -m scratchchain --data-dir "$DATA_DIR" snapshot-create --path "$PATH_OUT"

echo "Snapshot created: $PATH_OUT"

if [ -n "$BACKUP_DIR" ]; then
  mkdir -p "$BACKUP_DIR"
  cp "$PATH_OUT" "$BACKUP_DIR/"
  echo "Snapshot copied to: $BACKUP_DIR"
fi
