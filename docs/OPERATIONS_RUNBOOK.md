# Operations Runbook

## Daily checks
- Confirm node height and peer count
- Confirm indexer is synced to tip
- Review mempool size and block time
- Verify snapshot creation schedule

## Backups
- Create signed snapshots daily
- Copy snapshots to off-site storage
- Test restore monthly

## Upgrades
- Announce upgrade window
- Snapshot state before upgrade
- Roll out to a canary node first
- Monitor for forks and rollback if needed

## Recovery
- Restore from latest signed snapshot
- Validate chain tip and rejoin peers
- Rebuild indexer from snapshot if needed

## On-call
- Define severity levels and response SLAs
- Keep a rollback plan ready
