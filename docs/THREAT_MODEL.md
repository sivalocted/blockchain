# Threat Model

## Assets
- Validator private keys
- UTXO database and state
- Chain history and snapshots
- Governance keys and parameters

## Adversaries
- Remote attackers on P2P and RPC
- Malicious validators
- Spam and DoS actors
- Insider or compromised operator

## Attack surface
- P2P handshake and message parsing
- RPC endpoints
- Mempool and block validation
- Snapshot download and restore

## Controls
- Signed handshakes and message auth
- RPC auth token and rate limit
- Snapshot signatures and trust lists
- Slashing for equivocation
- Mempool eviction and fee bumping
