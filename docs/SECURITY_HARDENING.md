# Security Hardening

## Already implemented
- ECDSA via cryptography library
- Signed handshake and message authentication
- RPC rate limits and optional auth token
- Snapshot signatures and trust lists
- Mempool eviction and fee bumping

## Still required for mainnet
- Formal security audit by external firm
- Fuzzing at protocol, transaction, and P2P layers at scale
- Static analysis and dependency supply chain review
- Hardware wallet or remote signer for validator keys
- DDoS protection at network edge
- Red-team and incident drills

## Recommended guardrails
- Isolate RPC behind a reverse proxy and auth token
- Use separate accounts and least-privilege keys
- Enforce firewall rules on node ports
- Continuous monitoring and alerting
