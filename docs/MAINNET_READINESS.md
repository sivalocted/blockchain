# Mainnet Readiness

This file is a practical checklist for launching a real mainnet. Items tagged [done] are already implemented in code. Items tagged [ops] require infrastructure work. Items tagged [external] require third-party validation.

## Protocol and consensus
- [done] PoW and PoS modes with finality checkpoints
- [done] Validator registry and rotation
- [done] Slashing for equivocation
- [done] Fee market and gas accounting
- [done] Halving schedule and max supply cap
- [ops] Freeze genesis parameters and document them
- [external] Economic simulation and adversarial testing

## Networking and security
- [done] Signed handshakes, HMAC message auth, banscore
- [done] Optional TLS for P2P
- [done] Header-first sync and compact blocks
- [ops] DDoS protection and rate limiting at the edge
- [ops] Seed node hardening and firewall rules
- [external] Security audit and penetration test

## Data and reliability
- [done] Snapshots and fast sync
- [done] Persistent peer identity
- [ops] Automated backups and restore drills
- [ops] Monitoring, alerting, and logging

## Governance and upgrades
- [done] On-chain parameter update tx
- [ops] Governance process and upgrade policy
- [external] Legal review of governance and token policy

## Wallets and UX
- [done] Local wallet console in UI
- [ops] Secure key custody model
- [external] Security audit of wallet flows

## Launch gates
- [ops] Public testnet run for 4 to 12 weeks without critical incident
- [external] Independent security audit completed and fixed
- [ops] Incident response and on-call coverage in place
- [ops] Final tokenomics and distribution plan published
