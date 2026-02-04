# Security Levels

ScratchChain supports preset security profiles via `SCRATCHCHAIN_SECURITY_LEVEL`.

Levels:
- `standard`: default behavior (developer friendly).
- `hardened`: tighter RPC/mempool limits, TLS enabled, signed snapshots required.
- `paranoid`: strict limits, TLS verification, trusted peers only, and required secrets.

## Hardened (recommended for public testnets)
Set:
```
SCRATCHCHAIN_SECURITY_LEVEL=hardened
SCRATCHCHAIN_RPC_TOKEN=change_me
SCRATCHCHAIN_P2P_SECRET=change_me
```

Effects (defaults if not already set):
- Lower RPC rate and payload size
- Mempool limits reduced
- Minimum relay fee enforced
- Finality depth increased
- Signed snapshots required
- P2P TLS enabled

## Paranoid (production hardening)
Set:
```
SCRATCHCHAIN_SECURITY_LEVEL=paranoid
SCRATCHCHAIN_RPC_TOKEN=change_me
SCRATCHCHAIN_P2P_SECRET=change_me
SCRATCHCHAIN_TRUSTED_PEERS=ip1:9333,ip2:9333
SCRATCHCHAIN_P2P_CA=/path/to/ca.pem
```

Additional effects:
- TLS verification required
- Trusted peers only
- Stricter mempool and message limits

## Important limitation
No configuration makes a blockchain "uncrackable". This project currently uses ECDSA
(secp256k1), which is strong against classical computers but not post-quantum safe.
If you require quantum resistance, the signature scheme must be replaced or upgraded
(e.g., hybrid ECDSA + post-quantum signatures), which is a larger protocol change.
