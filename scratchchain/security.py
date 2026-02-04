import os


_LEVELS = {"standard", "hardened", "paranoid"}

_DEFAULTS = {
    "hardened": {
        "SCRATCHCHAIN_RPC_RATE": "60",
        "SCRATCHCHAIN_RPC_MAX": "262144",
        "SCRATCHCHAIN_MAX_MEMPOOL_TXS": "3000",
        "SCRATCHCHAIN_MAX_MEMPOOL_BYTES": "3000000",
        "SCRATCHCHAIN_MIN_RELAY_FEE_RATE": "1",
        "SCRATCHCHAIN_FINALITY_DEPTH": "24",
        "SCRATCHCHAIN_REQUIRE_SIGNED_SNAPSHOT": "1",
        "SCRATCHCHAIN_P2P_TLS": "1",
    },
    "paranoid": {
        "SCRATCHCHAIN_RPC_RATE": "30",
        "SCRATCHCHAIN_RPC_MAX": "131072",
        "SCRATCHCHAIN_MAX_MEMPOOL_TXS": "1500",
        "SCRATCHCHAIN_MAX_MEMPOOL_BYTES": "1500000",
        "SCRATCHCHAIN_MIN_RELAY_FEE_RATE": "5",
        "SCRATCHCHAIN_FINALITY_DEPTH": "48",
        "SCRATCHCHAIN_REQUIRE_SIGNED_SNAPSHOT": "1",
        "SCRATCHCHAIN_P2P_TLS": "1",
        "SCRATCHCHAIN_P2P_TLS_VERIFY": "1",
        "SCRATCHCHAIN_P2P_TRUSTED_ONLY": "1",
        "SCRATCHCHAIN_MAX_PEERS": "16",
        "SCRATCHCHAIN_MSG_RATE": "120",
        "SCRATCHCHAIN_MAX_TXS_MSG": "1000",
    },
}

_REQUIREMENTS = {
    "hardened": [
        "SCRATCHCHAIN_RPC_TOKEN",
        "SCRATCHCHAIN_P2P_SECRET",
    ],
    "paranoid": [
        "SCRATCHCHAIN_RPC_TOKEN",
        "SCRATCHCHAIN_P2P_SECRET",
        "SCRATCHCHAIN_TRUSTED_PEERS",
        "SCRATCHCHAIN_P2P_CA",
    ],
}


def get_security_level() -> str:
    level = os.getenv("SCRATCHCHAIN_SECURITY_LEVEL", "standard").strip().lower()
    if level not in _LEVELS:
        return "standard"
    return level


def apply_security_defaults() -> str:
    level = get_security_level()
    defaults = _DEFAULTS.get(level, {})
    for key, value in defaults.items():
        os.environ.setdefault(key, str(value))
    return level


def enforce_security_requirements() -> None:
    level = get_security_level()
    required = _REQUIREMENTS.get(level, [])
    if not required:
        return
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError(
            f"Security level '{level}' requires env vars: {', '.join(missing)}"
        )
