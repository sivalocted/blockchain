from typing import Dict

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
        Prehashed,
    )
except Exception as exc:  # pragma: no cover - hard fail when dependency missing
    raise ImportError(
        "cryptography is required. Install with `python3 -m pip install cryptography`."
    ) from exc

from .utils import sha256

CURVE = ec.SECP256K1()
# secp256k1 order (for low-s normalization)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _ensure_algo(algo: str) -> None:
    if algo != "ecdsa":
        raise ValueError("Only ecdsa (secp256k1) is supported.")


def _low_s(s: int) -> int:
    return N - s if s > N // 2 else s


# -----------------------------
# ECDSA secp256k1 (cryptography)
# -----------------------------


def ecdsa_generate_keypair() -> Dict[str, int]:
    key = ec.generate_private_key(CURVE)
    nums = key.private_numbers()
    return {"d": nums.private_value, "x": nums.public_numbers.x, "y": nums.public_numbers.y}


def ecdsa_public_key(priv: Dict[str, int]) -> Dict[str, int]:
    if "x" in priv and "y" in priv:
        return {"x": priv["x"], "y": priv["y"]}
    key = ec.derive_private_key(priv["d"], CURVE)
    pub = key.public_key().public_numbers()
    return {"x": pub.x, "y": pub.y}


def ecdsa_sign(message_hash_hex: str, priv: Dict[str, int]) -> str:
    key = ec.derive_private_key(priv["d"], CURVE)
    digest = bytes.fromhex(message_hash_hex)
    sig = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig)
    s = _low_s(s)
    return f"{r:x}:{s:x}"


def ecdsa_verify(message_hash_hex: str, signature: str, pub: Dict[str, int]) -> bool:
    try:
        r_hex, s_hex = signature.split(":")
        r = int(r_hex, 16)
        s = int(s_hex, 16)
    except Exception:
        return False
    if r <= 0 or r >= N or s <= 0 or s >= N:
        return False
    sig = encode_dss_signature(r, s)
    try:
        key = ec.EllipticCurvePublicNumbers(pub["x"], pub["y"], CURVE).public_key()
        digest = bytes.fromhex(message_hash_hex)
        key.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def ecdsa_key_to_hex(key: Dict[str, int]) -> Dict[str, str]:
    out = {}
    if "d" in key:
        out["d"] = hex(key["d"])
    if "x" in key:
        out["x"] = hex(key["x"])
    if "y" in key:
        out["y"] = hex(key["y"])
    return out


def ecdsa_key_from_hex(key: Dict[str, str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    if "d" in key:
        out["d"] = int(key["d"], 16)
    if "x" in key:
        out["x"] = int(key["x"], 16)
    if "y" in key:
        out["y"] = int(key["y"], 16)
    return out


# -----------------------------
# Unified helpers
# -----------------------------


def generate_keypair(algo: str = "ecdsa", bits: int = 1024) -> Dict[str, int]:
    _ensure_algo(algo)
    return ecdsa_generate_keypair()


def public_key(priv: Dict[str, int], algo: str = "ecdsa") -> Dict[str, int]:
    _ensure_algo(algo)
    return ecdsa_public_key(priv)


def sign(message_hash_hex: str, priv: Dict[str, int], algo: str = "ecdsa") -> str:
    _ensure_algo(algo)
    return ecdsa_sign(message_hash_hex, priv)


def verify(message_hash_hex: str, signature: str, pub: Dict[str, int], algo: str = "ecdsa") -> bool:
    _ensure_algo(algo)
    return ecdsa_verify(message_hash_hex, signature, pub)


def key_to_hex(key: Dict[str, int], algo: str = "ecdsa") -> Dict[str, str]:
    _ensure_algo(algo)
    return ecdsa_key_to_hex(key)


def key_from_hex(key: Dict[str, str], algo: str = "ecdsa") -> Dict[str, int]:
    _ensure_algo(algo)
    return ecdsa_key_from_hex(key)


def address_from_pubkey(pub: Dict[str, int], algo: str = "ecdsa") -> str:
    _ensure_algo(algo)
    payload = f"ecdsa:{pub['x']}:{pub['y']}".encode()
    return sha256(payload)[:40]
