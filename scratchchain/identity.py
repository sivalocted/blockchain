import json
import os
from typing import Dict, Tuple

from . import crypto
from .utils import json_dumps, sha256


def _key_path(data_dir: str) -> str:
    return os.path.join(data_dir, "node_key.json")


def load_or_create_node_key(data_dir: str) -> Tuple[Dict[str, int], Dict[str, int], str]:
    os.makedirs(data_dir, exist_ok=True)
    path = _key_path(data_dir)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        priv = crypto.key_from_hex(data["private_key"], "ecdsa")
    else:
        priv = crypto.generate_keypair("ecdsa")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"private_key": crypto.key_to_hex(priv, "ecdsa")}, f, indent=2)
    pub = crypto.public_key(priv, "ecdsa")
    node_id = crypto.address_from_pubkey(pub, "ecdsa")
    return priv, pub, node_id


def sign_payload(payload: dict, priv: Dict[str, int]) -> str:
    msg = sha256(json_dumps(payload).encode())
    return crypto.sign(msg, priv, "ecdsa")


def verify_payload(payload: dict, signature: str, pub: Dict[str, int]) -> bool:
    msg = sha256(json_dumps(payload).encode())
    return crypto.verify(msg, signature, pub, "ecdsa")


def pubkey_fingerprint(pub: Dict[str, int]) -> str:
    return sha256(json_dumps(pub).encode())
