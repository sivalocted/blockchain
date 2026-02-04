import json
from dataclasses import dataclass
from typing import Dict

from . import crypto


@dataclass
class Wallet:
    priv: Dict[str, int]
    algo: str = "ecdsa"

    @staticmethod
    def create(algo: str = "ecdsa", bits: int = 1024) -> "Wallet":
        if algo != "ecdsa":
            raise ValueError("Only ecdsa is supported.")
        priv = crypto.generate_keypair(algo=algo, bits=bits)
        return Wallet(priv=priv, algo=algo)

    @property
    def pub(self) -> Dict[str, int]:
        return crypto.public_key(self.priv, self.algo)

    @property
    def address(self) -> str:
        return crypto.address_from_pubkey(self.pub, self.algo)

    def to_dict(self) -> Dict[str, object]:
        return {"algo": self.algo, "private_key": crypto.key_to_hex(self.priv, self.algo)}

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "Wallet":
        algo = str(data.get("algo", "ecdsa"))
        if algo != "ecdsa":
            raise ValueError("Only ecdsa wallets are supported.")
        key = data.get("private_key", {})
        priv = crypto.key_from_hex(key, algo)
        return Wallet(priv=priv, algo=algo)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def load(path: str) -> "Wallet":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Wallet.from_dict(data)
