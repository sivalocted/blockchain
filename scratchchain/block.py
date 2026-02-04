from dataclasses import dataclass, field
from typing import List

from .merkle import merkle_root
from .utils import json_dumps, sha256, now_ts
from .tx import Transaction


@dataclass
class BlockHeader:
    prev_hash: str
    merkle_root: str
    timestamp: int
    nonce: int
    difficulty: int
    height: int
    base_gas_price: int = 0
    gas_used: int = 0
    validator: str = ""
    validator_pubkey: dict = field(default_factory=dict)
    validator_sig_algo: str = ""
    signature: str = ""

    def payload_dict(self) -> dict:
        return {
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "height": self.height,
            "base_gas_price": self.base_gas_price,
            "gas_used": self.gas_used,
            "validator": self.validator,
            "validator_pubkey": self.validator_pubkey,
            "validator_sig_algo": self.validator_sig_algo,
        }

    def to_dict(self) -> dict:
        data = self.payload_dict()
        if self.signature:
            data["signature"] = self.signature
        return data


@dataclass
class Block:
    header: BlockHeader
    txs: List[Transaction] = field(default_factory=list)

    @property
    def hash(self) -> str:
        payload = json_dumps(self.header.payload_dict()).encode()
        return sha256(payload)

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "txs": [tx.to_dict(include_sigs=True) for tx in self.txs],
        }

    @staticmethod
    def from_dict(data: dict) -> "Block":
        header_data = data["header"]
        header = BlockHeader(
            prev_hash=header_data["prev_hash"],
            merkle_root=header_data["merkle_root"],
            timestamp=header_data["timestamp"],
            nonce=header_data["nonce"],
            difficulty=header_data["difficulty"],
            height=header_data["height"],
            base_gas_price=header_data.get("base_gas_price", 0),
            gas_used=header_data.get("gas_used", 0),
            validator=header_data.get("validator", ""),
            validator_pubkey=header_data.get("validator_pubkey", {}),
            validator_sig_algo=header_data.get("validator_sig_algo", ""),
            signature=header_data.get("signature", ""),
        )
        txs = [Transaction.from_dict(t) for t in data["txs"]]
        return Block(header=header, txs=txs)

    @staticmethod
    def build(
        prev_hash: str,
        height: int,
        difficulty: int,
        txs: List[Transaction],
        base_gas_price: int = 0,
        gas_used: int = 0,
        validator: str = "",
        validator_pubkey: dict = None,
        validator_sig_algo: str = "",
    ) -> "Block":
        root = merkle_root([tx.txid for tx in txs])
        header = BlockHeader(
            prev_hash=prev_hash,
            merkle_root=root,
            timestamp=now_ts(),
            nonce=0,
            difficulty=difficulty,
            height=height,
            base_gas_price=base_gas_price,
            gas_used=gas_used,
            validator=validator,
            validator_pubkey=validator_pubkey or {},
            validator_sig_algo=validator_sig_algo,
        )
        return Block(header=header, txs=txs)

    def mine(self) -> None:
        target = 1 << (256 - self.header.difficulty)
        while True:
            h = int(self.hash, 16)
            if h < target:
                return
            self.header.nonce += 1


def header_hash_from_dict(header_data: dict) -> str:
    payload = {
        "prev_hash": header_data["prev_hash"],
        "merkle_root": header_data["merkle_root"],
        "timestamp": header_data["timestamp"],
        "nonce": header_data["nonce"],
        "difficulty": header_data["difficulty"],
        "height": header_data["height"],
        "base_gas_price": header_data.get("base_gas_price", 0),
        "gas_used": header_data.get("gas_used", 0),
        "validator": header_data.get("validator", ""),
        "validator_pubkey": header_data.get("validator_pubkey", {}),
        "validator_sig_algo": header_data.get("validator_sig_algo", ""),
    }
    return sha256(json_dumps(payload).encode())
