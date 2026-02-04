from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import crypto
from .utils import json_dumps, sha256, now_ts


@dataclass
class TxInput:
    prev_txid: str
    output_index: int
    signature: str = ""
    pubkey: Optional[Dict[str, str]] = None
    sig_algo: str = "ecdsa"

    def to_dict(self, include_sig: bool = True, include_pubkey: bool = True) -> Dict[str, object]:
        data = {
            "prev_txid": self.prev_txid,
            "output_index": self.output_index,
            "sig_algo": self.sig_algo,
        }
        if include_pubkey:
            data["pubkey"] = self.pubkey
        if include_sig:
            data["signature"] = self.signature
        return data

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "TxInput":
        return TxInput(
            prev_txid=data["prev_txid"],
            output_index=int(data["output_index"]),
            signature=str(data.get("signature", "")),
            pubkey=data.get("pubkey"),
            sig_algo=str(data.get("sig_algo", "ecdsa")),
        )


@dataclass
class TxOutput:
    amount: int
    address: str
    stake: bool = False

    def to_dict(self) -> Dict[str, object]:
        data = {"amount": self.amount, "address": self.address}
        if self.stake:
            data["stake"] = True
        return data

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "TxOutput":
        return TxOutput(
            amount=int(data["amount"]),
            address=str(data["address"]),
            stake=bool(data.get("stake", False)),
        )


@dataclass
class Transaction:
    inputs: List[TxInput]
    outputs: List[TxOutput]
    timestamp: int = field(default_factory=now_ts)
    coinbase_data: str = ""
    tx_type: str = "transfer"
    gas_limit: int = 0
    gas_price: int = 0
    payload: Optional[Dict[str, object]] = None

    def to_dict(self, include_sigs: bool = True) -> Dict[str, object]:
        return {
            "inputs": [
                inp.to_dict(include_sig=include_sigs, include_pubkey=include_sigs)
                for inp in self.inputs
            ],
            "outputs": [out.to_dict() for out in self.outputs],
            "timestamp": self.timestamp,
            "coinbase_data": self.coinbase_data,
            "tx_type": self.tx_type,
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            "payload": self.payload,
        }

    @staticmethod
    def from_dict(data: Dict[str, object]) -> "Transaction":
        return Transaction(
            inputs=[TxInput.from_dict(i) for i in data.get("inputs", [])],
            outputs=[TxOutput.from_dict(o) for o in data.get("outputs", [])],
            timestamp=int(data.get("timestamp", now_ts())),
            coinbase_data=str(data.get("coinbase_data", "")),
            tx_type=str(data.get("tx_type", "transfer")),
            gas_limit=int(data.get("gas_limit", 0)),
            gas_price=int(data.get("gas_price", 0)),
            payload=data.get("payload"),
        )

    @property
    def txid(self) -> str:
        payload = json_dumps(self.to_dict(include_sigs=False)).encode()
        return sha256(payload)


    def estimate_size(self) -> int:
        data = json_dumps(self.to_dict(include_sigs=True))
        return len(data)

    def sign(self, priv_key: Dict[str, int], algo: str = "ecdsa") -> None:
        if self.is_coinbase:
            return
        pub = crypto.public_key(priv_key, algo)
        pub_hex = crypto.key_to_hex(pub, algo)
        msg = self.txid
        sig = crypto.sign(msg, priv_key, algo)
        for inp in self.inputs:
            inp.signature = sig
            inp.pubkey = pub_hex
            inp.sig_algo = algo

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 0

    def validate(self, utxo: Dict[str, TxOutput]) -> bool:
        if self.is_coinbase:
            return self.tx_type in ("coinbase", "slash")

        total_in = 0
        total_out = sum(o.amount for o in self.outputs)
        seen = set()
        msg = self.txid

        for inp in self.inputs:
            key = f"{inp.prev_txid}:{inp.output_index}"
            if key in seen:
                return False
            seen.add(key)

            prev_out = utxo.get(key)
            if not prev_out:
                return False

            if prev_out.stake and self.tx_type != "unstake":
                return False

            if not inp.pubkey or not inp.signature:
                return False

            try:
                pub = crypto.key_from_hex(inp.pubkey, inp.sig_algo)
                addr = crypto.address_from_pubkey(pub, inp.sig_algo)
                if addr != prev_out.address:
                    return False
                if not crypto.verify(msg, inp.signature, pub, inp.sig_algo):
                    return False
            except Exception:
                return False

            total_in += prev_out.amount

        if total_in < total_out:
            return False
        # staking outputs only allowed in stake tx
        if any(o.stake for o in self.outputs) and self.tx_type != "stake":
            return False
        return True


def create_coinbase(address: str, amount: int, data: str = "") -> Transaction:
    out = TxOutput(amount=amount, address=address)
    return Transaction(inputs=[], outputs=[out], coinbase_data=data, tx_type="coinbase")
