import json
import threading
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .chain import COIN
from .merkle import merkle_proof, verify_merkle_proof
from .tx import Transaction
from .wallet import Wallet

RPC_TOKEN = os.getenv("SCRATCHCHAIN_RPC_TOKEN")
MAX_RPC_SIZE = int(os.getenv("SCRATCHCHAIN_RPC_MAX", "1048576"))
RPC_RATE_LIMIT = int(os.getenv("SCRATCHCHAIN_RPC_RATE", "120"))


def _parse_amount(value):
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value * COIN)
    if isinstance(value, str):
        if value.strip().isdigit():
            return int(value)
        try:
            from decimal import Decimal
            return int(Decimal(value) * COIN)
        except Exception as exc:
            raise ValueError("invalid amount") from exc
    raise ValueError("invalid amount")


class RpcServer:
    def __init__(self, node, host: str, port: int) -> None:
        self.node = node
        self.host = host
        self.port = port
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[ThreadingHTTPServer] = None
        self.rate: Dict[str, Dict[str, float]] = {}

    def start(self) -> None:
        if self._thread:
            return

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code: int, payload: Dict[str, Any]) -> None:
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                if self.path != "/rpc":
                    self._send(404, {"ok": False, "error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_RPC_SIZE:
                    self._send(413, {"ok": False, "error": "payload_too_large"})
                    return
                if RPC_TOKEN:
                    token = self.headers.get("X-Auth-Token", "")
                    if token != RPC_TOKEN:
                        self._send(401, {"ok": False, "error": "unauthorized"})
                        return
                # simple rate limit per IP
                ip = self.client_address[0]
                now = time.time()
                rec = self.server.node.rpc.rate.get(ip, {"count": 0, "ts": now})
                if now - rec["ts"] > 60:
                    rec = {"count": 0, "ts": now}
                rec["count"] += 1
                self.server.node.rpc.rate[ip] = rec
                if rec["count"] > RPC_RATE_LIMIT:
                    self._send(429, {"ok": False, "error": "rate_limited"})
                    return
                raw = self.rfile.read(length)
                try:
                    req = json.loads(raw.decode())
                except Exception:
                    self._send(400, {"ok": False, "error": "invalid_json"})
                    return

                method = req.get("method")
                params = req.get("params", {})
                try:
                    result = self.server.node._rpc_handle(method, params)
                    self._send(200, {"ok": True, "result": result})
                except Exception as exc:
                    self._send(400, {"ok": False, "error": str(exc)})

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.node = self.node
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


class RpcMixin:
    def _rpc_handle(self, method: str, params: Dict[str, Any]) -> Any:
        if method == "get_info":
            return self.status()
        if method == "get_metrics":
            return self.metrics()
        if method == "get_balance":
            address = params.get("address")
            if not address:
                raise ValueError("address required")
            return {"address": address, "balance": self.chain.get_balance(address)}
        if method == "get_stake":
            address = params.get("address")
            if not address:
                raise ValueError("address required")
            return {"address": address, "stake": self.chain.get_stake(address)}
        if method == "get_block":
            block_hash = params.get("hash")
            if not block_hash:
                raise ValueError("hash required")
            block = self.chain.get_block(block_hash)
            if not block:
                raise ValueError("block not found")
            return block.to_dict()
        if method == "get_headers":
            start = int(params.get("start", 0))
            count = int(params.get("count", 200))
            return self.chain.get_headers(start, count)
        if method == "get_contract":
            contract_id = params.get("contract_id")
            if not contract_id:
                raise ValueError("contract_id required")
            contract = self.chain.contracts.get(contract_id)
            if not contract:
                raise ValueError("contract not found")
            return {
                "id": contract.contract_id,
                "creator": contract.creator,
                "code": contract.code,
                "storage": contract.storage,
            }
        if method == "get_validators":
            return self.chain.get_validators()
        if method == "get_governance":
            return self.chain.get_governance()
        if method == "get_tx":
            txid = params.get("txid")
            if not txid:
                raise ValueError("txid required")
            data = self.chain.get_tx(txid)
            if not data:
                raise ValueError("tx not found")
            return data
        if method == "get_receipt":
            txid = params.get("txid")
            if not txid:
                raise ValueError("txid required")
            data = self.chain.get_receipt(txid)
            if not data:
                raise ValueError("receipt not found")
            return data
        if method == "get_history":
            address = params.get("address")
            limit = int(params.get("limit", 50))
            offset = int(params.get("offset", 0))
            direction = params.get("direction")
            if not address:
                raise ValueError("address required")
            return self.chain.get_history(address, limit, offset, direction)
        if method == "get_block_by_height":
            height = int(params.get("height"))
            block = self.chain.get_block_by_height(height)
            if not block:
                raise ValueError("block not found")
            return block.to_dict()
        if method == "submit_tx":
            tx_data = params.get("tx")
            if not tx_data:
                raise ValueError("tx required")
            tx = Transaction.from_dict(tx_data)
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "send":
            wallet_path = params.get("wallet")
            to = params.get("to")
            amount = params.get("amount")
            fee = params.get("fee")
            if not wallet_path or not to or amount is None:
                raise ValueError("wallet, to, amount required")
            wallet = Wallet.load(wallet_path)
            fee_value = _parse_amount(fee) if fee is not None else 0
            tx = self.chain.build_transfer_tx(wallet, to, _parse_amount(amount), fee=fee_value)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "stake":
            wallet_path = params.get("wallet")
            amount = params.get("amount")
            fee = params.get("fee")
            if not wallet_path or amount is None:
                raise ValueError("wallet, amount required")
            wallet = Wallet.load(wallet_path)
            fee_value = _parse_amount(fee) if fee is not None else 0
            tx = self.chain.build_stake_tx(wallet, _parse_amount(amount), fee=fee_value)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "unstake":
            wallet_path = params.get("wallet")
            amount = params.get("amount")
            fee = params.get("fee")
            if not wallet_path or amount is None:
                raise ValueError("wallet, amount required")
            wallet = Wallet.load(wallet_path)
            fee_value = _parse_amount(fee) if fee is not None else 0
            tx = self.chain.build_unstake_tx(wallet, _parse_amount(amount), fee=fee_value)
            if not tx:
                raise ValueError("insufficient stake")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "contract_create":
            wallet_path = params.get("wallet")
            code = params.get("code")
            storage = params.get("storage", {})
            gas_limit = int(params.get("gas_limit", 0))
            gas_price = int(params.get("gas_price", 0))
            if not wallet_path or not isinstance(code, list):
                raise ValueError("wallet, code required")
            wallet = Wallet.load(wallet_path)
            tx = self.chain.build_contract_create_tx(wallet, code, storage, gas_limit, gas_price)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "contract_call":
            wallet_path = params.get("wallet")
            contract_id = params.get("contract_id")
            calldata = params.get("calldata", [])
            gas_limit = int(params.get("gas_limit", 0))
            gas_price = int(params.get("gas_price", 0))
            if not wallet_path or not contract_id:
                raise ValueError("wallet, contract_id required")
            wallet = Wallet.load(wallet_path)
            tx = self.chain.build_contract_call_tx(wallet, contract_id, calldata, gas_limit, gas_price)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "validator_register":
            wallet_path = params.get("wallet")
            name = params.get("name", "")
            website = params.get("website", "")
            commission = params.get("commission")
            fee = params.get("fee")
            if not wallet_path:
                raise ValueError("wallet required")
            wallet = Wallet.load(wallet_path)
            tx = self.chain.build_validator_register_tx(wallet, name=name, website=website, commission=commission, fee=fee)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "validator_update":
            wallet_path = params.get("wallet")
            name = params.get("name", "")
            website = params.get("website", "")
            commission = params.get("commission")
            fee = params.get("fee")
            if not wallet_path:
                raise ValueError("wallet required")
            wallet = Wallet.load(wallet_path)
            tx = self.chain.build_validator_update_tx(wallet, name=name, website=website, commission=commission, fee=fee)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "gov_update":
            wallet_path = params.get("wallet")
            changes = params.get("params")
            fee = params.get("fee")
            if not wallet_path or not isinstance(changes, dict):
                raise ValueError("wallet, params required")
            wallet = Wallet.load(wallet_path)
            tx = self.chain.build_gov_update_tx(wallet, changes, fee=fee)
            if not tx:
                raise ValueError("insufficient funds")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "get_tx_proof":
            block_hash = params.get("block_hash")
            txid = params.get("txid")
            if not block_hash or not txid:
                raise ValueError("block_hash, txid required")
            block = self.chain.get_block(block_hash)
            if not block:
                raise ValueError("block not found")
            txids = [t.txid for t in block.txs]
            if txid not in txids:
                raise ValueError("tx not in block")
            idx = txids.index(txid)
            proof = merkle_proof(txids, idx)
            return {"root": block.header.merkle_root, "index": idx, "txid": txid, "proof": proof}
        if method == "verify_tx_proof":
            leaf = params.get("txid")
            root = params.get("root")
            proof = params.get("proof")
            if not leaf or not root or not proof:
                raise ValueError("txid, root, proof required")
            ok = verify_merkle_proof(leaf, proof, root)
            return {"valid": ok}
        if method == "slash":
            header_a = params.get("header_a")
            header_b = params.get("header_b")
            reward_to = params.get("reward_to")
            if not isinstance(header_a, dict) or not isinstance(header_b, dict):
                raise ValueError("header_a and header_b required")
            tx = self.chain.build_slash_tx(header_a, header_b, reward_to=reward_to)
            if not tx:
                raise ValueError("invalid evidence")
            if not self.chain.add_tx(tx):
                raise ValueError("tx rejected")
            return {"txid": tx.txid}
        if method == "snapshot_create":
            path = params.get("path")
            if not path:
                if not self.chain.best_tip:
                    raise ValueError("chain not initialized")
                path = self.chain._snapshot_path(self.chain.height, self.chain.best_tip)
            snapshot = self.chain.snapshot_dict()
            if not params.get("unsigned"):
                priv = getattr(self, "identity_priv", None)
                pub = getattr(self, "identity_pub", None)
                if priv and pub:
                    snapshot = self.chain.sign_snapshot(snapshot, priv, pub)
            self.chain.save_snapshot(path, snapshot)
            return {"path": path}
        if method == "snapshot_load":
            path = params.get("path")
            if not path:
                raise ValueError("path required")
            snap = self.chain.load_snapshot(path)
            self.chain.apply_snapshot(snap)
            return {"ok": True}
        if method == "mine":
            wallet_path = params.get("wallet")
            if not wallet_path:
                raise ValueError("wallet required")
            wallet = Wallet.load(wallet_path)
            block = self.chain.mine_block(wallet.address, wallet.priv, wallet.algo)
            if not block:
                raise ValueError("mining failed")
            return {"hash": block.hash, "height": block.header.height}
        if method == "create_wallet":
            path = params.get("wallet")
            algo = params.get("algo", "ecdsa")
            if not path:
                raise ValueError("wallet required")
            if algo != "ecdsa":
                raise ValueError("only ecdsa is supported")
            wallet = Wallet.create(algo=algo)
            wallet.save(path)
            return {"address": wallet.address, "wallet": path, "algo": algo}
        if method == "wallet_info":
            path = params.get("wallet")
            if not path:
                raise ValueError("wallet required")
            wallet = Wallet.load(path)
            return {"address": wallet.address, "wallet": path, "algo": wallet.algo}
        raise ValueError("unknown method")
