import asyncio
import base64
import gzip
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import crypto
from .block import Block, header_hash_from_dict
from .chain import Chain
from .identity import load_or_create_node_key, pubkey_fingerprint, sign_payload, verify_payload
from .network import read_message, send_message
from .p2p_tls import build_ssl_context
from .rpc import RpcServer, RpcMixin
from .tx import Transaction
from .wallet import Wallet


@dataclass
class Peer:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    addr: Tuple[str, int]
    node_id: str = ""
    pubkey: dict = field(default_factory=dict)
    fingerprint: str = ""
    best_tip: str = ""
    best_height: int = -1
    best_work: int = 0
    msg_count: int = 0
    last_reset: float = 0.0
    authenticated: bool = False
    services: Dict[str, bool] = field(default_factory=dict)
    last_seen: float = 0.0


MAX_HEADERS = int(os.getenv("SCRATCHCHAIN_MAX_HEADERS", "200"))
MAX_PEERS = int(os.getenv("SCRATCHCHAIN_MAX_PEERS", "32"))
MSG_RATE_LIMIT = int(os.getenv("SCRATCHCHAIN_MSG_RATE", "200"))
BAN_THRESHOLD = int(os.getenv("SCRATCHCHAIN_BAN_THRESHOLD", "100"))
BAN_TIME = int(os.getenv("SCRATCHCHAIN_BAN_TIME", "600"))
COMPACT_BLOCKS = os.getenv("SCRATCHCHAIN_COMPACT_BLOCKS", "1") == "1"
HELLO_MAX_SKEW = int(os.getenv("SCRATCHCHAIN_HELLO_SKEW", "60"))
MAX_TXS_PER_MSG = int(os.getenv("SCRATCHCHAIN_MAX_TXS_MSG", "2000"))
MAX_SNAPSHOT_BYTES = int(os.getenv("SCRATCHCHAIN_MAX_SNAPSHOT_BYTES", "5000000"))
MAX_TX_CACHE = int(os.getenv("SCRATCHCHAIN_MAX_TX_CACHE", "10000"))
HELLO_NONCE_TTL = int(os.getenv("SCRATCHCHAIN_HELLO_NONCE_TTL", "300"))
TRUSTED_ONLY = os.getenv("SCRATCHCHAIN_P2P_TRUSTED_ONLY", "0") == "1"
FASTSYNC = os.getenv("SCRATCHCHAIN_FASTSYNC", "0") == "1"
SEEDS = [p for p in os.getenv("SCRATCHCHAIN_SEEDS", "").split(",") if p]


class Node(RpcMixin):
    def __init__(
        self,
        data_dir: str,
        host: str = "0.0.0.0",
        port: int = 9333,
        peers: Optional[List[Tuple[str, int]]] = None,
        rpc_host: str = "127.0.0.1",
        rpc_port: int = 9334,
        miner_wallet: Optional[str] = None,
        enable_mining: bool = False,
        mine_interval: int = 10,
    ) -> None:
        self.data_dir = data_dir
        self.chain = Chain(data_dir)
        self.host = host
        self.port = port
        self.peer_addrs = peers or []
        self.peers: Dict[str, Peer] = {}

        self.identity_priv, self.identity_pub, self.node_id = load_or_create_node_key(data_dir)
        self.identity_fp = pubkey_fingerprint(self.identity_pub)

        self.tls_server_ctx = build_ssl_context(data_dir, True)
        self.tls_client_ctx = build_ssl_context(data_dir, False)

        self.known_peers: Dict[str, float] = {}
        self.peer_fingerprints: Dict[str, str] = {}
        self.trusted_peers: Dict[str, str] = {}
        self.seen_nonces: Dict[str, float] = {}
        self._load_peer_cache()
        self._load_trusted_peers()

        self.bans: Dict[str, float] = {}
        self.banscore: Dict[str, int] = {}
        self.compact_pending: Dict[str, dict] = {}
        self.tx_cache: Dict[str, Transaction] = {}
        self._requested_blocks: Dict[str, int] = {}

        self.rpc = RpcServer(self, rpc_host, rpc_port)
        self.enable_mining = enable_mining
        self.mine_interval = mine_interval
        self._server: Optional[asyncio.AbstractServer] = None
        self.miner_address: Optional[str] = None
        self.miner_priv: Optional[dict] = None
        self.miner_algo: str = "ecdsa"
        if miner_wallet:
            wallet = Wallet.load(miner_wallet)
            self.miner_address = wallet.address
            self.miner_priv = wallet.priv
            self.miner_algo = wallet.algo

        for host, port in self.peer_addrs:
            self._add_known_peer(f"{host}:{port}")
        for seed in SEEDS:
            self._add_known_peer(seed)

    def status(self) -> dict:
        return {
            "node_id": self.node_id,
            "best_tip": self.chain.best_tip,
            "height": self.chain.height,
            "best_work": self.chain.best_work,
            "difficulty": self.chain.difficulty,
            "mempool_size": len(self.chain.mempool),
            "peers": list(self.peers.keys()),
            "known_peers": list(self.known_peers.keys()),
        }

    def metrics(self) -> dict:
        base = self.status()
        base.update(self.chain.metrics())
        base["banscore"] = dict(self.banscore)
        return base

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_incoming, self.host, self.port, ssl=self.tls_server_ctx
        )
        self.rpc.start()

        for peer_id in list(self.known_peers.keys()):
            host, port = peer_id.split(":")
            asyncio.create_task(self._connect_to_peer(host, int(port)))

        if self.enable_mining:
            if not self.miner_address:
                print("Mining enabled but no --miner-wallet provided")
            else:
                asyncio.create_task(self._mine_loop())

        asyncio.create_task(self._peer_maintenance_loop())
        async with self._server:
            await self._server.serve_forever()

    async def _peer_maintenance_loop(self) -> None:
        while True:
            self._save_peer_cache()
            self._prune_nonces()
            await asyncio.sleep(60)

    def _peer_cache_path(self) -> str:
        return os.path.join(self.data_dir, "peers.json")

    def _trusted_peers_path(self) -> str:
        return os.path.join(self.data_dir, "trusted_peers.json")

    def _load_peer_cache(self) -> None:
        try:
            with open(self._peer_cache_path(), "r", encoding="utf-8") as f:
                data = f.read()
            obj = __import__("json").loads(data)
            self.known_peers = obj.get("known", {})
            self.peer_fingerprints = obj.get("fingerprints", {})
        except Exception:
            self.known_peers = {}
            self.peer_fingerprints = {}

    def _load_trusted_peers(self) -> None:
        trusted: Dict[str, str] = {}
        raw = os.getenv("SCRATCHCHAIN_TRUSTED_PEERS", "").strip()
        if raw:
            try:
                if raw.startswith("{"):
                    trusted.update(__import__("json").loads(raw))
                else:
                    for item in raw.split(","):
                        item = item.strip()
                        if not item or ":" not in item:
                            continue
                        node_id, fp = item.split(":", 1)
                        trusted[node_id.strip()] = fp.strip()
            except Exception:
                pass
        try:
            with open(self._trusted_peers_path(), "r", encoding="utf-8") as f:
                obj = __import__("json").loads(f.read())
            if isinstance(obj, dict):
                trusted.update(obj.get("trusted", obj))
        except Exception:
            pass
        self.trusted_peers = trusted

    def _save_peer_cache(self) -> None:
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            payload = {"known": self.known_peers, "fingerprints": self.peer_fingerprints}
            with open(self._peer_cache_path(), "w", encoding="utf-8") as f:
                f.write(__import__("json").dumps(payload, indent=2))
        except Exception:
            pass

    def _prune_nonces(self) -> None:
        if not self.seen_nonces:
            return
        now = time.time()
        for nonce, ts in list(self.seen_nonces.items()):
            if now - ts > HELLO_NONCE_TTL:
                self.seen_nonces.pop(nonce, None)

    def _add_known_peer(self, peer_id: str) -> None:
        if peer_id == f"{self.host}:{self.port}":
            return
        self.known_peers[peer_id] = time.time()

    def _score(self, peer_id: str, points: int) -> None:
        self.banscore[peer_id] = self.banscore.get(peer_id, 0) + points
        if self.banscore[peer_id] >= BAN_THRESHOLD:
            self.bans[peer_id] = time.time() + BAN_TIME

    def _is_banned(self, peer_id: str) -> bool:
        until = self.bans.get(peer_id, 0)
        if until and time.time() < until:
            return True
        if until and time.time() >= until:
            self.bans.pop(peer_id, None)
        return False

    async def _handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        peer_id = f"{addr[0]}:{addr[1]}"
        if self._is_banned(peer_id) or len(self.peers) >= MAX_PEERS:
            writer.close()
            await writer.wait_closed()
            return
        peer = Peer(reader=reader, writer=writer, addr=addr, last_reset=time.time())
        self._add_known_peer(peer_id)
        self.peers[peer_id] = peer
        await self._send_hello(peer)
        await self._peer_loop(peer, peer_id)

    async def _connect_to_peer(self, host: str, port: int) -> None:
        peer_id = f"{host}:{port}"
        if self._is_banned(peer_id) or peer_id in self.peers:
            return
        try:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=self.tls_client_ctx, server_hostname=host if self.tls_client_ctx else None
            )
        except Exception:
            return
        peer = Peer(reader=reader, writer=writer, addr=(host, port), last_reset=time.time())
        self._add_known_peer(peer_id)
        self.peers[peer_id] = peer
        await self._send_hello(peer)
        await self._peer_loop(peer, peer_id)

    async def _peer_loop(self, peer: Peer, peer_id: str) -> None:
        try:
            while True:
                msg = await read_message(peer.reader)
                if msg is None:
                    break
                now = time.time()
                if now - peer.last_reset > 60:
                    peer.last_reset = now
                    peer.msg_count = 0
                peer.msg_count += 1
                if peer.msg_count > MSG_RATE_LIMIT:
                    self._score(peer_id, BAN_THRESHOLD)
                    break
                if not peer.authenticated and msg.get("type") != "hello":
                    self._score(peer_id, BAN_THRESHOLD)
                    break
                await self._handle_message(peer, peer_id, msg)
        except Exception:
            pass
        finally:
            self.peers.pop(peer_id, None)
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass

    async def _handle_message(self, peer: Peer, peer_id: str, msg: dict) -> None:
        msg_type = msg.get("type")
        if msg_type == "hello":
            if not self._verify_hello(peer, peer_id, msg):
                self._score(peer_id, BAN_THRESHOLD)
                try:
                    peer.writer.close()
                    await peer.writer.wait_closed()
                except Exception:
                    pass
                return
            if peer.best_height > self.chain.height:
                await self._maybe_fast_sync(peer)
            return

        if msg_type == "get_peers":
            peers = list(self.known_peers.keys())
            await send_message(peer.writer, {"type": "peers", "peers": peers})
            return

        if msg_type == "peers":
            for p in msg.get("peers", []):
                if p not in self.known_peers and p != f"{self.host}:{self.port}":
                    self._add_known_peer(p)
                    host, port = p.split(":")
                    asyncio.create_task(self._connect_to_peer(host, int(port)))
            return

        if msg_type == "get_headers":
            start = int(msg.get("start", 0))
            count = min(int(msg.get("count", MAX_HEADERS)), MAX_HEADERS)
            headers = self.chain.get_headers(start, count)
            await send_message(peer.writer, {"type": "headers", "headers": headers})
            return

        if msg_type == "headers":
            headers = msg.get("headers", [])
            if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
                return
            for h in headers:
                try:
                    block_hash = header_hash_from_dict(h)
                except Exception:
                    continue
                if self.chain.has_block(block_hash):
                    continue
                await self._request_block(peer, block_hash)
            return

        if msg_type == "block_inv":
            header = msg.get("header")
            txids = msg.get("txids", [])
            if not header or not txids:
                return
            if len(txids) > MAX_TXS_PER_MSG:
                return
            try:
                block_hash = header_hash_from_dict(header)
            except Exception:
                return
            if self.chain.has_block(block_hash):
                return
            missing = [t for t in txids if t not in self.chain.mempool and t not in self.tx_cache]
            self.compact_pending[block_hash] = {"header": header, "txids": txids, "peer": peer}
            if missing:
                await send_message(peer.writer, {"type": "get_txs", "txids": missing[:MAX_TXS_PER_MSG]})
            else:
                await self._try_compact_block(block_hash)
            return

        if msg_type == "get_txs":
            txs = []
            for txid in msg.get("txids", [])[:MAX_TXS_PER_MSG]:
                tx = self.chain.mempool.get(txid) or self.tx_cache.get(txid)
                if tx:
                    txs.append(tx.to_dict(include_sigs=True))
            await send_message(peer.writer, {"type": "txs", "txs": txs})
            return

        if msg_type == "txs":
            for data in msg.get("txs", [])[:MAX_TXS_PER_MSG]:
                try:
                    tx = Transaction.from_dict(data)
                    self.tx_cache[tx.txid] = tx
                    if len(self.tx_cache) > MAX_TX_CACHE:
                        self.tx_cache.pop(next(iter(self.tx_cache)))
                    self.chain.add_tx(tx)
                except Exception:
                    continue
            for block_hash in list(self.compact_pending.keys()):
                await self._try_compact_block(block_hash)
            return

        if msg_type == "get_block":
            block_hash = msg.get("hash")
            if not block_hash:
                return
            block = self.chain.get_block(block_hash)
            if not block:
                return
            await send_message(peer.writer, {"type": "block", "block": block.to_dict()})
            return

        if msg_type == "block":
            data = msg.get("block")
            if not data:
                return
            block = Block.from_dict(data)
            status, missing_parent = self.chain.add_block(block)
            if status == "invalid":
                self._score(peer.node_id or peer_id, 10)
            if status == "orphan" and missing_parent:
                await self._request_block(peer, missing_parent)
            if status == "accepted":
                await self._broadcast_block(block, exclude=peer)
            return

        if msg_type == "tx":
            data = msg.get("tx")
            if not data:
                return
            tx = Transaction.from_dict(data)
            if len(self.tx_cache) > MAX_TX_CACHE:
                self.tx_cache.pop(next(iter(self.tx_cache)))
            if self.chain.add_tx(tx):
                await self.broadcast({"type": "tx", "tx": tx.to_dict(include_sigs=True)}, exclude=peer)
            else:
                self._score(peer.node_id or peer_id, 1)
            return

        if msg_type == "get_mempool":
            txs = [t.to_dict(include_sigs=True) for t in list(self.chain.mempool.values())[:MAX_TXS_PER_MSG]]
            await send_message(peer.writer, {"type": "mempool", "txs": txs})
            return

        if msg_type == "mempool":
            for data in msg.get("txs", [])[:MAX_TXS_PER_MSG]:
                tx = Transaction.from_dict(data)
                self.chain.add_tx(tx)
            return

        if msg_type == "get_snapshot":
            height = int(msg.get("height", -1))
            try:
                snapshot = self.chain.snapshot_dict()
                snapshot = self.chain.sign_snapshot(snapshot, self.identity_priv, self.identity_pub)
                raw = gzip.compress(json.dumps(snapshot).encode())
            except Exception:
                return
            if height >= 0 and snapshot.get("height", 0) > height:
                return
            if len(raw) > MAX_SNAPSHOT_BYTES:
                return
            payload = {"type": "snapshot", "data": base64.b64encode(raw).decode()}
            sig_payload = {"data": payload["data"]}
            payload["sig"] = sign_payload(sig_payload, self.identity_priv)
            await send_message(peer.writer, payload)
            return

        if msg_type == "snapshot":
            if not FASTSYNC:
                return
            data = msg.get("data")
            sig = msg.get("sig", "")
            if not data or not sig or not peer.pubkey:
                return
            if not verify_payload({"data": data}, sig, peer.pubkey):
                self._score(peer_id, BAN_THRESHOLD)
                return
            raw = base64.b64decode(data.encode())
            if len(raw) > MAX_SNAPSHOT_BYTES:
                return
            try:
                self.chain.apply_snapshot_blob(raw)
                await send_message(
                    peer.writer,
                    {"type": "get_headers", "start": self.chain.height + 1, "count": MAX_HEADERS},
                )
            except Exception:
                self._score(peer_id, 10)
            return

    async def _send_hello(self, peer: Peer) -> None:
        payload = {
            "type": "hello",
            "node_id": self.node_id,
            "pubkey": self.identity_pub,
            "best_tip": self.chain.best_tip,
            "best_height": self.chain.height,
            "best_work": self.chain.best_work,
            "ts": int(time.time()),
            "nonce": secrets.token_hex(16),
            "services": {
                "compact": COMPACT_BLOCKS,
                "snapshot": self.chain.snapshot_enabled,
                "tls": bool(self.tls_server_ctx),
            },
            "version": 1,
        }
        sig = sign_payload(payload, self.identity_priv)
        payload["sig"] = sig
        await send_message(peer.writer, payload)
        await send_message(peer.writer, {"type": "get_peers"})

    def _verify_hello(self, peer: Peer, peer_id: str, msg: dict) -> bool:
        sig = msg.get("sig")
        pub = msg.get("pubkey")
        ts = int(msg.get("ts", 0))
        nonce = msg.get("nonce")
        if not sig or not isinstance(pub, dict):
            return False
        if abs(int(time.time()) - ts) > HELLO_MAX_SKEW:
            return False
        if not nonce or not isinstance(nonce, str) or len(nonce) > 64:
            return False
        self._prune_nonces()
        if nonce in self.seen_nonces:
            return False
        self.seen_nonces[nonce] = time.time()
        payload = {k: v for k, v in msg.items() if k not in ("sig", "mac")}
        if not verify_payload(payload, sig, pub):
            return False
        node_id = msg.get("node_id", "")
        try:
            calc_id = crypto.address_from_pubkey(pub, "ecdsa")
        except Exception:
            return False
        if node_id != calc_id:
            return False
        fp = pubkey_fingerprint(pub)
        if TRUSTED_ONLY and node_id not in self.trusted_peers:
            return False
        if node_id in self.trusted_peers and self.trusted_peers[node_id] != fp:
            return False
        if node_id in self.peer_fingerprints and self.peer_fingerprints[node_id] != fp:
            return False
        self.peer_fingerprints[node_id] = fp
        peer.node_id = node_id
        peer.pubkey = pub
        peer.fingerprint = fp
        peer.best_tip = msg.get("best_tip", "")
        peer.best_height = int(msg.get("best_height", -1))
        peer.best_work = int(msg.get("best_work", 0))
        peer.services = msg.get("services", {}) or {}
        peer.authenticated = True
        peer.last_seen = time.time()
        return True

    async def _maybe_fast_sync(self, peer: Peer) -> None:
        if FASTSYNC and peer.services.get("snapshot"):
            await send_message(peer.writer, {"type": "get_snapshot", "height": peer.best_height})
        else:
            await send_message(
                peer.writer,
                {"type": "get_headers", "start": self.chain.height + 1, "count": MAX_HEADERS},
            )

    async def _request_block(self, peer: Peer, block_hash: str) -> None:
        if block_hash in self._requested_blocks:
            return
        self._requested_blocks[block_hash] = 1
        await send_message(peer.writer, {"type": "get_block", "hash": block_hash})

    async def _try_compact_block(self, block_hash: str) -> None:
        entry = self.compact_pending.get(block_hash)
        if not entry:
            return
        txs = []
        for txid in entry["txids"]:
            tx = self.chain.mempool.get(txid) or self.tx_cache.get(txid)
            if not tx:
                return
            txs.append(tx.to_dict(include_sigs=True))
        block = Block.from_dict({"header": entry["header"], "txs": txs})
        status, missing_parent = self.chain.add_block(block)
        if status == "orphan" and missing_parent:
            await self._request_block(entry["peer"], missing_parent)
            return
        if status == "accepted":
            await self._broadcast_block(block, exclude=entry["peer"])
        self.compact_pending.pop(block_hash, None)

    async def broadcast(self, msg: dict, exclude: Optional[Peer] = None) -> None:
        for peer in list(self.peers.values()):
            if exclude and peer is exclude:
                continue
            try:
                await send_message(peer.writer, msg)
            except Exception:
                pass

    async def _broadcast_block(self, block: Block, exclude: Optional[Peer] = None) -> None:
        if COMPACT_BLOCKS:
            msg = {
                "type": "block_inv",
                "header": block.header.to_dict(),
                "txids": [tx.txid for tx in block.txs],
            }
            await self.broadcast(msg, exclude=exclude)
        else:
            await self.broadcast({"type": "block", "block": block.to_dict()}, exclude=exclude)

    async def _mine_loop(self) -> None:
        if not self.miner_address:
            return
        while True:
            if self.chain.best_tip:
                block = self.chain.mine_block(self.miner_address, self.miner_priv, self.miner_algo)
                if block:
                    await self._broadcast_block(block)
            await asyncio.sleep(self.mine_interval)
