import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .chain import Chain

CACHE_TTL = int(os.getenv("SCRATCHCHAIN_INDEXER_CACHE_TTL", "2"))
MAX_BLOCKS = int(os.getenv("SCRATCHCHAIN_INDEXER_MAX_BLOCKS", "200"))


def run_indexer(data_dir: str, host: str = "127.0.0.1", port: int = 9337) -> None:
    state = {"chain": Chain(data_dir), "tip": None}
    cache: Dict[str, tuple[float, Any]] = {}

    def current_chain() -> Chain:
        chain = state["chain"]
        try:
            best_tip = chain.db.get_meta("best_tip")
            if best_tip and best_tip != chain.best_tip:
                state["chain"] = Chain(data_dir)
                chain = state["chain"]
        except Exception:
            pass
        return chain

    def cache_get(key: str) -> Optional[Any]:
        if key not in cache:
            return None
        exp, value = cache[key]
        if exp < time.time():
            cache.pop(key, None)
            return None
        return value

    def cache_set(key: str, value: Any, ttl: int = CACHE_TTL) -> None:
        if ttl <= 0:
            return
        cache[key] = (time.time() + ttl, value)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            try:
                chain = current_chain()
                if path == "/status":
                    key = "status"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    result = chain.metrics()
                    result["best_tip"] = chain.best_tip
                    result["mempool_size"] = len(chain.mempool)
                    payload = {"ok": True, "result": result}
                    cache_set(key, payload, ttl=1)
                    self._send(200, payload)
                    return
                if path == "/blocks":
                    count = min(int((qs.get("count") or ["20"])[0]), MAX_BLOCKS)
                    direction = (qs.get("direction") or ["desc"])[0]
                    if "start" in qs:
                        start = int(qs["start"][0])
                    else:
                        start = chain.height if direction == "desc" else 0
                    key = f"blocks:{start}:{count}:{direction}:{chain.best_tip}"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    blocks = []
                    if direction == "desc":
                        heights = range(start, max(-1, start - count), -1)
                    else:
                        heights = range(start, start + count)
                    for h in heights:
                        block = chain.get_block_by_height(h)
                        if not block:
                            continue
                        blocks.append(_block_summary(block))
                    payload = {"ok": True, "result": blocks}
                    cache_set(key, payload)
                    self._send(200, payload)
                    return
                if path == "/search":
                    query = (qs.get("q") or [""])[0].strip()
                    if not query:
                        self._send(400, {"ok": False, "error": "missing query"})
                        return
                    key = f"search:{query}:{chain.best_tip}"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    result = _search(chain, query)
                    payload = {"ok": True, "result": result}
                    cache_set(key, payload)
                    self._send(200, payload)
                    return
                if path.startswith("/tx/"):
                    txid = path.split("/tx/")[1]
                    key = f"tx:{txid}:{chain.best_tip}"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    tx = chain.get_tx(txid)
                    receipt = chain.get_receipt(txid)
                    if not tx:
                        self._send(404, {"ok": False, "error": "tx not found"})
                        return
                    payload = {"ok": True, "result": {"tx": tx, "receipt": receipt}}
                    cache_set(key, payload)
                    self._send(200, payload)
                    return
                if path.startswith("/block/"):
                    block_hash = path.split("/block/")[1]
                    key = f"block:{block_hash}"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    block = chain.get_block(block_hash)
                    if not block:
                        self._send(404, {"ok": False, "error": "block not found"})
                        return
                    payload = {"ok": True, "result": block.to_dict()}
                    cache_set(key, payload)
                    self._send(200, payload)
                    return
                if path.startswith("/address/"):
                    address = path.split("/address/")[1]
                    limit = int((qs.get("limit") or ["50"])[0])
                    offset = int((qs.get("offset") or ["0"])[0])
                    direction = (qs.get("direction") or [None])[0]
                    key = f"addr:{address}:{limit}:{offset}:{direction}:{chain.best_tip}"
                    cached = cache_get(key)
                    if cached:
                        self._send(200, cached)
                        return
                    history = chain.get_history(address, limit=limit, offset=offset, direction=direction)
                    payload = {"ok": True, "result": history}
                    cache_set(key, payload)
                    self._send(200, payload)
                    return
                self._send(404, {"ok": False, "error": "not_found"})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Indexer listening on http://{host}:{port}")
    server.serve_forever()


def _block_summary(block) -> dict:
    return {
        "hash": block.hash,
        "height": block.header.height,
        "prev_hash": block.header.prev_hash,
        "timestamp": block.header.timestamp,
        "txs": len(block.txs),
        "gas_used": block.header.gas_used,
        "merkle_root": block.header.merkle_root,
    }


def _search(chain: Chain, query: str) -> dict:
    if query.isdigit():
        block = chain.get_block_by_height(int(query))
        if block:
            return {"type": "block", "data": block.to_dict()}
    if len(query) >= 40:
        tx = chain.get_tx(query)
        if tx:
            return {"type": "tx", "data": tx}
        block = chain.get_block(query)
        if block:
            return {"type": "block", "data": block.to_dict()}
    history = chain.get_history(query, limit=20)
    return {"type": "address", "data": history}
