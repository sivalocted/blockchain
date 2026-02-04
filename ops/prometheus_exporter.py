#!/usr/bin/env python3
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

RPC_URL = os.getenv("SCRATCHCHAIN_RPC", "http://127.0.0.1:9334/rpc")
HOST = os.getenv("SCRATCHCHAIN_EXPORTER_HOST", "127.0.0.1")
PORT = int(os.getenv("SCRATCHCHAIN_EXPORTER_PORT", "9108"))


def rpc_call(method, params=None):
    payload = json.dumps({"method": method, "params": params or {}}).encode()
    req = Request(RPC_URL, data=payload, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "rpc error"))
    return data.get("result")


def format_metrics(result, up):
    lines = []
    lines.append(f"scratchchain_rpc_up {1 if up else 0}")
    if not up or not result:
        return "\n".join(lines) + "\n"

    def add(name, value):
        try:
            num = float(value)
        except Exception:
            return
        lines.append(f"{name} {num}")

    add("scratchchain_height", result.get("height"))
    add("scratchchain_mempool_size", result.get("mempool_size"))
    add("scratchchain_difficulty", result.get("difficulty"))
    add("scratchchain_best_work", result.get("best_work"))
    add("scratchchain_mempool_bytes", result.get("mempool_bytes"))
    add("scratchchain_utxo_set", result.get("utxo_set"))
    add("scratchchain_contracts", result.get("contracts"))
    add("scratchchain_validators", result.get("validators"))
    add("scratchchain_avg_block_time", result.get("avg_block_time"))
    add("scratchchain_blocks_known", result.get("blocks_known"))
    add("scratchchain_forks", result.get("forks"))

    peers = result.get("peers") or []
    known_peers = result.get("known_peers") or []
    banscore = result.get("banscore") or {}
    add("scratchchain_peers", len(peers))
    add("scratchchain_known_peers", len(known_peers))
    add("scratchchain_banscore_entries", len(banscore))

    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path not in ("/metrics", "/health"):
            self._send(404, "not_found")
            return
        if self.path == "/health":
            self._send(200, "ok")
            return
        try:
            result = rpc_call("get_metrics")
            body = format_metrics(result, True)
            self._send(200, body)
        except Exception:
            body = format_metrics(None, False)
            self._send(200, body)

    def log_message(self, format, *args):
        return


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Exporter listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
