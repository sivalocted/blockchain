#!/usr/bin/env python3
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

RPC_URL = os.getenv("SCRATCHCHAIN_RPC", "http://127.0.0.1:9334/rpc")
RPC_TOKEN = os.getenv("SCRATCHCHAIN_RPC_TOKEN")
FAUCET_WALLET = os.getenv("SCRATCHCHAIN_FAUCET_WALLET")
FAUCET_AMOUNT = os.getenv("SCRATCHCHAIN_FAUCET_AMOUNT", "1")
HOST = os.getenv("SCRATCHCHAIN_FAUCET_HOST", "0.0.0.0")
PORT = int(os.getenv("SCRATCHCHAIN_FAUCET_PORT", "9494"))
RATE_LIMIT_SECONDS = int(os.getenv("SCRATCHCHAIN_FAUCET_RATE", "60"))

last_request = {}


def rpc_call(method, params=None):
    payload = json.dumps({"method": method, "params": params or {}}).encode()
    headers = {"Content-Type": "application/json"}
    if RPC_TOKEN:
        headers["X-Auth-Token"] = RPC_TOKEN
    req = Request(RPC_URL, data=payload, headers=headers)
    with urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "rpc error"))
    return data.get("result")


def rate_limited(ip):
    now = time.time()
    last = last_request.get(ip, 0)
    if now - last < RATE_LIMIT_SECONDS:
        return True
    last_request[ip] = now
    return False


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/faucet":
            self._send(404, {"ok": False, "error": "not_found"})
            return
        if not FAUCET_WALLET:
            self._send(500, {"ok": False, "error": "FAUCET_WALLET not configured"})
            return
        ip = self.client_address[0]
        if rate_limited(ip):
            self._send(429, {"ok": False, "error": "rate_limited"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode())
        except Exception:
            self._send(400, {"ok": False, "error": "invalid_json"})
            return
        address = data.get("address")
        if not address:
            self._send(400, {"ok": False, "error": "address required"})
            return
        try:
            res = rpc_call(
                "send",
                {"wallet": FAUCET_WALLET, "to": address, "amount": FAUCET_AMOUNT},
            )
            self._send(200, {"ok": True, "txid": res.get("txid")})
        except Exception as exc:
            self._send(500, {"ok": False, "error": str(exc)})

    def log_message(self, format, *args):
        return


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Faucet listening on http://{HOST}:{PORT}/faucet")
    server.serve_forever()


if __name__ == "__main__":
    main()
