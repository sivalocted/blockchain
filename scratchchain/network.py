import asyncio
import json
import os
import time
import hmac
import hashlib
from typing import Any, Dict, Optional

MAX_MSG_SIZE = 2_000_000
P2P_SECRET = os.getenv("SCRATCHCHAIN_P2P_SECRET")
MAX_SKEW = int(os.getenv("SCRATCHCHAIN_P2P_SKEW", "60"))


def _canonical(msg: Dict[str, Any]) -> str:
    return json.dumps(msg, separators=(",", ":"), sort_keys=True)


def _sign_payload(payload: str) -> str:
    if not P2P_SECRET:
        return ""
    mac = hmac.new(P2P_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return mac


def encode_message(msg: Dict[str, Any]) -> bytes:
    if P2P_SECRET:
        if "ts" not in msg:
            msg["ts"] = int(time.time())
        unsigned = {k: v for k, v in msg.items() if k != "mac"}
        mac = _sign_payload(_canonical(unsigned))
        msg["mac"] = mac
    data = _canonical(msg)
    return (data + "\n").encode()


async def send_message(writer: asyncio.StreamWriter, msg: Dict[str, Any]) -> None:
    writer.write(encode_message(msg))
    await writer.drain()


async def read_message(reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
    line = await reader.readline()
    if not line:
        return None
    if len(line) > MAX_MSG_SIZE:
        raise ValueError("Message too large")
    msg = json.loads(line.decode())
    if P2P_SECRET:
        mac = msg.get("mac", "")
        ts = int(msg.get("ts", 0))
        if abs(int(time.time()) - ts) > MAX_SKEW:
            raise ValueError("Message timestamp out of range")
        unsigned = {k: v for k, v in msg.items() if k != "mac"}
        expected = _sign_payload(_canonical(unsigned))
        if not hmac.compare_digest(mac, expected):
            raise ValueError("Bad message mac")
    return msg
