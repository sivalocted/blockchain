#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Allow running as "python3 scratchchain/demo.py" or "python3 -m scratchchain.demo"
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scratchchain.block import header_hash_from_dict
from scratchchain.tx import Transaction


BASE = Path(os.getcwd()) / "scratchchain_demo"


def run(cmd, env=None, capture=False) -> str:
    print("+", " ".join(cmd))
    if capture:
        return subprocess.check_output(cmd, env=env).decode().strip()
    subprocess.run(cmd, check=True, env=env)
    return ""


def pow_demo() -> None:
    data_dir = BASE / "pow"
    data_dir.mkdir(parents=True, exist_ok=True)
    wallet = data_dir / "wallet.json"
    wallet2 = data_dir / "wallet2.json"

    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "init"])
    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)])

    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "create-wallet", "--wallet", str(wallet2)])
    addr = run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "address", "--wallet", str(wallet2)], capture=True)

    run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "send",
        "--wallet", str(wallet), "--to", addr, "--amount", "1.5"
    ])
    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)])
    bal = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "balance",
        "--address", addr
    ], capture=True)
    print("Recipient balance:", bal)

    code = '["PUSH 5","PUSH 7","ADD","STORE total","LOAD total","STOP"]'
    out = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "contract-create",
        "--wallet", str(wallet), "--code", code, "--gas-limit", "200", "--gas-price", "1"
    ], capture=True)
    contract_id = ""
    for line in out.splitlines():
        if line.startswith("TXID:"):
            contract_id = line.split("TXID:")[1].strip()
            break
    if not contract_id:
        raise RuntimeError("Failed to parse contract id")

    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)])

    run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "contract-call",
        "--wallet", str(wallet), "--contract", contract_id, "--calldata", "[1,2]",
        "--gas-limit", "200", "--gas-price", "1"
    ])
    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)])

    chain_json = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "print-chain"
    ], capture=True)
    chain = json.loads(chain_json)
    last_block = chain[-1]
    block_hash = header_hash_from_dict(last_block["header"])
    last_tx = Transaction.from_dict(last_block["txs"][-1])
    proof_out = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "tx-proof",
        "--block", block_hash, "--txid", last_tx.txid
    ], capture=True)
    proof_obj = json.loads(proof_out)
    proof_arg = json.dumps(proof_obj)
    verify = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "verify-proof",
        "--proof", proof_arg
    ], capture=True)
    print("Merkle proof verification:", verify)


def pos_demo() -> None:
    data_dir = BASE / "pos"
    data_dir.mkdir(parents=True, exist_ok=True)
    wallet = data_dir / "wallet.json"
    env = os.environ.copy()
    env["SCRATCHCHAIN_CONSENSUS"] = "pos"

    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "init"], env=env)
    run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "stake",
        "--wallet", str(wallet), "--amount", "10"
    ], env=env)
    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)], env=env)
    run(["python3", "-m", "scratchchain", "--data-dir", str(data_dir), "mine", "--wallet", str(wallet)], env=env)
    stake_bal = run([
        "python3", "-m", "scratchchain", "--data-dir", str(data_dir), "stake-balance",
        "--wallet", str(wallet)
    ], env=env, capture=True)
    print("PoS stake balance:", stake_bal)


def main() -> None:
    if BASE.exists():
        shutil.rmtree(BASE)
    BASE.mkdir(parents=True, exist_ok=True)
    print("Running PoW demo...")
    pow_demo()
    print("Running PoS demo...")
    pos_demo()
    print("Demo complete. Data stored in", BASE)


if __name__ == "__main__":
    main()
