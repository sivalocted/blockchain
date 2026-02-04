import argparse
import asyncio
import json
import os
from decimal import Decimal, InvalidOperation
from typing import List

from .chain import Chain, COIN
from .identity import load_or_create_node_key
from .node import Node
from .wallet import Wallet


DEFAULT_DATA_DIR = os.path.join(os.getcwd(), "scratchchain_data")


def parse_amount(text: str) -> int:
    try:
        val = Decimal(text)
    except InvalidOperation as exc:
        raise SystemExit(f"Invalid amount: {text}") from exc
    if val <= 0:
        raise SystemExit("Amount must be > 0")
    return int(val * COIN)


def format_amount(amount: int) -> str:
    return f"{Decimal(amount) / COIN:.8f}"


def _load_json(value: str):
    if os.path.exists(value):
        with open(value, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(value)


def _load_json_list(value: str) -> List:
    data = _load_json(value)
    if not isinstance(data, list):
        raise SystemExit("Expected JSON list")
    return data


def _load_code_list(value: str) -> List:
    from .contract import compile_source
    if os.path.exists(value):
        with open(value, "r", encoding="utf-8") as f:
            raw = f.read()
        try:
            data = json.loads(raw)
            if not isinstance(data, list):
                raise SystemExit("Expected JSON list for code")
            return data
        except Exception:
            return compile_source(raw)
    try:
        data = json.loads(value)
        if not isinstance(data, list):
            raise SystemExit("Expected JSON list for code")
        return data
    except Exception:
        return compile_source(value)


def _load_json_dict(value: str):
    data = _load_json(value)
    if not isinstance(data, dict):
        raise SystemExit("Expected JSON object")
    return data


def cmd_init(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet_path = args.wallet or os.path.join(args.data_dir, "wallet.json")
    if os.path.exists(wallet_path):
        wallet = Wallet.load(wallet_path)
    else:
        wallet = Wallet.create(algo=args.algo)
        wallet.save(wallet_path)
    block = chain.init_genesis(wallet.address)
    print("Genesis created")
    print("Address:", wallet.address)
    print("Algo:", wallet.algo)
    print("Block hash:", block.hash)


def cmd_create_wallet(args: argparse.Namespace) -> None:
    wallet = Wallet.create(algo=args.algo)
    path = args.wallet
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    wallet.save(path)
    print("Wallet created")
    print("Address:", wallet.address)
    print("Algo:", wallet.algo)


def cmd_address(args: argparse.Namespace) -> None:
    wallet = Wallet.load(args.wallet)
    print(wallet.address)


def cmd_balance(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    address = args.address
    if not address:
        if not args.wallet:
            raise SystemExit("Provide --address or --wallet")
        wallet = Wallet.load(args.wallet)
        address = wallet.address
    balance = chain.get_balance(address)
    print(format_amount(balance))


def cmd_stake_balance(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    address = args.address
    if not address:
        if not args.wallet:
            raise SystemExit("Provide --address or --wallet")
        wallet = Wallet.load(args.wallet)
        address = wallet.address
    stake = chain.get_stake(address)
    print(format_amount(stake))


def cmd_send(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    amount = parse_amount(args.amount)
    tx = chain.build_transfer_tx(wallet, args.to, amount)
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Transaction added to mempool")
    print("TXID:", tx.txid)


def cmd_stake(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    amount = parse_amount(args.amount)
    tx = chain.build_stake_tx(wallet, amount)
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Stake tx added")
    print("TXID:", tx.txid)


def cmd_unstake(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    amount = parse_amount(args.amount)
    tx = chain.build_unstake_tx(wallet, amount)
    if not tx:
        raise SystemExit("Insufficient staked funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Unstake tx added")
    print("TXID:", tx.txid)


def cmd_slash(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    header_a = _load_json_dict(args.header_a)
    header_b = _load_json_dict(args.header_b)
    reward_to = args.reward_to
    if not reward_to and args.wallet:
        reward_to = Wallet.load(args.wallet).address
    tx = chain.build_slash_tx(header_a, header_b, reward_to=reward_to)
    if not tx:
        raise SystemExit("Invalid slashing evidence")
    if not chain.add_tx(tx):
        raise SystemExit("Slash tx rejected")
    print("Slash tx added")
    print("TXID:", tx.txid)



def cmd_contract_create(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    code = _load_code_list(args.code)
    storage = _load_json_dict(args.storage) if args.storage else {}
    tx = chain.build_contract_create_tx(wallet, code, storage, args.gas_limit, args.gas_price)
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Contract create tx added")
    print("TXID:", tx.txid)


def cmd_contract_call(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    calldata = _load_json_list(args.calldata) if args.calldata else []
    tx = chain.build_contract_call_tx(wallet, args.contract, calldata, args.gas_limit, args.gas_price)
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Contract call tx added")
    print("TXID:", tx.txid)


def cmd_contract_get(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    contract = chain.contracts.get(args.contract)
    if not contract:
        raise SystemExit("Contract not found")
    print(json.dumps({
        "id": contract.contract_id,
        "creator": contract.creator,
        "code": contract.code,
        "storage": contract.storage,
    }, indent=2))


def cmd_validator_register(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    tx = chain.build_validator_register_tx(
        wallet,
        name=args.name or "",
        website=args.website or "",
        commission=args.commission,
        fee=args.fee,
    )
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Validator register tx added")
    print("TXID:", tx.txid)


def cmd_validator_update(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    tx = chain.build_validator_update_tx(
        wallet,
        name=args.name or "",
        website=args.website or "",
        commission=args.commission,
        fee=args.fee,
    )
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Validator update tx added")
    print("TXID:", tx.txid)


def cmd_gov_update(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    params = _load_json_dict(args.params)
    tx = chain.build_gov_update_tx(wallet, params, fee=args.fee)
    if not tx:
        raise SystemExit("Insufficient funds")
    if not chain.add_tx(tx):
        raise SystemExit("Transaction rejected")
    print("Governance update tx added")
    print("TXID:", tx.txid)


def cmd_snapshot_create(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    if not chain.best_tip:
        raise SystemExit("Chain not initialized")
    path = args.path or chain._snapshot_path(chain.height, chain.best_tip)
    snapshot = chain.snapshot_dict()
    if not args.unsigned:
        priv, pub, _node_id = load_or_create_node_key(chain.data_dir)
        snapshot = chain.sign_snapshot(snapshot, priv, pub)
    chain.save_snapshot(path, snapshot)
    print("Snapshot saved:", path)


def cmd_snapshot_load(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    snap = chain.load_snapshot(args.path)
    chain.apply_snapshot(snap)
    print("Snapshot loaded")


def cmd_metrics(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    print(json.dumps(chain.metrics(), indent=2))


def cmd_indexer(args: argparse.Namespace) -> None:
    from .indexer import run_indexer
    run_indexer(args.data_dir, host=args.host, port=args.port)



def cmd_get_tx(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    data = chain.get_tx(args.txid)
    if not data:
        raise SystemExit("TX not found")
    print(json.dumps(data, indent=2))


def cmd_receipt(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    data = chain.get_receipt(args.txid)
    if not data:
        raise SystemExit("Receipt not found")
    print(json.dumps(data, indent=2))


def cmd_history(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    address = args.address
    if not address:
        if not args.wallet:
            raise SystemExit("Provide --address or --wallet")
        wallet = Wallet.load(args.wallet)
        address = wallet.address
    data = chain.get_history(address, args.limit, args.offset, args.direction)
    print(json.dumps(data, indent=2))


def cmd_get_block(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    block = chain.get_block(args.block)
    if not block:
        raise SystemExit("Block not found")
    print(json.dumps(block.to_dict(), indent=2))



def cmd_mine(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    wallet = Wallet.load(args.wallet)
    block = chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    if not block:
        raise SystemExit("Mining failed (chain not initialized?)")
    print("Block mined")
    print("Height:", block.header.height)
    print("Hash:", block.hash)


def cmd_print_chain(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    data = chain.dump_chain()
    print(json.dumps(data, indent=2))


def cmd_tx_proof(args: argparse.Namespace) -> None:
    chain = Chain(args.data_dir)
    block = chain.get_block(args.block)
    if not block:
        raise SystemExit("Block not found")
    txids = [t.txid for t in block.txs]
    if args.txid not in txids:
        raise SystemExit("TXID not in block")
    idx = txids.index(args.txid)
    from .merkle import merkle_proof
    proof = merkle_proof(txids, idx)
    print(json.dumps({"root": block.header.merkle_root, "index": idx, "txid": args.txid, "proof": proof}, indent=2))


def cmd_verify_proof(args: argparse.Namespace) -> None:
    data = _load_json_dict(args.proof)
    leaf = data.get("txid") or data.get("leaf") or args.txid
    root = data.get("root")
    proof = data.get("proof")
    if not leaf:
        raise SystemExit("TXID/leaf required in proof or --txid")
    from .merkle import verify_merkle_proof
    ok = verify_merkle_proof(leaf, proof, root)
    print("valid" if ok else "invalid")


def cmd_node(args: argparse.Namespace) -> None:
    peers = []
    for p in args.peer:
        host, port = p.split(":")
        peers.append((host, int(port)))
    node = Node(
        data_dir=args.data_dir,
        host=args.host,
        port=args.port,
        peers=peers,
        rpc_host=args.rpc_host,
        rpc_port=args.rpc_port,
        miner_wallet=args.miner_wallet,
        enable_mining=args.mine,
        mine_interval=args.mine_interval,
    )
    asyncio.run(node.start())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scratchchain")
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create genesis block")
    s.add_argument("--wallet")
    s.add_argument("--algo", default="ecdsa", choices=["ecdsa"])
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("create-wallet")
    s.add_argument("--wallet", required=True)
    s.add_argument("--algo", default="ecdsa", choices=["ecdsa"])
    s.set_defaults(func=cmd_create_wallet)

    s = sub.add_parser("address")
    s.add_argument("--wallet", required=True)
    s.set_defaults(func=cmd_address)

    s = sub.add_parser("balance")
    s.add_argument("--wallet")
    s.add_argument("--address")
    s.set_defaults(func=cmd_balance)

    s = sub.add_parser("stake-balance")
    s.add_argument("--wallet")
    s.add_argument("--address")
    s.set_defaults(func=cmd_stake_balance)

    s = sub.add_parser("send")
    s.add_argument("--wallet", required=True)
    s.add_argument("--to", required=True)
    s.add_argument("--amount", required=True)
    s.set_defaults(func=cmd_send)

    s = sub.add_parser("stake")
    s.add_argument("--wallet", required=True)
    s.add_argument("--amount", required=True)
    s.set_defaults(func=cmd_stake)

    s = sub.add_parser("unstake")
    s.add_argument("--wallet", required=True)
    s.add_argument("--amount", required=True)
    s.set_defaults(func=cmd_unstake)

    s = sub.add_parser("contract-create")
    s.add_argument("--wallet", required=True)
    s.add_argument("--code", required=True, help="JSON list or file path")
    s.add_argument("--storage", help="JSON object or file path")
    s.add_argument("--gas-limit", type=int, required=True)
    s.add_argument("--gas-price", type=int, required=True)
    s.set_defaults(func=cmd_contract_create)

    s = sub.add_parser("contract-call")
    s.add_argument("--wallet", required=True)
    s.add_argument("--contract", required=True)
    s.add_argument("--calldata", help="JSON list or file path")
    s.add_argument("--gas-limit", type=int, required=True)
    s.add_argument("--gas-price", type=int, required=True)
    s.set_defaults(func=cmd_contract_call)

    s = sub.add_parser("contract-get")
    s.add_argument("--contract", required=True)
    s.set_defaults(func=cmd_contract_get)

    s = sub.add_parser("validator-register")
    s.add_argument("--wallet", required=True)
    s.add_argument("--name")
    s.add_argument("--website")
    s.add_argument("--commission")
    s.add_argument("--fee", type=int)
    s.set_defaults(func=cmd_validator_register)

    s = sub.add_parser("validator-update")
    s.add_argument("--wallet", required=True)
    s.add_argument("--name")
    s.add_argument("--website")
    s.add_argument("--commission")
    s.add_argument("--fee", type=int)
    s.set_defaults(func=cmd_validator_update)

    s = sub.add_parser("gov-update")
    s.add_argument("--wallet", required=True)
    s.add_argument("--params", required=True, help="JSON object or file path")
    s.add_argument("--fee", type=int)
    s.set_defaults(func=cmd_gov_update)

    s = sub.add_parser("snapshot-create")
    s.add_argument("--path")
    s.add_argument("--unsigned", action="store_true", help="create snapshot without signature")
    s.set_defaults(func=cmd_snapshot_create)

    s = sub.add_parser("snapshot-load")
    s.add_argument("--path", required=True)
    s.set_defaults(func=cmd_snapshot_load)

    s = sub.add_parser("metrics")
    s.set_defaults(func=cmd_metrics)

    s = sub.add_parser("indexer")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9337)
    s.set_defaults(func=cmd_indexer)


    s = sub.add_parser("mine")
    s.add_argument("--wallet", required=True)
    s.set_defaults(func=cmd_mine)

    s = sub.add_parser("get-block")
    s.add_argument("--block", required=True)
    s.set_defaults(func=cmd_get_block)

    s = sub.add_parser("get-tx")
    s.add_argument("--txid", required=True)
    s.set_defaults(func=cmd_get_tx)

    s = sub.add_parser("receipt")
    s.add_argument("--txid", required=True)
    s.set_defaults(func=cmd_receipt)

    s = sub.add_parser("history")
    s.add_argument("--wallet")
    s.add_argument("--address")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--direction", choices=["in", "out"])
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("print-chain")
    s.set_defaults(func=cmd_print_chain)

    s = sub.add_parser("tx-proof")
    s.add_argument("--block", required=True)
    s.add_argument("--txid", required=True)
    s.set_defaults(func=cmd_tx_proof)

    s = sub.add_parser("verify-proof")
    s.add_argument("--proof", required=True, help="JSON proof object or file path")
    s.add_argument("--txid")
    s.set_defaults(func=cmd_verify_proof)

    s = sub.add_parser("node", help="run p2p node + RPC")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=9333)
    s.add_argument("--rpc-host", default="127.0.0.1")
    s.add_argument("--rpc-port", type=int, default=9334)
    s.add_argument("--peer", action="append", default=[])
    s.add_argument("--mine", action="store_true")
    s.add_argument("--miner-wallet")
    s.add_argument("--mine-interval", type=int, default=10)
    s.set_defaults(func=cmd_node)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
