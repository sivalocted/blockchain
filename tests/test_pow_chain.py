import json

from scratchchain.block import header_hash_from_dict
from scratchchain.merkle import verify_merkle_proof
from scratchchain.tx import Transaction
from scratchchain.wallet import Wallet


def test_pow_flow(tmp_path, monkeypatch, load_chain_module):
    chain_mod = load_chain_module(monkeypatch, consensus="pow", difficulty="6")
    Chain = chain_mod.Chain

    data_dir = tmp_path / "pow"
    chain = Chain(str(data_dir))

    wallet = Wallet.create()
    wallet.save(str(data_dir / "wallet.json"))
    chain.init_genesis(wallet.address)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    wallet2 = Wallet.create()
    addr2 = wallet2.address

    tx = chain.build_transfer_tx(wallet, addr2, 150000000)
    assert tx is not None
    assert chain.add_tx(tx)
    block = chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    assert block is not None
    assert chain.get_balance(addr2) == 150000000

    # contract create + call
    code = ["PUSH 5", "PUSH 7", "ADD", "STORE total", "LOAD total", "STOP"]
    c_tx = chain.build_contract_create_tx(wallet, code, {}, gas_limit=200, gas_price=1)
    assert c_tx is not None
    assert chain.add_tx(c_tx)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    contract_id = c_tx.txid
    call_tx = chain.build_contract_call_tx(wallet, contract_id, [1, 2], gas_limit=200, gas_price=1)
    assert call_tx is not None
    assert chain.add_tx(call_tx)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    contract = chain.contracts.get(contract_id)
    assert contract is not None
    assert contract.storage.get("total") == 12

    # merkle proof verification
    chain_data = chain.dump_chain()
    last_block = chain_data[-1]
    block_hash = header_hash_from_dict(last_block["header"])
    txids = [Transaction.from_dict(t).txid for t in last_block["txs"]]
    assert call_tx.txid in txids
    idx = txids.index(call_tx.txid)

    from scratchchain.merkle import merkle_proof
    proof = merkle_proof(txids, idx)
    root = last_block["header"]["merkle_root"]
    assert verify_merkle_proof(call_tx.txid, proof, root)
