from scratchchain.wallet import Wallet


def test_min_gas_price(tmp_path, monkeypatch, load_chain_module):
    chain_mod = load_chain_module(monkeypatch, consensus="pow", difficulty="6")
    Chain = chain_mod.Chain
    data_dir = tmp_path / "fees"
    chain = Chain(str(data_dir))

    wallet = Wallet.create()
    chain.init_genesis(wallet.address)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    code = ["PUSH 1", "PUSH 2", "ADD", "STOP"]
    # base gas price defaults to 1, so 0 should be rejected
    tx = chain.build_contract_create_tx(wallet, code, {}, gas_limit=50, gas_price=0)
    assert tx is None
