from scratchchain.wallet import Wallet


def test_history(tmp_path, monkeypatch, load_chain_module):
    chain_mod = load_chain_module(monkeypatch, consensus="pow", difficulty="6")
    Chain = chain_mod.Chain
    data_dir = tmp_path / "hist"
    chain = Chain(str(data_dir))

    wallet = Wallet.create()
    chain.init_genesis(wallet.address)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    wallet2 = Wallet.create()
    tx = chain.build_transfer_tx(wallet, wallet2.address, 100000000)
    assert chain.add_tx(tx)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)

    history = chain.get_history(wallet2.address, 10)
    assert any(h["direction"] == "in" for h in history)
