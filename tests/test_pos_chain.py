from scratchchain.wallet import Wallet


def test_pos_flow(tmp_path, monkeypatch, load_chain_module):
    chain_mod = load_chain_module(monkeypatch, consensus="pos", difficulty="1")
    Chain = chain_mod.Chain

    data_dir = tmp_path / "pos"
    chain = Chain(str(data_dir))

    wallet = Wallet.create()
    chain.init_genesis(wallet.address)

    stake_tx = chain.build_stake_tx(wallet, 1000000000)
    assert stake_tx is not None
    assert chain.add_tx(stake_tx)
    block1 = chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    assert block1 is not None
    assert chain.get_stake(wallet.address) == 1000000000

    block2 = chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    assert block2 is not None
    assert block2.header.validator == wallet.address
    assert block2.header.signature
