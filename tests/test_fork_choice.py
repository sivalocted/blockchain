from scratchchain.block import Block
from scratchchain.tx import create_coinbase
from scratchchain.wallet import Wallet


def _mine_block(chain_mod, chain, parent_hash, height, miner_address):
    difficulty = chain._calc_next_difficulty(parent_hash)
    base_gas_price = chain._calc_next_base_gas_price(parent_hash)
    reward = chain.block_reward(height)
    coinbase = create_coinbase(miner_address, reward, "fork")
    block = Block.build(parent_hash, height, difficulty, [coinbase], base_gas_price=base_gas_price, gas_used=0)
    block.mine()
    return block


def test_fork_choice(tmp_path, monkeypatch, load_chain_module):
    chain_mod = load_chain_module(monkeypatch, consensus="pow", difficulty="6")
    Chain = chain_mod.Chain
    data_dir = tmp_path / "fork"
    chain = Chain(str(data_dir))

    wallet = Wallet.create()
    chain.init_genesis(wallet.address)

    # main chain height 2
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    chain.mine_block(wallet.address, wallet.priv, wallet.algo)
    main_tip = chain.best_tip
    main_height = chain.height
    assert main_height == 2

    # build fork from genesis with 3 blocks
    genesis_hash = chain._chain_hashes(chain.best_tip)[0]
    b1 = _mine_block(chain_mod, chain, genesis_hash, 1, wallet.address)
    status, _ = chain.add_block(b1)
    assert status == "accepted"
    b2 = _mine_block(chain_mod, chain, b1.hash, 2, wallet.address)
    status, _ = chain.add_block(b2)
    assert status == "accepted"
    b3 = _mine_block(chain_mod, chain, b2.hash, 3, wallet.address)
    status, _ = chain.add_block(b3)
    assert status == "accepted"

    assert chain.best_tip == b3.hash
    assert chain.height == 3
    assert chain.best_tip != main_tip
