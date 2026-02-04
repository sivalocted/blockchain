import importlib

import pytest


@pytest.fixture
def load_chain_module():
    def _loader(monkeypatch, consensus="pow", difficulty="6"):
        monkeypatch.setenv("SCRATCHCHAIN_CONSENSUS", consensus)
        monkeypatch.setenv("SCRATCHCHAIN_INITIAL_DIFFICULTY", difficulty)
        import scratchchain.chain as chain
        return importlib.reload(chain)

    return _loader
