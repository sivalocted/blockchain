from scratchchain import crypto
from scratchchain.utils import sha256


def test_ecdsa_sign_verify():
    priv = crypto.ecdsa_generate_keypair()
    msg = sha256(b"hello")
    sig = crypto.ecdsa_sign(msg, priv)
    pub = crypto.ecdsa_public_key(priv)
    assert crypto.ecdsa_verify(msg, sig, pub)
    assert not crypto.ecdsa_verify(msg, "00:00", pub)
