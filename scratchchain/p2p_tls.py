import os
import ssl
from datetime import datetime, timedelta
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _default_paths(data_dir: str) -> tuple[str, str]:
    return (
        os.path.join(data_dir, "p2p_cert.pem"),
        os.path.join(data_dir, "p2p_key.pem"),
    )


def ensure_self_signed_cert(cert_path: str, key_path: str, common_name: str) -> None:
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def build_ssl_context(data_dir: str, is_server: bool) -> Optional[ssl.SSLContext]:
    if os.getenv("SCRATCHCHAIN_P2P_TLS", "0") != "1":
        return None

    cert_path = os.getenv("SCRATCHCHAIN_P2P_CERT")
    key_path = os.getenv("SCRATCHCHAIN_P2P_KEY")
    if not cert_path or not key_path:
        cert_path, key_path = _default_paths(data_dir)
    ensure_self_signed_cert(cert_path, key_path, "scratchchain")

    if is_server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return ctx

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    verify = os.getenv("SCRATCHCHAIN_P2P_TLS_VERIFY", "0") == "1"
    if verify:
        ca_path = os.getenv("SCRATCHCHAIN_P2P_CA")
        if ca_path:
            ctx.load_verify_locations(cafile=ca_path)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx
