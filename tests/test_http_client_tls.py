"""Custom trust and client credentials reach every async transport, fail closed."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent_bom.http_client import create_client


@pytest.fixture
def tls_material(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = tmp_path / "key.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca, private, cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy", [False, True])
async def test_custom_ca_and_client_cert_reach_direct_and_proxy_transports(monkeypatch, tls_material, proxy):
    ca, key, der = tls_material
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    if proxy:
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:19876")
    loaded = []
    original = ssl.SSLContext.load_cert_chain

    def load_cert_chain(context, certfile, keyfile=None, password=None):
        loaded.append(context)
        return original(context, certfile, keyfile, password)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load_cert_chain)
    async with create_client(verify=str(ca), cert=(str(ca), str(key))) as client:
        transports = [client._transport, *(transport for transport in client._mounts.values() if transport is not None)]
        assert len(transports) == (2 if proxy else 1)
        for transport in transports:
            context = transport._pool._ssl_context
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname is True
            assert context.get_ca_certs(binary_form=True) == [der]
            assert context in loaded


@pytest.mark.parametrize("verify", [False, "", None, 0])
def test_invalid_tls_verification_fails_before_client_creation(verify):
    with pytest.raises(ValueError, match="certificate verification"):
        create_client(verify=verify)
