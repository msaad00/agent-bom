"""Keep malformed JWT payloads inside PyJWT's documented error contract."""

import base64

import jwt
import pytest


@pytest.mark.parametrize("entrypoint", ["decode", "jwks"])
def test_nested_payload_raises_token_error_before_key_lookup(entrypoint, monkeypatch):
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"untrusted"}').rstrip(b"=")
    depth = 20_000  # Exceeds the JSON decoder's recursion budget on supported Pythons.
    payload = base64.urlsafe_b64encode(b"[" * depth + b"]" * depth).rstrip(b"=")
    token = b".".join([header, payload, b"c2ln"]).decode()
    client = jwt.PyJWKClient("https://issuer.invalid/jwks")

    def unexpected_key_lookup(*args, **kwargs):
        pytest.fail("Malformed payload must be rejected before key lookup")

    monkeypatch.setattr(client, "get_signing_key", unexpected_key_lookup)
    with pytest.raises(jwt.InvalidTokenError):
        if entrypoint == "decode":
            jwt.decode(token, options={"verify_signature": False})
        else:
            client.get_signing_key_from_jwt(token)
