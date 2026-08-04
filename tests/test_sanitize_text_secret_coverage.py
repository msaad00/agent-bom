"""Redacting the identifier while printing the secret is worse than redacting neither.

`sanitize_text` is the log and error path. It matched only the pattern list, which
carries AWS access key *ids* (`AKIA…`) but nothing for the 40-char secret access
key — so `id=AKIA… secret=wJalr…` came out with the harmless half masked and the
dangerous half verbatim. That reads as "credentials are handled" while leaking the
credential.

The fix redacts a value whose *key* names a credential, reusing
`env_key_is_credential`. It deliberately does NOT import the entropy fallback that
`sanitize_env_vars` applies to bare values: that heuristic is sound for env vars,
where a high-entropy value is almost certainly a secret, and unsound for free text,
which is full of high-entropy tokens that are not — content hashes, ARNs, digests,
request ids. An earlier draft did apply it and redacted a `hash_ref` and a
GuardDuty ARN out of the runtime taxonomy. A redactor that eats legitimate labels
is one people switch off, so precision is load-bearing here.
"""

from __future__ import annotations

import pytest

from agent_bom.security import sanitize_text

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

CREDENTIAL_KEYS = ["secret", "AWS_SECRET_ACCESS_KEY", "api_token", "DB_PASSWORD"]

# Recognisable regardless of context — the pattern list carries their shape.
SHAPED_SECRETS = [
    pytest.param(AWS_KEY_ID, id="aws-access-key-id"),
    pytest.param("ghp_" + "a" * 36, id="github-token"),
    pytest.param("xoxb-1234567890-abcdefghij", id="slack-token"),
]

# Legitimate high-entropy values that must survive. Each was a real regression
# when the entropy fallback was applied to bare tokens in free text.
BENIGN = [
    pytest.param("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", id="content-hash"),
    pytest.param("arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def", id="aws-arn"),
    pytest.param("/usr/local/lib/python3.13/site-packages", id="path"),
    pytest.param("scanning 42 packages for vulnerabilities", id="prose"),
    pytest.param("us-east-1", id="region"),
]


@pytest.mark.parametrize("key", CREDENTIAL_KEYS)
def test_a_secret_under_a_credential_key_is_redacted(key: str) -> None:
    assert AWS_SECRET not in sanitize_text(f"{key}={AWS_SECRET}")


def test_both_halves_of_an_aws_credential_are_redacted() -> None:
    """Masking only the id is the failure mode: it looks handled and is not."""
    cleaned = sanitize_text(f"id={AWS_KEY_ID} secret={AWS_SECRET}")

    assert AWS_KEY_ID not in cleaned
    assert AWS_SECRET not in cleaned


@pytest.mark.parametrize("secret", SHAPED_SECRETS)
def test_a_recognisably_shaped_secret_is_redacted_without_a_key(secret: str) -> None:
    assert secret not in sanitize_text(f"observed {secret} in output")


@pytest.mark.parametrize("value", BENIGN)
def test_legitimate_high_entropy_values_survive(value: str) -> None:
    assert value in sanitize_text(f"hash_ref={value}")
    assert value in sanitize_text(value)


def test_a_bare_unshaped_secret_is_a_documented_limit() -> None:
    """Stated so nobody reads the guarantee as broader than it is.

    A 40-char base64 run with no key and no recognisable prefix is not
    distinguishable from a digest. Redacting it means redacting every hash in
    every log line. This asserts the limit rather than leaving it implied.
    """
    assert AWS_SECRET in sanitize_text(f"observed {AWS_SECRET} in output")
