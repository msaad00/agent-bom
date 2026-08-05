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


# A 64-char hex API key: no recognisable prefix, and its entropy (~4.0 bits/char
# over a 16-symbol alphabet) sits below the bare-value threshold on purpose. The
# key name is the whole signal, so every shape the key can be written in has to
# find it.
HEX_KEY = "a3f9c21e8b4d7605fe12ab34cd56ef7890123456789abcdef0123456789abcde"

KEY_VALUE_SHAPES = [
    pytest.param(f"API_KEY={HEX_KEY}", id="bare"),
    pytest.param(f'API_KEY="{HEX_KEY}"', id="double-quoted"),
    pytest.param(f"API_KEY='{HEX_KEY}'", id="single-quoted"),
    pytest.param(f"API_KEY = {HEX_KEY}", id="spaced"),
    pytest.param(f'{{"api_key": "{HEX_KEY}"}}', id="json"),
    pytest.param(f"api_key: {HEX_KEY}", id="yaml"),
    pytest.param(f'api_key:"{HEX_KEY}"', id="json-tight"),
    pytest.param(f"launching with api_key={HEX_KEY}, region=us-east-1", id="comma-separated"),
    pytest.param(f"  api-key  =  {HEX_KEY}  ", id="hyphenated-and-padded"),
]


@pytest.mark.parametrize("text", KEY_VALUE_SHAPES)
def test_a_credential_key_is_found_in_every_ordinary_formatting(text: str) -> None:
    """`rpartition` found the key only in `KEY=value`; everything else leaked."""
    assert HEX_KEY not in sanitize_text(text)


def test_base64_padding_does_not_defeat_the_key_match() -> None:
    """`rpartition("=")` split on the *padding*, leaving an empty candidate.

    The key was then the whole `TOKEN=<value>` run and the value was empty, so
    the check fell through and printed the token verbatim.
    """
    padded = "c2VjcmV0LXZhbHVlLXRoYXQtaXMtbG9uZy1lbm91Z2g="

    assert padded not in sanitize_text(f"AWS_SESSION_TOKEN={padded}")


# The other direction: widening how the *key* is found must not widen what
# counts as a secret. Each of these has a credential-ish key and a value that is
# not credential material; redacting them makes logs unreadable without making
# anything safer.
NON_SECRET_VALUES = [
    pytest.param("exposed_credentials=3", "3", id="a-count"),
    pytest.param("api_key=none", "none", id="absent"),
    pytest.param("has_token: false", "false", id="boolean"),
    pytest.param("password=***REDACTED***", "***REDACTED***", id="already-redacted"),
    pytest.param("credential_names=OPENAI_API_KEY", "OPENAI_API_KEY", id="credential-identifier"),
]


@pytest.mark.parametrize(("text", "survivor"), NON_SECRET_VALUES)
def test_values_that_are_not_credential_material_survive(text: str, survivor: str) -> None:
    assert survivor in sanitize_text(text)


def test_a_very_short_value_is_a_documented_limit() -> None:
    """Stated rather than implied: under four characters nothing is redacted.

    `auth=jwt` and `cert=pem` are enum values, and the key name cannot tell them
    from a three-character secret. Nothing regresses — the previous value gate
    needed 24 characters before it looked at anything.
    """
    assert sanitize_text("api_key=abc") == "api_key=abc"


def test_a_structured_graph_node_id_is_not_read_as_an_assignment() -> None:
    """A colon delimits node-id segments far more often than it assigns a value.

    `sanitize_text` runs over every graph node and edge id. Reading the first
    colon as `key: value` truncated the id to `credential_ref:<redacted>`, and
    the exporter set-dedups on the id — so distinct credential references
    collapsed into one phantom node with invented edges.
    """
    node_id = "credential_ref:credential_ref:credential_ref:credential_reference:redacted"

    assert sanitize_text(node_id) == node_id
    assert sanitize_text("token:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b") == (
        "token:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    )


def test_a_credential_bearing_url_keeps_its_shape() -> None:
    """A URL under a credential key is reduced, not blanked — the host is evidence."""
    cleaned = sanitize_text("DATABASE_URL=postgres://app:hunter2@db.internal:5432/prod")

    assert "hunter2" not in cleaned
    assert "db.internal" in cleaned


def test_a_bare_unshaped_secret_is_a_documented_limit() -> None:
    """Stated so nobody reads the guarantee as broader than it is.

    A 40-char base64 run with no key and no recognisable prefix is not
    distinguishable from a digest. Redacting it means redacting every hash in
    every log line. This asserts the limit rather than leaving it implied.
    """
    assert AWS_SECRET in sanitize_text(f"observed {AWS_SECRET} in output")
