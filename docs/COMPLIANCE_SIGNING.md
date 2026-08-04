# Compliance Evidence Bundle Signing

`GET /v1/compliance/{framework}/report` returns a signed evidence bundle.
Two signing modes:

| Mode | Verifier needs | Non-repudiation | Default? |
|---|---|---|---|
| **HMAC-SHA256** | shared secret (`AGENT_BOM_AUDIT_HMAC_KEY`) | no (symmetric) | yes |
| **Ed25519** | public key only | yes (asymmetric) | opt-in |

HMAC is fine for internal review. External auditor / SOC 2 / ISO / PCI
evidence hand-off should use Ed25519 — the verifier only receives the
public key, which cannot be used to forge new bundles.

---

## Is the signature actually verifiable?

**A bundle is not verifiable just because it is signed.** When neither
`AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM` nor `AGENT_BOM_AUDIT_HMAC_KEY`
is set — the default for `agent-bom serve` — the HMAC key is generated at
process start and never leaves the process. Bundles are still stamped
`signature_algorithm: HMAC-SHA256`, but nobody can check them, including the
issuing deployment after a restart.

Every bundle therefore carries `signature_disclosure` **inside the signed
envelope** (it is part of the canonical body, so it cannot be stripped or
forged without breaking the signature):

```json
"signature_disclosure": {
  "signature_verifiable": false,
  "persists_across_restart": false,
  "verification_status": "unverifiable_ephemeral_key",
  "verification_guidance": "This deployment signs with a per-process HMAC key …",
  "remediation": "Set AGENT_BOM_AUDIT_HMAC_KEY … or AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM …"
}
```

| `verification_status` | Meaning | Auditor-distributable |
|---|---|---|
| `verifiable_public_key` | Ed25519 — verifier needs only the public key | yes |
| `verifiable_shared_secret` | `AGENT_BOM_AUDIT_HMAC_KEY` is configured and persists | no — the secret can also forge bundles |
| `unverifiable_ephemeral_key` | per-process key; the bundle proves nothing | no |

`GET /v1/compliance/verification-key` reports the same three fields plus
`remediation`, so a verifier can tell before fetching evidence whether the
deployment can produce anything checkable. A bundle whose status is
`unverifiable_ephemeral_key` must be re-exported after the deployment is
reconfigured — the key that signed it is gone.

---

## Enabling Ed25519

Generate a key pair once, store the private key in your secret manager:

```bash
openssl genpkey -algorithm ed25519 -out agent-bom-evidence-key.pem
openssl pkey -in agent-bom-evidence-key.pem -pubout -out agent-bom-evidence-pub.pem
```

Deploy the server with the **private** key as a mounted file and set
`AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE` to that path. File-first
resolution keeps the PEM out of `.env`, Pod environment, and process listings.
The inline `..._PEM` variable remains compatibility-only.

On Helm, mount the Secret instead of projecting its contents into an environment variable:

```yaml
controlPlane:
  api:
    extraVolumes:
      - name: evidence-signing
        secret:
          secretName: agent-bom-evidence-signing
    extraVolumeMounts:
      - name: evidence-signing
        mountPath: /run/secrets/agent-bom
        readOnly: true
    env:
      - name: AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM_FILE
        value: /run/secrets/agent-bom/private.pem
```

The server logs at startup:

```
compliance evidence signing: Ed25519 enabled (key_id=3f9a2c8d1b4e7f02)
```

If the PEM is malformed, the server logs a warning and falls back to HMAC
— the endpoint does not crash.

---

## How a verifier checks a bundle

### 1. Pin the public key

```bash
curl -s https://agent-bom.example.com/v1/compliance/verification-key \
     -H "Authorization: Bearer $TOKEN" | jq -r .public_key_pem > pinned.pem
```

The response also contains `key_id` (16-hex SHA-256 prefix of the DER
public key). Pin both the key and the `key_id` — every signed bundle
echoes the `key_id` so you know which key to use.

### 2. Fetch an evidence bundle

```bash
curl -s -o bundle.json \
     https://agent-bom.example.com/v1/compliance/soc2/report \
     -H "Authorization: Bearer $TOKEN"
```

The bundle **embeds its own signature** in the `signature` field, so the saved
file is verifiable on its own — no headers needed. The same value is mirrored
into `X-Agent-Bom-Compliance-Report-Signature` for streaming consumers that
verify before buffering the body.

### 3. Verify offline

Shipped verifier — no hand-copied script required:

```bash
agent-bom attest compliance-verify bundle.json --public-key pinned.pem
```

```
VERIFIED: bundle.json
  reason:    verified
  algorithm: Ed25519
  check:     disclosure:verifiable_public_key
  check:     expires_at:valid
```

It exits non-zero on any failure and reads both the `json` and `jsonl`
renderings. It **never trusts `signature_public_key_pem` embedded in the
bundle** — that key is self-attesting, so anyone who edits the bundle can
re-sign it. Without `--public-key` an Ed25519 bundle fails with
`no_trusted_public_key`. (`--trust-embedded-key` exists for checking your own
artifact's internal consistency; it is not evidence.) HMAC bundles are
verified against `AGENT_BOM_AUDIT_HMAC_KEY` in the verifier's environment;
a bundle whose own disclosure says the issuer key was ephemeral fails with
`issuer_key_ephemeral` rather than pretending to check it.

The equivalent by hand, in Python:

```python
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

body = json.load(open("bundle.json"))
sig_hex = body["signature"]
canonical = json.dumps({k: v for k, v in body.items() if k != "signature"}, sort_keys=True).encode()
pub = serialization.load_pem_public_key(open("pinned.pem").read().encode())
assert isinstance(pub, Ed25519PublicKey)
pub.verify(bytes.fromhex(sig_hex), canonical)
print("bundle verified against pinned key")
```

The canonical form is `json.dumps(body, sort_keys=True).encode()` of the
response body **with the `signature` field removed** — a signature cannot cover
itself. Tampering with any other byte invalidates the signature.

> **Breaking change.** Bundles previously carried no `signature` field, and the
> canonical form was the *entire* body. A verifier written against the old
> contract must now drop the `signature` key before hashing. Bundles archived
> before this change verify with the old recipe (no `signature` field is
> present to remove), so both are distinguishable by whether the field exists.

### Verifying the `jsonl` rendering

`?format=jsonl` streams one record per line. Reassemble and verify with the
**same** canonical form — the signature no longer depends on the stream's byte
layout:

```python
records = [json.loads(line) for line in open("bundle.jsonl") if line.strip()]
meta = next(r["meta"] for r in records if "meta" in r)
body = {
    **meta,
    "controls": [r["control"] for r in records if "control" in r],
    "audit_events": [r["audit"] for r in records if "audit" in r],
}
canonical = json.dumps({k: v for k, v in body.items() if k != "signature"}, sort_keys=True).encode()
pub.verify(bytes.fromhex(meta["signature"]), canonical)
```

---

## Key rotation

1. Generate a new key pair.
2. Replace the mounted private-key file and redeploy.
3. Auditors re-fetch `/v1/compliance/verification-key` and pin the new `key_id`.
4. Bundles signed with the old key remain verifiable against the old public key — retain it offline for the evidence retention window your framework requires.

Each bundle carries `signature_key_id` inside the body, so long-term
evidence archives can pick the right key at audit time.

---

## Threat model

The `threat_model` block inside every bundle summarises what the signature
does and does not prove:

- **Integrity** — the HMAC or Ed25519 signature covers the canonical body. Any field change invalidates the signature. When the signer is ephemeral, `integrity` says so and the bundle should be treated as unsigned evidence — see `signature_disclosure` above.
- **Confidentiality** — the bundle itself is cleartext by design (auditors read it). Always serve `/v1/compliance/*` over TLS.
- **Replay** — `nonce` + `expires_at` are inside the signed envelope. Verifiers reject bundles past `expires_at`.
- **Non-repudiation** — only Ed25519 provides it. HMAC is a shared secret, so the server and the verifier are indistinguishable.

For forensic cases requiring non-repudiation, also correlate with the
`compliance.report_exported` entry in the HMAC-chained audit log — that
captures actor, tenant, nonce, and `expires_at` on export.
