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

Python:

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

- **Integrity** — the HMAC or Ed25519 signature covers the canonical body. Any field change invalidates the signature.
- **Confidentiality** — the bundle itself is cleartext by design (auditors read it). Always serve `/v1/compliance/*` over TLS.
- **Replay** — `nonce` + `expires_at` are inside the signed envelope. Verifiers reject bundles past `expires_at`.
- **Non-repudiation** — only Ed25519 provides it. HMAC is a shared secret, so the server and the verifier are indistinguishable.

For forensic cases requiring non-repudiation, also correlate with the
`compliance.report_exported` entry in the HMAC-chained audit log — that
captures actor, tenant, nonce, and `expires_at` on export.
