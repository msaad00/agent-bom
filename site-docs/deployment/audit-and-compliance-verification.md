# Audit Chain vs Compliance Signing

`agent-bom` has **two different integrity mechanisms** that solve different
problems.

This page exists so operators and auditors do not confuse them.

## The two mechanisms

| Mechanism | What it protects | Scope | Verifier needs |
|---|---|---|---|
| HMAC-chained audit log | append-only action history | control-plane audit entries | shared HMAC key or online API verification |
| Ed25519 compliance signing | exported evidence bundle | compliance report export payload | public key only |

They are related, but they are not interchangeable.

## Audit log chain

The audit log is:

- append-only
- chained per tenant
- HMAC-protected

It answers:

- was this action history tampered with?
- did this tenant’s audit sequence remain intact?
- was a report export recorded at all?

Relevant endpoints:

- `GET /v1/audit`
- `GET /v1/audit/integrity`
- `GET /v1/audit/export`
- `POST /v1/audit/export/verify`

The JSON export body includes `filters`, `integrity`, and each entry's
`hmac_signature` / `prev_signature` chain fields. JSONL exports carry the same
entry shape one record per line.

Typical audit event for compliance export:

- `compliance.report_exported`

That event records details such as:

- actor
- tenant
- nonce
- expiry
- framework

## Compliance signing

Compliance signing protects the exported report bundle itself.

It answers:

- was this JSON evidence bundle modified after export?
- which signing key produced it?
- can an external auditor verify it offline without a shared secret?

Relevant endpoints:

- `GET /v1/compliance/{framework}/report`
- `GET /v1/compliance/verification-key`

Ed25519 is the preferred external-auditor path because it gives asymmetric
verification.

## How the two fit together

Think of them this way:

- **audit chain** proves the export action is in the system history
- **bundle signature** proves the exported payload was not changed

For a stronger audit trail, use both:

1. verify the evidence bundle signature
2. verify the matching `compliance.report_exported` audit entry
3. confirm tenant, framework, nonce, and expiry align

## Auditor workflow

### 1. Verify the bundle

Follow the signing cookbook in:

- [docs/COMPLIANCE_SIGNING.md](https://github.com/msaad00/agent-bom/blob/main/docs/COMPLIANCE_SIGNING.md)

### 2. Verify the export action

Example:

```bash
curl -s "https://agent-bom.example.com/v1/audit?action=compliance.report_exported&limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

Then verify audit integrity:

```bash
curl -s "https://agent-bom.example.com/v1/audit/integrity?limit=1000" \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Correlate them

Match:

- tenant
- framework
- nonce
- `expires_at`
- signing `key_id` where applicable

## What each mechanism does not prove

### Audit chain does not prove

- non-repudiation to an external third party
- that an exported JSON file was not modified after it left the API

### Compliance signing does not prove

- that the export was authorized by the right actor
- that the action was present in the full tenant audit history

That is why both are useful.

## Recommended production posture

- keep the audit HMAC key in your secret manager
- enable Ed25519 signing for external evidence exchange
- retain old public keys for the evidence retention window after rotation
- verify both the bundle and the audit event for formal audits
