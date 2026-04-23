# Runtime Operations

Use this page for the small but important operator tasks that sit between
"feature shipped" and "production stayed healthy":

- rotating the Ed25519 key used to sign cached proxy policy bundles
- verifying and renewing the cert-manager-backed CA chain for the sidecar
  mutating webhook

These are not separate products. They are the runtime maintenance tasks for the
same self-hosted `agent-bom` deployment.

## Proxy policy-cache signing key rotation

When `AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM` is set, each proxy
persists its cached gateway policy bundle together with an Ed25519 signature and
fails closed if the signature is missing, tampered, or produced by a different
key.

That hardening changes the rotation rule:

1. rotate the signing key while the control plane is reachable
2. restart or refresh proxies so they fetch and re-sign a fresh policy bundle
3. only then rely on cached-startup fallback again

### Why the order matters

The proxy uses the currently mounted private key to verify the cached signature
at startup. If you mount a new key while the cache still contains a bundle
signed by the old key, a cold start will reject that cache and fail closed.

That is the intended safety property. Rotation should therefore be treated as a
rolling refresh, not a "swap the secret and walk away" change.

### Recommended rotation flow

Generate a new Ed25519 key pair:

```bash
openssl genpkey -algorithm ed25519 -out /tmp/proxy-policy-cache-ed25519.pem
openssl pkey -in /tmp/proxy-policy-cache-ed25519.pem -pubout -out /tmp/proxy-policy-cache-ed25519.pub
```

Update the secret or environment source that backs
`AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM`.

For Kubernetes, that usually means updating the Secret referenced by the proxy
or sidecar deployment:

```bash
kubectl -n agent-bom create secret generic agent-bom-proxy-policy-signing \
  --from-file=AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM=/tmp/proxy-policy-cache-ed25519.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

Then roll the affected proxy workloads while the control plane is healthy:

```bash
kubectl -n agent-bom rollout restart deploy/agent-bom-sidecar-injector
kubectl -n <workload-namespace> rollout restart deploy/<mcp-workload>
```

For laptop or MDM rollout, regenerate the onboarding bundle and push the updated
environment/config through the same managed path used for initial install:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./bundle \
  --control-plane-url https://agent-bom.internal.example.com \
  --control-plane-token "$CONTROL_PLANE_TOKEN" \
  --enrollment-name corp-laptop-rollout \
  --mdm-provider jamf
```

### Break-glass recovery

If a proxy starts with a newly rotated key while the control plane is
unreachable, it may reject the old cached bundle and exit.

Recovery order:

1. restore control-plane reachability if possible
2. remove the stale cache and signature files
3. restart the proxy so it fetches a fresh bundle

Default cache paths:

- `~/.agent-bom/cache/gateway-policies.json`
- `~/.agent-bom/cache/gateway-policies.json.sig`

### Rotation checklist

- rotate the secret value that backs `AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM`
- perform rolling restarts while the control plane is reachable
- confirm proxies can still pull policy and start cleanly
- archive the public key if your change process requires evidence of the new key

## Sidecar webhook certificate and CA renewal

The packaged sidecar mutating webhook is cert-manager-backed. The chart ships:

- an `Issuer` or externally supplied `issuerRef`
- a `Certificate`
- a `MutatingWebhookConfiguration` with
  `cert-manager.io/inject-ca-from`

That means the normal case is automatic:

- cert-manager renews the webhook serving certificate before expiry
- the Secret mounted into the injector Deployment updates
- cert-manager injects the matching CA bundle into the webhook configuration

### Relevant chart values

- `sidecarInjection.enabled=true`
- `sidecarInjection.certManager.enabled=true`
- `sidecarInjection.certManager.duration`
- `sidecarInjection.certManager.renewBefore`
- `sidecarInjection.certManager.createSelfSignedIssuer`
- `sidecarInjection.certManager.issuerRef.*`

### What to verify

Check the certificate and its renewal window:

```bash
kubectl -n agent-bom get certificate,secret | grep sidecar-injector
kubectl -n agent-bom describe certificate agent-bom-sidecar-injector
```

Check that the webhook configuration is still receiving the injected CA bundle:

```bash
kubectl get mutatingwebhookconfiguration agent-bom-sidecar-injector -o yaml | rg "caBundle|inject-ca-from"
```

Check that the injector pod is serving with the expected Secret:

```bash
kubectl -n agent-bom describe deploy agent-bom-sidecar-injector
kubectl -n agent-bom get pods -l app.kubernetes.io/component=sidecar-injector
```

### Rotation and renewal behavior

If you use the chart-managed self-signed issuer, cert-manager owns the full
renewal path.

If you use an external issuer:

- `issuerRef` points to the cluster or namespace issuer you manage
- renewal cadence comes from that issuer plus the chart's
  `duration` / `renewBefore`
- `cert-manager.io/inject-ca-from` still keeps the webhook CA bundle aligned

### Recovery steps if admission starts failing

Symptoms usually show up as failed Pod creates in opted-in namespaces.

Check in this order:

1. `Certificate` condition is `Ready=True`
2. serving TLS Secret exists and was updated recently
3. `MutatingWebhookConfiguration` still has the `inject-ca-from` annotation
4. injector Deployment has healthy pods
5. cert-manager controller logs do not show issuance or injection failures

If the certificate renewed but the injector pod still serves the old mount,
restart the injector Deployment:

```bash
kubectl -n agent-bom rollout restart deploy/agent-bom-sidecar-injector
```

## Release sign-off for runtime operations

Before calling a release "operator-ready", verify:

- proxy policy signing is either disabled intentionally or documented with a
  concrete secret owner and rotation path
- sidecar injection uses cert-manager with a known issuer and renewal window
- the recovery commands above are present in the team's internal runbook or
  deployment ticket
