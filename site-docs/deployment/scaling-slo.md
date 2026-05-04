# Scaling SLOs and KEDA-driven autoscaling

> **You do not need to read this unless** you are running KEDA-backed
> autoscaling, validating the shipped per-tier SLOs, or signing off
> production sizing for the EKS reference deployment. For default
> sizing guidance use [Performance, Sizing, and
> Benchmarks](performance-and-sizing.md).

This page publishes the per-tier scaling SLOs agent-bom commits to under the
documented EKS reference deployment, and explains the autoscaling primitives
the chart ships with so you can validate them against your own load.

## Published SLOs (control-plane API tier)

These targets apply to the `eks-production-values.yaml` + `eks-keda-values.yaml`
combination on EKS 1.30+ with the KEDA operator installed and Prometheus
available at the configured `serverAddress`.

| SLO | Target | Window | How we measure |
|---|---|---|---|
| API request availability | ≥ 99.9% | rolling 30 days | `1 - (rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]))` aggregated across replicas |
| API p99 latency under autoscaling load | < 2.0s | rolling 1 hour | `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{job=~".*agent-bom-api.*"}[2m])))` |
| Time-to-scale-out under burst | < 90s from saturation signal to first new pod ready | per burst | KEDA poll (30s) + scheduler (~10s) + readiness probe (~30s + startup) |
| Min replica floor honored | 100% of windows | rolling 24 hours | `count(up{job=~".*agent-bom-api.*"} == 1)` ≥ `minReplicas` |
| Scale-up headroom remaining | ≥ 25% (replicas below `maxReplicas`) | sustained ≥ 5 min | `kube_horizontalpodautoscaler_status_current_replicas{horizontalpodautoscaler=~".*agent-bom-api.*"} / kube_horizontalpodautoscaler_spec_max_replicas{horizontalpodautoscaler=~".*agent-bom-api.*"} ≤ 0.75` |

These are operating SLOs, not benchmarks. They're the targets the chart's
defaults are tuned to hit; they aren't a guarantee that any particular
cluster will meet them under arbitrary load. See [Honest gaps](#honest-gaps)
for what is *not* yet measured at clustered scale.

## Why KEDA, not just HPA

The default `controlPlane.api.autoscaling.enabled=true` ships a CPU/memory
HPA. That works for steady traffic but lags on the workload pattern most
agent-bom operators see: bursty scan jobs that build up backpressure long
before CPU registers the load.

The KEDA path (`controlPlane.api.autoscaling.keda.enabled=true`) replaces
the static HPA with a `ScaledObject` driven by two leading-indicator signals
the API tier exposes through Prometheus today:

1. **Rate-limit pressure**
   `sum(rate(agent_bom_rate_limit_hits_total{bucket=~"global|tenant"}[1m]))`
   When the limiter starts rejecting, queue saturation is imminent. This is
   exported by `src/agent_bom/api/metrics.py` and rendered at `/metrics`
   on every API replica.

2. **API p99 latency**
   `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{job=~".*agent-bom-api.*"}[2m])))`
   Backed by the standard Starlette instrumentation. Climbing past the
   threshold means request servicing is starting to back up.

3. **In-flight scan jobs (queued + running)**
   `sum(agent_bom_scan_jobs_active)`
   First-class queue-depth gauge exported by every API replica. Bumped
   in `agent_bom.api.routes.scan.enqueue_scan_job` as soon as the job is
   durably enqueued; decremented in `agent_bom.api.pipeline._run_scan_sync`
   when the job reaches a terminal status (DONE / FAILED / CANCELLED).
   Floored at zero so any instrumentation gap absorbs gracefully instead
   of producing a negative gauge. This is the most direct saturation
   signal of the three — the rate-limit and p99 triggers are leading
   indicators; this one is the actual queue.

KEDA polls every 30s by default, so the worst-case scaling latency is one
poll plus pod-startup. The published "< 90s" SLO is calibrated against that.

## How to enable

```bash
# 1. Install KEDA on the cluster (one-time).
helm repo add kedacore https://kedacore.github.io/charts
helm install keda kedacore/keda --namespace keda --create-namespace
kubectl get crd scaledobjects.keda.sh   # should exist

# 2. Render the agent-bom chart with the KEDA preset on top of production.
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml \
  -f deploy/helm/agent-bom/examples/eks-keda-values.yaml \
  --set controlPlane.api.autoscaling.keda.prometheus.serverAddress=http://prometheus.monitoring.svc:9090

# 3. Verify the ScaledObject is active and the underlying HPA is generated.
kubectl get scaledobject -n agent-bom
kubectl get hpa -n agent-bom   # KEDA-managed HPA appears with name keda-hpa-*
```

The static `controlplane-api-hpa.yaml` template detects KEDA and skips
rendering — there is exactly one HPA against the Deployment at any time.

## Tuning the trigger thresholds

The defaults in `eks-keda-values.yaml` (rate-limit > 0.5/sec, p99 > 1.5s)
are calibrated 0.5s below the published p99 SLO so the scaler reacts
*before* the SLO is breached, not after.

If your operating profile is steadier and you want fewer scale events,
raise the thresholds toward the SLO target:

```yaml
controlPlane:
  api:
    autoscaling:
      keda:
        prometheus:
          rateLimitThreshold: "1.0"
          p99ThresholdSeconds: "1.8"
```

If your operating profile is burstier (e.g. fleet-sync waves, large CI
matrices firing scans in parallel), lower the thresholds and shorten the
cooldown:

```yaml
controlPlane:
  api:
    autoscaling:
      keda:
        cooldownSeconds: 180
        prometheus:
          rateLimitThreshold: "0.25"
          p99ThresholdSeconds: "1.2"
```

## Custom triggers (queue depth, SQS, Kafka, etc.)

Set `controlPlane.api.autoscaling.keda.triggers` to a full KEDA trigger
list to replace the default Prometheus pair. KEDA's [trigger reference](https://keda.sh/docs/2.16/scalers/)
covers SQS, Kafka, NATS, CloudWatch, and many others.

```yaml
controlPlane:
  api:
    autoscaling:
      keda:
        enabled: true
        triggers:
          - type: aws-sqs-queue
            metadata:
              queueURL: https://sqs.us-east-2.amazonaws.com/123456789/agent-bom-jobs
              queueLength: "20"
              awsRegion: us-east-2
            authenticationRef:
              name: agent-bom-sqs-auth
```

## Honest gaps

The chart's autoscaling primitives are real and tested. The published SLOs
above are honest about what the **defaults are tuned to hit**. The remaining
gap, called out so a reviewer doesn't have to derive it:

**No published clustered Postgres scale benchmark.** Today's published
evidence (`scripts/run_scale_evidence.py`) is in-process and tops out at
1k–10k entities. A clustered Postgres run at 50k+ entities is the next
piece needed before claiming "elastic at 1M edges." Until that lands, keep
your `maxReplicas` calibrated to your Postgres connection-pool capacity
(default chart sets pool size in
`controlPlane.api.env.AGENT_BOM_POSTGRES_POOL_MAX`).

This gap blocks the "elastic at 1M edges" claim, but it does not block
pilots and does not prevent the SLOs above from being met for the
workload sizes they're written for.
