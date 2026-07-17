# Warehouse export publication contract

ClickHouse, BigQuery, and Databricks write each invocation to
`<feed_table>_staged` with a new `publication_attempt_id`. After every batch
completes, one row is appended to `<feed_table>_runs`. The manifest row is the
publication pointer; staged rows without one are not completed export data.

Retries and concurrent workers may create more than one complete attempt.
Consumers select exactly one latest pointer per tenant by warehouse commit
time, then join all three scope columns. This makes a zero-row snapshot and
finding removals supersede older run IDs. Publication ordering is assigned only
after staging completes, not when an export starts.

A definitive pre-publication batch failure is cleaned up best-effort. Once a
manifest write starts, a timeout is ambiguous: an absent immediate read is not
proof the operation cannot still commit. The adapters therefore preserve the
complete immutable staging attempt. A present exact marker is reconciled as
success; absent or unavailable status raises a publication-indeterminate error
and audits the run as `indeterminate`, never `failure`, without risking a late
pointer to deleted data. Cleanup failures are logged and never replace the
primary export error.

Databricks uses explicit connector autocommit for these single-statement Delta
writes. It does not claim a multi-statement transaction: correctness comes from
immutable attempts plus the one-statement manifest pointer, so it also works on
warehouses that do not meet Databricks' catalog-managed transaction preview
requirements.

```sql
-- BigQuery / Databricks
WITH published_snapshot AS (
  SELECT *
  FROM findings_feed_runs
  QUALIFY ROW_NUMBER() OVER (
    PARTITION BY tenant_id
    ORDER BY committed_at DESC, commit_version DESC, publication_attempt_id DESC
  ) = 1
)
SELECT staged.* EXCEPT (publication_attempt_id)
FROM findings_feed_staged AS staged
JOIN published_snapshot AS published
  ON published.tenant_id = staged.tenant_id
 AND published.run_id = staged.run_id
 AND published.publication_attempt_id = staged.publication_attempt_id
;
```

ClickHouse uses the same three-column join and selects its pointer with
`argMax(tuple(run_id, publication_attempt_id), tuple(committed_at,
commit_version, publication_attempt_id))` grouped by `tenant_id`.
Both ordering fields are assigned by the destination warehouse at publication
time (BigQuery and Databricks use `CURRENT_TIMESTAMP()`; ClickHouse column
defaults use `now64()`), so clock skew between exporter replicas cannot select
an older snapshot as current.

The manifest join is mandatory; querying the staging table directly includes
unpublished attempts. Superseded and indeterminate attempts remain physical
staging data and are not part of the published feed. This change does not ship
automatic BigQuery or Delta retention; operators must apply their warehouse
table-expiration/VACUUM policy. ClickHouse retention is likewise deployment
owned until a separately configurable product TTL is introduced.

Snowflake prepares and uploads its attempt first, then explicitly executes
`BEGIN`, tenant-scoped `DELETE`, a non-empty run's `COPY INTO`, a durable
run-marker insert, and
`COMMIT`. The marker and replacement are one transaction. A fresh-session exact
marker read reconciles a lost COMMIT response. A failed replacement attempts
both `ROLLBACK` and unique stage-prefix removal without masking the primary
error. Snowflake and Databricks require a non-blank stored private key or token
at API validation and build time. S3, GCS, BigQuery, and Azure Blob retain their
implemented ambient or managed-identity credential chains.
