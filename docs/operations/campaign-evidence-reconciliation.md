# Campaign evidence reconciliation

Campaign list requests, including MCP list calls, read current findings and
stored workflow assignments without modifying memberships or audit records.
When findings change, the read projects the corresponding generation and
version; it does not treat an old verification result as current.

SQLite and Postgres source writes update a tenant-scoped campaign queue in the
same transaction as the existing job or hub evidence revision. The control
plane's maintenance loop polls this queue on startup and approximately every
minute, in bounded tenant batches. A different replica can resume pending work
after restart. A partial collection stays pending and cannot retire membership.
A complete empty collection retires the previous memberships and persists its
checkpoint. Retirement alone does not verify that a vulnerability was fixed.

Owner, SLA, state, verification, and ticket mutations check evidence freshness
again. Membership and workflow writes use the source revision as a transaction
fence; a stale source receives HTTP 409 and must be collected again. Ticket
batches check freshness before each external action; an external system's own
transaction cannot be rolled back by the control plane.

Run the Postgres migrations with the configured migration role before starting
an upgraded control plane:

```bash
python -m alembic -c deploy/supabase/postgres/alembic.ini upgrade head
```

Migration `20261007_02` adds the queue, forced tenant RLS, and source
revision triggers. Runtime initialization validates the migration instead of
selecting a fallback store. Back up before upgrading; its downgrade deliberately
refuses to discard campaign checkpoints. Reverting application code does not
remove the additive table or triggers.
