# SQLite graph search scope

Graph text search intersects tenant and snapshot postings before joining matches
to graph nodes. Exact SQL equality on both identifiers remains mandatory:
FTS tokenization normalizes case, punctuation and diacritics, so the index is a
query optimization, not an authorization boundary. User search terms remain
restricted to the original evidence columns; tenant and snapshot metadata do
not become new searchable content.

The storage adapter owns the transaction and connection. The
`api/storage/sqlite_graph_search.py` helper owns the index definition, upgrade,
rollback and FTS expression. Ranking, exact totals, filters and cursors retain
the existing graph-store contract. PostgreSQL uses its existing separate adapter.
Identifiers with no ASCII letter/digit, or containing NUL, use exact SQL scope
filtering without the FTS scope optimization. This preserves existing text
matching for opaque identifiers.

## Qualify the change

```bash
uv sync --frozen --extra api --extra dev
uv run pytest -q tests/test_graph_search_scope_index.py tests/test_graph_search_single_pass.py
uv run python scripts/run_graph_mixed_scale_evidence.py \
  --output /tmp/graph-search-sustained --duration-seconds 120
```

Inspect `receipt.json` for every request, tenant ownership checks, failures,
latency, CPU/memory and actual read/write overlap. Compare the same fixture and
resource limits with the baseline. See [mixed-load evidence](graph-mixed-load.md)
for workload shape and limitations. Unit-test SQL work budgets and isolated
query timings do not establish end-to-end latency or production capacity.

## Upgrade an existing SQLite store

This changes the derived FTS index, preserving its eight columns, row IDs and
stored contents. The first initialization rebuilds legacy postings in one
reserved write transaction. A failed copy, drop or rename rolls the transaction
back. Graph nodes, relationships and snapshot generations are not rewritten.

1. Stop every API, MCP, worker and CLI process using this graph database. Do not
   mix old and new readers: old readers search all indexed columns and would
   include scope metadata after the upgrade.
2. Take a consistent backup of the stopped database and allow spare space for
   the old index, its replacement and SQLite's transaction journal/WAL. Rebuild
   duration and space grow with the stored search corpus; measure a copy first.
3. Run the offline upgrade below using the upgraded checkout/environment.
   Do not put this corpus-sized rebuild behind a normal HTTP request timeout.
4. Start the upgraded processes. Observe readiness and run a scoped search.
   A concurrent writer's lock timeout is not a migration deadline.

```bash
uv run python - /absolute/path/to/graph.db <<'PY'
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from agent_bom.api.storage.sqlite_graph_search import ensure_search_index

uri = Path(sys.argv[1]).resolve().as_uri() + "?mode=rw"
with closing(sqlite3.connect(uri, uri=True, timeout=60)) as connection:
    connection.execute("BEGIN IMMEDIATE")
    ensure_search_index(connection)
    connection.commit()
PY
```

Fresh stores create the scoped index directly. Subsequent initialization checks
its definition without rebuilding it. Older writer column layouts are compatible,
but that does not make a rolling deployment with older readers safe.

## Roll back without discarding newer graph data

Stop all processes again. From the upgraded checkout and environment, rebuild
only the search postings in their prior format, then start the older code:

```bash
uv run python - /absolute/path/to/graph.db <<'PY'
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from agent_bom.api.storage.sqlite_graph_search import rebuild_search_index

uri = Path(sys.argv[1]).resolve().as_uri() + "?mode=rw"
with closing(sqlite3.connect(uri, uri=True, timeout=60)) as connection:
    connection.execute("BEGIN IMMEDIATE")
    rebuild_search_index(connection, scoped=False)
    connection.commit()
PY
```

Keep the database backup until the older deployment's searches are verified.
This procedure retains current rows, including evidence written after upgrade;
a binary-only rollback does not restore the old search-content semantics.
