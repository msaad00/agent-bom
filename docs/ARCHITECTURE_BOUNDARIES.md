# Security semantics and architecture gates

`agent_bom.core` owns severity labels, histogram/policy ordering and CVSS
validation/scoring. Adapters import those rules rather than reimplementing
thresholds. The kernel cannot import API, scanner, graph, CLI, output or
provider adapters. CVSS 4 scoring loads its scorer only when requested.
Vendor-specific advisory-only fallback policies stay in their adapters;
missing/invalid CVSS is unknown, while a validated zero score is none.

Existing imports through `models.Severity`, `graph.severity` and scanner risk
helpers remain compatibility exports of the same implementations. Package
identity and ecosystem version decisions live in `core/packages.py` and the
bounded `core/versions/` modules. `package_utils` and `version_utils` preserve
existing imports; registry requests and per-scan warning delivery remain in the
outer adapter. Cached range decisions retain dropped-bound evidence so later
scans still report comparison gaps.

Run `python scripts/check_architecture.py` before a PR, or run `make preflight`.
The gate checks semantic ownership and kernel imports and prevents growth in
Python file length, function length and Ruff C901 complexity. New code uses
600 physical lines per file, 80 physical lines per function, and complexity 15.
Existing excess is recorded in `scripts/architecture-baseline.json`; this is
measured debt, not a statement that those units meet the target.

After reducing an existing unit, run
`python scripts/check_architecture.py --write-baseline` and review the reduced
allowance. The command refuses increases. CI also compares allowances against the trusted
base commit, so editing the baseline cannot approve growth. A new or renamed oversized unit has
no inherited exception. The Python gate excludes browser bundles and generated
JSON/schema/TypeScript artifacts, which retain their owning generation checks.
It sets no PR line-count limit.

Cloud role-assignment projection lives in `graph/cloud_rbac.py`, separate from
the report builder. Azure resource-group graph keys include the complete ARM
scope, normalized for case and trailing slashes; names alone cannot identify a
group across subscriptions. Rescans build these scoped keys; retained historical
snapshots are not rewritten. Authoritative authorization evidence still takes
precedence, and partial evidence does not fall back to legacy role-name edges.

Composer/Packagist recognizes `patch` as a patch-level alias, consistent with
[Composer's version parser](https://github.com/composer/semver/blob/main/src/VersionParser.php).
Native PHP retains its own qualifier ordering. The architecture gate measures
complexity even when a function carries a `noqa` annotation.
