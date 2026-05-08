# Product Screenshot Refresh Checklist

Use this checklist when refreshing product screenshots for README, docs site,
Docker Hub, release notes, or marketplace evidence. It turns the capture
protocol in [`docs/CAPTURE.md`](../CAPTURE.md) into a PR-ready release gate.

## Preflight

- Start from the release branch or tag that will publish the screenshots.
- Confirm the visible version in `pyproject.toml` matches the intended release.
- Build the packaged dashboard; do not capture from an archived UI or a dev
  page that shows transient build state.
- Generate bundled demo data offline and push that exact payload to the API.
- Keep local workstation discovery, private tenants, and customer data out of
  the capture database.

## Capture Set

Refresh all images listed in `docs/images/product-screenshots.json` unless the
PR clearly explains why an asset is unchanged.

| Asset | Required proof |
|---|---|
| `dashboard-live.png` | Risk overview top frame, visible version, headline KPIs, posture grade, and start of attack paths. |
| `dashboard-paths-live.png` | Risk overview mid-frame, attack paths, exposure KPIs, severity/source charts, and backlog context. |
| `mesh-live.png` | Agent mesh scoped to a high-signal demo agent, currently `cursor`, with non-empty packages, findings, tools, credentials, and edges. |
| `remediation-live.png` | Fix-first remediation table with prioritized packages and framework context. |

## Manifest

Update `docs/images/product-screenshots.json` in the same PR:

- `release_version` matches `pyproject.toml`.
- `captured_at` uses UTC ISO-8601 time.
- every screenshot entry has `path`, `page`, `scope`, and `visible_version`.
- every `visible_version` matches the release version.
- each listed file exists under `docs/images/`.

## Visual Review

Before opening the PR, inspect every refreshed image:

- no private paths, credentials, customer names, local usernames, browser chrome,
  terminal windows, or dev overlays are visible
- no empty graph, nearly empty graph, or unreadable dense graph is published as
  product evidence
- text and critical UI affordances are readable at GitHub README scale
- light/dark theme claims are backed by captured evidence when the PR says so
- the image shows shipped product behavior, not roadmap copy or mock data that
  is not produced by `agent-bom`

## Verification

Run these checks before pushing:

```bash
uv run python scripts/check_release_consistency.py
git diff --check
```

For UI changes that alter the captured surfaces, also run the relevant UI
validation or Playwright capture command and list it in the PR body.

## PR Evidence

The PR body should include:

- exact command used to generate and push demo data
- API/UI serving mode used for capture
- refreshed asset list
- visual review summary
- validation commands and results
- linked issue or release task

Do not claim a screenshot refresh is release-ready if the manifest, visible
version, and reviewed images are not aligned.
