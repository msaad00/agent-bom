# Overview screenshot evidence

Regenerate the offline enterprise fixture from the repository root:

```bash
uv run python ui/scripts/generate-overview-proof.py
```

The generator creates temporary application stores, seeds the synthetic demo
estate, and records authenticated API responses. It clears inherited operator
configuration and does not bind a listening port. The fixture is compressed to
keep the full scan evidence out of the application bundle and compact in Git.

Commit the fixture and UI changes, then run `npm run capture:product-proof` in
`ui/`. The screenshot generator serves these responses only for Overview;
other gallery routes have their own labeled fixtures. Captures pin their inputs
in `docs/images/product-screenshots.json`.

Counts use the API's deduplication and scope rules. Security categories overlap;
framework checks and risk mappings are distinct. These are modeled results,
not live cloud collection or certification evidence. Snapshot IDs and timestamps
are generated afresh and remain consistent within each fixture.
