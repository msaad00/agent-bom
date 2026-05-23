# OpenAPI Contract

`v1.json` and `v1.yaml` are generated from the FastAPI control-plane app and
committed as the stable SDK/codegen input for agent-bom clients.

Refresh after API route or model changes:

```bash
python scripts/export_openapi.py
```

Check for drift in CI:

```bash
python scripts/export_openapi.py --check
```

The TypeScript, Python, and Go control-plane clients should treat these
artifacts as the source contract rather than hand-maintaining route paths
independently.
