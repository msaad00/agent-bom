# agent-bom Streamlit Dashboard — Legacy / Deprecated

> **This dashboard is deprecated.** Use the Next.js UI instead.

## Migrate to Next.js

The Next.js dashboard (`ui/`) replaces this Streamlit app and has full feature parity plus interactive graphs, WebSocket live metrics, agent topology, attack flow chains, compliance heatmap, and fleet management — none of which Streamlit supports.

```bash
# Start the API server
pip install 'agent-bom[api]'
agent-bom api

# Start the Next.js UI
cd ui
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8422" > .env.local
npm run dev
# → http://localhost:3000
```

## Why kept in repo

The `dashboard/` folder is retained for the **Snowflake Native App** path only. Streamlit is the only UI framework compatible with Snowflake Native Apps. For all other deployments, use the Next.js UI.

## Running (legacy)

```bash
pip install streamlit plotly pandas
agent-bom scan -f json -o report.json
streamlit run dashboard/app.py -- --report report.json
```
