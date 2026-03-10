# agent-bom v0.69.0 demo — run with: vhs docs/demo.tape
# Install vhs: brew install vhs  (or https://github.com/charmbracelet/vhs)
# Prereqs:
#   pip install agent-bom
#   docker running (for --gpu-scan section)
#   Run before recording: docker run -d --name gpu-demo \
#     --label com.nvidia.cuda.version=12.3.0 \
#     node:18-slim sleep 3600

Output docs/images/demo-v0.69.0.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 1.2

# ── 1. Auto-discover your MCP setup ─────────────────────────────────────────
# Discovers 21 MCP clients, scans CVEs, maps blast radius, 11-framework compliance
Type "agent-bom scan"
Sleep 300ms
Enter
Sleep 10s

# ── 2. Find a critical CVE before installing ─────────────────────────────────
Type "agent-bom check lodash@4.17.20 --ecosystem npm"
Sleep 300ms
Enter
Sleep 5s

# ── 3. Fix it — scan the patched version ─────────────────────────────────────
Type "agent-bom check lodash@4.17.23 --ecosystem npm"
Sleep 300ms
Enter
Sleep 5s

# ── 4. GPU/AI compute infra scan ─────────────────────────────────────────────
# Detects CUDA containers, DCGM endpoints, GPU workload security
Type "agent-bom scan --gpu-scan"
Sleep 300ms
Enter
Sleep 12s

# ── 5. Output formats — SARIF, CycloneDX, SPDX, HTML, Mermaid ──────────────
Type "agent-bom scan -f sarif -o results.sarif && echo '13 output formats: SARIF, CycloneDX 1.6, SPDX 3.0, HTML, Mermaid, SVG, Prometheus, Badge...'"
Sleep 300ms
Enter
Sleep 4s

# ── 6. Runtime proxy — intercept MCP traffic with 7 detectors ───────────────
# SQL injection, credential leak, prompt injection, tool drift detection
Type "agent-bom proxy --detect-credentials --block-undeclared -- npx @modelcontextprotocol/server-fs /tmp &"
Sleep 300ms
Enter
Sleep 3s
Type "# ↑ Proxy running: 71 security patterns, Cortex AI model tracking, SQL injection detection"
Sleep 300ms
Enter
Sleep 2s

# ── 7. Show 30 MCP server tools ─────────────────────────────────────────────
Type "agent-bom mcp-server --help | head -5 && echo '30 MCP tools | 12 cloud providers | 7 runtime detectors'"
Sleep 300ms
Enter
Sleep 3s

Sleep 2s
