# agent-bom v0.63.0 demo — run with: vhs docs/demo.tape
# Install vhs: brew install vhs  (or https://github.com/charmbracelet/vhs)
# Prereqs:
#   pip install agent-bom
#   docker running (for --gpu-scan section)
#   Run before recording: docker run -d --name gpu-demo \
#     --label com.nvidia.cuda.version=12.3.0 \
#     node:18-slim sleep 3600

Output docs/images/demo-v0.63.0.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 1.2

# ── 1. Auto-discover your MCP setup ─────────────────────────────────────────
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
# (requires Docker running with: docker run -d --name gpu-demo \
#   --label com.nvidia.cuda.version=12.3.0 node:18-slim sleep 3600)
Type "agent-bom scan --gpu-scan"
Sleep 300ms
Enter
Sleep 12s

# ── 5. Show 23 MCP server tools ──────────────────────────────────────────────
Type "agent-bom mcp-server --help | grep -E '^\s{6}\w' | head -25"
Sleep 300ms
Enter
Sleep 3s

Sleep 2s
