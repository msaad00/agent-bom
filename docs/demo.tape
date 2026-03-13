# agent-bom v0.70.7 demo — run with: vhs docs/demo.tape
#
# Install vhs:  brew install vhs
# Prereqs:
#   pip install agent-bom==0.70.7
#   Stage scans before recording:
#     agent-bom scan --demo -f json -o /tmp/baseline.json
#     agent-bom scan --demo -f json -o /tmp/current.json
# Optional (GPU scene — requires Docker):
#   docker run -d --name nim-demo \
#     --label com.nvidia.cuda.version=12.4.0 \
#     --label com.nvidia.nim.model=meta/llama-3.1-8b-instruct \
#     node:20-slim sleep 3600

Output docs/images/demo-v0.70.7.gif

Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# ── 0. Version ────────────────────────────────────────────────────────────────
Type "agent-bom --version"
Enter
Sleep 3s

# ── 1. CLI overview ───────────────────────────────────────────────────────────
Type "agent-bom --help"
Enter
Sleep 5s

# ── 2. Instant discovery — no CVE scan, just what's there ─────────────────────
Type "agent-bom inventory"
Enter
Sleep 8s

# ── 3. Pre-install guard — catch CVEs before they land ────────────────────────
Type "agent-bom check lodash@4.17.20 --ecosystem npm"
Enter
Sleep 6s

Type "agent-bom check lodash@4.17.23 --ecosystem npm"
Enter
Sleep 4s

# ── 4. Full scan — progress bar + timing breakdown + next-steps ───────────────
Type "agent-bom scan --demo --enrich"
Enter
Sleep 20s

# ── 5. AI component detection — SDK imports, shadow AI, deprecated models ─────
Type "agent-bom scan --demo --ai-inventory"
Enter
Sleep 14s

# ── 6. Two-tier CI gate — warn on high, fail on critical ──────────────────────
Type "agent-bom scan --demo --warn-on high --fail-on-severity critical"
Enter
Sleep 14s

# ── 7. Delta mode — only new findings since baseline ──────────────────────────
Type "agent-bom diff /tmp/baseline.json /tmp/current.json"
Enter
Sleep 6s

# ── 8. GPU / AI compute infra — NIM containers, CUDA CVEs ───────────────────
Type "agent-bom scan --gpu-scan -q"
Enter
Sleep 18s

# ── 9. Output formats — SARIF, CycloneDX SBOM, HTML ─────────────────────────
Type "agent-bom scan --demo -f sarif -o /tmp/results.sarif -q && echo 'SARIF written → GitHub/GitLab Security tab'"
Enter
Sleep 10s

Type "agent-bom scan --demo -f cyclonedx -o /tmp/bom.cdx.json -q && echo 'CycloneDX SBOM written → compliance / procurement'"
Enter
Sleep 10s

Type "agent-bom scan --demo -f html -o /tmp/report.html -q && echo 'HTML report written'"
Enter
Sleep 8s

# ── 10. Runtime proxy — intercept live MCP traffic ───────────────────────────
Type "agent-bom proxy --help | head -18"
Enter
Sleep 4s

# ── 11. What you get ──────────────────────────────────────────────────────────
Type "echo '32 MCP tools  |  22 MCP client types  |  12 cloud providers  |  7 runtime detectors'"
Enter
Sleep 2s
Type "echo '11 compliance frameworks  |  delta scanning  |  local SQLite DB  |  Trivy/Grype ingestion'"
Enter
Sleep 2s
Type "echo 'AI component detection  |  progress bar + timing  |  DeepSeek + GlassWorm defense'"
Enter
Sleep 3s

Sleep 1s
