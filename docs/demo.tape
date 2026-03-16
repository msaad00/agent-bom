# agent-bom demo — run with: vhs docs/demo.tape
#
# Install vhs:  brew install vhs
# Prereqs (run in a CLEAN venv to avoid ModuleNotFoundError):
#   python -m venv /tmp/abom-demo && source /tmp/abom-demo/bin/activate
#   pip install agent-bom
#   Verify: agent-bom --version  (must show no errors)
#   Stage scans before recording:
#     agent-bom scan --demo -f json -o /tmp/baseline.json
#     agent-bom scan --demo -f json -o /tmp/current.json
# Optional (GPU scene — requires Docker):
#   docker run -d --name nim-demo \
#     --label com.nvidia.cuda.version=12.4.0 \
#     --label com.nvidia.nim.model=meta/llama-3.1-8b-instruct \
#     node:20-slim sleep 3600
#
# IMPORTANT: Run every command manually BEFORE recording to verify success.
# A demo with errors is worse than no demo.

# Output filename — update README.md img src to match after recording
Output docs/images/demo-v0.70.12.gif

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 800
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# ── 0. Version ────────────────────────────────────────────────────────────────
Type "agent-bom --version"
Enter
Sleep 3s

# ── 1. CLI overview ───────────────────────────────────────────────────────────
Type "agent-bom scan --help | head -30"
Enter
Sleep 5s

# ── 2. Pre-install guard — catch CVEs before they land ────────────────────────
Type "agent-bom check django@3.2.0 --ecosystem pypi"
Enter
Sleep 6s

Type "agent-bom check lodash@4.17.20 --ecosystem npm"
Enter
Sleep 6s

# ── 4. Full scan — progress bar + timing breakdown + next-steps ───────────────
Type "agent-bom scan --demo --enrich"
Enter
Sleep 20s

# ── 5. AI component detection — SDK imports, shadow AI, deprecated models ─────
Type "agent-bom scan --demo --ai-inventory ."
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
Type "agent-bom scan --demo --gpu-scan -q"
Enter
Sleep 18s

# ── 9. Output formats — SARIF, CycloneDX SBOM ─────────────────────────────
Type "agent-bom scan --demo -f sarif -o /tmp/results.sarif -q && echo 'SARIF written'"
Enter
Sleep 8s

Type "agent-bom scan --demo -f cyclonedx -o /tmp/bom.cdx.json -q && echo 'CycloneDX SBOM written'"
Enter
Sleep 8s

# ── 10. Runtime proxy — intercept live MCP traffic ───────────────────────────
Type "agent-bom proxy --help | head -18"
Enter
Sleep 4s

# ── 11. What you get ──────────────────────────────────────────────────────────
Type "echo '32 MCP tools  |  22 MCP client types  |  11 ecosystems  |  7 runtime detectors'"
Enter
Sleep 2s
Type "echo '14 compliance frameworks  |  5 cloud + 7 AI platforms  |  CVE canonical dedup'"
Enter
Sleep 2s
Type "echo 'Native scanning (no Grype/Syft required)  |  VM snapshot MCP discovery'"
Enter
Sleep 3s

Sleep 1s
