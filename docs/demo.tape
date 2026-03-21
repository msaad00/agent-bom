# agent-bom v0.74.0 demo — run with: vhs docs/demo.tape
#
# 3 hero commands that show what agent-bom does:
# 1. agents --demo  → discovery + blast radius + remediation (the core value)
# 2. check          → pre-install CVE gate (finds CRITICAL CVE)
# 3. agents -f cyclonedx → AI BOM export with ML extensions
#
# All output is real — --demo uses bundled inventory, no mocked data.

Output docs/images/demo-v0.74.0.gif

Set Shell "bash"
Set FontSize 18
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0

# Setup: correct binary, clean prompt, no personal paths
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && mkdir -p /tmp/abom-demo && cd /tmp/abom-demo && clear"
Enter
Sleep 1s
Show

# ── Hero 1: Full scan — blast radius mapping (the core product) ──────────────
Type "agent-bom agents --demo"
Enter
Sleep 22s

# ── Hero 2: Pre-install CVE gate — finds CRITICAL + fix version ──────────────
Type "agent-bom check flask@2.0.0"
Enter
Sleep 8s

# ── Hero 3: AI BOM export — CycloneDX with MCP tool capabilities ────────────
Type "agent-bom agents --demo -f cyclonedx -o sbom.json -q && echo '✓ AI BOM exported' && head -25 sbom.json"
Enter
Sleep 6s

Sleep 2s
