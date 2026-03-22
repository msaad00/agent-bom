# agent-bom v0.74.1 demo — run with: vhs docs/demo.tape
#
# Shows the full product surface:
#   1. Agent + MCP discovery with blast radius
#   2. Container image scan
#   3. AI BOM generation (CycloneDX 1.6)
#   4. Pre-install CVE gate
#   5. Supply chain provenance verification
#
# No personal paths, configs, or credentials in output.

Output docs/images/demo-v0.74.1.gif

Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 30ms
Set PlaybackSpeed 1.5

# Setup
Hide
Type "export PS1='agent-bom $ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 2s

# 2. Agent + MCP discovery → CVEs → blast radius → remediation
Type "agent-bom agents --demo"
Enter
Sleep 35s
Sleep 2s

# 3. Container image scan
Type "agent-bom image python:3.12-slim --no-color"
Enter
Sleep 15s
Sleep 1s

# 4. Generate AI BOM (CycloneDX 1.6 with ML extensions)
Type "agent-bom agents --demo -f cyclonedx -o ai-bom.cdx.json --quiet && head -30 ai-bom.cdx.json"
Enter
Sleep 12s
Sleep 1s

# 5. Pre-install CVE gate
Type "agent-bom check lodash@4.17.20"
Enter
Sleep 8s
Sleep 1s

# 6. Supply chain provenance
Type "agent-bom verify flask"
Enter
Sleep 8s

Sleep 3s
