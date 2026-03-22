# agent-bom v0.74.1 demo — run with: vhs docs/demo.tape
#
# Shows: blast radius chain, ecosystem coverage, severity source,
# pre-install CVE check, supply chain provenance verification.
# All output is real — --demo uses bundled inventory, no personal data.
#
# IMPORTANT: No personal paths, configs, or credentials appear in output.
# --demo mode uses temp dirs with clean display paths.
#
# Prerequisites: pip install -e . (or uv tool upgrade agent-bom)

Output docs/images/demo-v0.74.1.gif

Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 2.0

# Setup: clean prompt, alias to correct python, no personal paths visible
Hide
Type "export PS1='\\[\\033[1;36m\\]agent-bom\\[\\033[0m\\] $ ' && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 2s

# 2. Full scan — blast radius, severity source, ecosystem coverage
Type "agent-bom agents --demo"
Enter
Sleep 30s

Sleep 2s

# 3. Pre-install check — quick CVE gate (public package, no personal data)
Type "agent-bom check lodash@4.17.20"
Enter
Sleep 8s

Sleep 1s

# 4. Verify supply chain provenance (public package, no personal data)
Type "agent-bom verify flask"
Enter
Sleep 8s

Sleep 2s
