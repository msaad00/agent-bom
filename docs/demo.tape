# agent-bom v0.74.1 demo — run with: vhs docs/demo.tape
#
# Shows: blast radius chain, ecosystem coverage, severity source,
# provenance verification, compliance tagging, IaC scanning.
# All output is real — --demo uses bundled inventory, no mocked data.

Output docs/images/demo-v0.74.1.gif

Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 2.0

# Setup: clean prompt
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && mkdir -p /tmp/demo && cd /tmp/demo && clear"
Enter
Sleep 1s
Show

# 1. Full scan — the core value (blast radius, severity source, ecosystem skips)
Type "agent-bom agents --demo --verbose"
Enter
Sleep 35s

Sleep 2s

# 2. Pre-install check — quick CVE gate
Type "agent-bom check lodash@4.17.20"
Enter
Sleep 8s

Sleep 1s

# 3. IaC scan — 138 rules across 5 formats
Type "agent-bom iac --demo"
Enter
Sleep 10s

Sleep 1s

# 4. Verify supply chain provenance
Type "agent-bom verify agent-bom"
Enter
Sleep 8s

Sleep 2s
