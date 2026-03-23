# agent-bom v0.75.0 demo — run with: vhs docs/demo.tape
#
# Shows the full product surface with real output.
# No personal paths, configs, or credentials in output.

Output docs/images/demo-v0.75.0.gif

Set Shell "bash"
Set FontSize 14
Set Width 2200
Set Height 1100
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 30ms
Set PlaybackSpeed 1.5

# Setup
Hide
Type "export PS1='agent-bom $ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && export COLUMNS=200 && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 2s

# 2. Doctor — preflight check (NEW in v0.75.0)
Type "agent-bom doctor"
Enter
Sleep 3s

# 3. Posture summary — 5-line workstation risk (NEW in v0.75.0)
Type "agent-bom agents --demo --posture"
Enter
Sleep 15s
Sleep 1s

# 4. Full agent scan with blast radius
Type "agent-bom agents --demo"
Enter
Sleep 35s
Sleep 2s

# 5. Container image scan (native, no external tools)
Type "agent-bom image python:3.12-slim"
Enter
Sleep 15s
Sleep 1s

# 6. Pre-install CVE gate
Type "agent-bom check lodash@4.17.20"
Enter
Sleep 8s

Sleep 3s
