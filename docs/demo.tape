# agent-bom v0.74.1 demo — run with: vhs docs/demo.tape
#
# Prerequisites:
#   pip install -e .   (installs agent-bom from source into current env)
#
# No personal paths, configs, or credentials appear in output.

Output docs/images/demo-v0.74.1.gif

Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 1.5

# Setup: clean prompt, ensure conda agent-bom (v0.74.1) is first in PATH
Hide
Type "export PS1='agent-bom $ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 3s

# 2. Full scan — blast radius, severity source, ecosystem coverage
Type "agent-bom agents --demo"
Enter
Sleep 35s

Sleep 2s

# 3. Pre-install check — quick CVE gate
Type "agent-bom check lodash@4.17.20"
Enter
Sleep 10s

Sleep 1s

# 4. Verify supply chain provenance
Type "agent-bom verify flask"
Enter
Sleep 10s

Sleep 3s
