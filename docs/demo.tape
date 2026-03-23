# agent-bom v0.75.3 demo — run with: vhs docs/demo.tape
#
# HIGH RES, READABLE. Large font, focused output.
# No personal paths, configs, or credentials.

Output docs/images/demo-v0.75.3.gif

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 800
Set Theme "Dracula"
Set Padding 30
Set TypingSpeed 25ms
Set PlaybackSpeed 1.5

# Setup
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 2s

# 2. Doctor — preflight check
Type "agent-bom doctor"
Enter
Sleep 4s

# 3. Posture summary — quick workstation risk
Type "agent-bom agents --demo --posture"
Enter
Sleep 20s

# 4. Pre-install CVE gate
Type "agent-bom check requests==2.28.0"
Enter
Sleep 10s

Sleep 3s
