# agent-bom v0.75.9 demo — run with: vhs docs/demo.tape
#
# HIGH RES, READABLE. Large font, focused output.
# No personal paths, configs, or credentials.

Output docs/images/demo-latest.gif

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
Type ". scripts/demo-env.sh"
Enter
Type "clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "agent-bom --version"
Enter
Sleep 2s

# 2. Posture summary — quick workstation risk
Type "agent-bom agents --demo --posture --offline"
Enter
Sleep 9s

# 3. Pre-install CVE gate
Type "agent-bom check pillow@9.0.0 --ecosystem pypi"
Enter
Sleep 6s

Sleep 3s
