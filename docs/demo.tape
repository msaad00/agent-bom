# agent-bom v0.74.0 demo — run with: vhs docs/demo.tape
#
# Shows the full blast radius chain: agent → server → tools → packages → CVEs → credentials
# All output is real — --demo uses bundled inventory, no mocked data.

Output docs/images/demo-v0.74.0.gif

Set Shell "bash"
Set FontSize 16
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 2.0

# Setup: clean prompt
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && mkdir -p /tmp/demo && cd /tmp/demo && clear"
Enter
Sleep 1s
Show

# Full scan with dependency tree — the core value
Type "agent-bom agents --demo --verbose"
Enter
Sleep 35s

Sleep 2s
