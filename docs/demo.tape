# agent-bom v0.74.0 demo — run with: vhs docs/demo.tape
#
# Shows: agent discovery → blast radius with agents/servers/creds → CVE gate
# All output is real — --demo uses bundled inventory, no mocked data.

Output docs/images/demo-v0.74.0.gif

Set Shell "bash"
Set FontSize 18
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 40ms
Set PlaybackSpeed 1.5

# Setup: clean prompt, no personal paths
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && mkdir -p /tmp/demo && cd /tmp/demo && clear"
Enter
Sleep 1s
Show

# ── Full scan — shows agents, servers, packages, CVEs, blast radius ──────────
Type "agent-bom agents --demo"
Enter
Sleep 30s

# ── Pre-install CVE gate ─────────────────────────────────────────────────────
Type "agent-bom check flask@2.0.0"
Enter
Sleep 6s

Sleep 2s
