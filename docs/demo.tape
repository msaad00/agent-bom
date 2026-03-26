# agent-bom v0.75.7 demo — run with: vhs docs/demo.tape
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
Type "export PS1='$ ' && mkdir -p /tmp/agent-bom-demo && cp \"$HOME/.agent-bom/db/vulns.db\" /tmp/agent-bom-demo/vulns.db && alias abdemo='docker run --rm -e AGENT_BOM_DB_PATH=/tmp/vulns.db -v /tmp/agent-bom-demo/vulns.db:/tmp/vulns.db:ro agent-bom:release-alpine-test' && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "abdemo --version"
Enter
Sleep 2s

# 2. Posture summary — quick workstation risk
Type "abdemo agents --demo --posture --offline"
Enter
Sleep 9s

# 3. Pre-install CVE gate
Type "abdemo check flask==2.2.0 --ecosystem pypi"
Enter
Sleep 6s

Sleep 3s
