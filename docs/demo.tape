# agent-bom v0.75.5 demo — run with: vhs docs/demo.tape
#
# HIGH RES, READABLE. Large font, focused output.
# No personal paths, configs, or credentials.

Output docs/images/demo-v0.75.5.gif

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
Type "export PS1='$ ' && mkdir -p /tmp/agent-bom-demo && cp /Users/mohamedsaad/.agent-bom/db/vulns.db /tmp/agent-bom-demo/vulns.db && alias abdemo='docker run --rm -e AGENT_BOM_DB_PATH=/tmp/vulns.db -v /tmp/agent-bom-demo/vulns.db:/tmp/vulns.db:ro agent-bom:release-alpine-test' && clear"
Enter
Sleep 500ms
Show

# 1. Version
Type "abdemo --version"
Enter
Sleep 2s

# 2. Quick agent and MCP scan
Type "abdemo agents --demo --offline"
Enter
Sleep 14s

# 3. Posture summary — quick workstation risk
Type "abdemo agents --demo --posture --offline"
Enter
Sleep 12s

# 4. Pre-install CVE gate
Type "abdemo check requests==2.28.0 --ecosystem pypi"
Enter
Sleep 9s

Sleep 3s
