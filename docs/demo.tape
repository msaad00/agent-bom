# agent-bom v0.74.0 demo — run with: vhs docs/demo.tape
#
# Story: Engineer discovers their AI agents have vulnerable dependencies,
# checks a package before installing, then exports an AI BOM for compliance.
#
# Flow: Discover → Scan → Gate → Export
# All output is real — --demo uses bundled inventory, no mocked data.

Output docs/images/demo-v0.74.0.gif

Set Shell "bash"
Set FontSize 18
Set Width 1800
Set Height 1000
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# Setup: clean prompt, no personal paths
Hide
Type "export PS1='$ ' && export PATH=/opt/homebrew/Caskroom/miniconda/base/bin:$PATH && mkdir -p /tmp/demo && cd /tmp/demo && clear"
Enter
Sleep 1s
Show

# ── Step 1: Discover and scan AI agents — the core value proposition ─────────
# Shows: agents found, CVEs, blast radius, remediation plan
Type "# Step 1: Scan AI agents — discover CVEs and blast radius"
Enter
Sleep 1s
Type "agent-bom agents --demo --quiet"
Enter
Sleep 14s

# ── Step 2: Pre-install CVE gate — fast, actionable ─────────────────────────
# Shows: CRITICAL CVE found with fix version
Type "# Step 2: Pre-install CVE gate"
Enter
Sleep 1s
Type "agent-bom check flask@2.0.0"
Enter
Sleep 5s

# ── Step 3: Export AI BOM for compliance ────────────────────────────────────
# Shows: CycloneDX 1.6 with ML extensions
Type "# Step 3: Export AI BOM (CycloneDX 1.6 with ML extensions)"
Enter
Sleep 1s
Type "agent-bom agents --demo -f cyclonedx -o ai-bom.json --quiet && head -20 ai-bom.json"
Enter
Sleep 10s

Sleep 2s
