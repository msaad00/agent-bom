# agent-bom demo — run with: vhs docs/demo.tape
#
# Install vhs:  brew install vhs
# Prereqs (run in a CLEAN venv to avoid ModuleNotFoundError):
#   python -m venv /tmp/abom-demo && source /tmp/abom-demo/bin/activate
#   pip install agent-bom
#   Verify: agent-bom --version  (must show no errors)
#
# IMPORTANT: Run every command manually BEFORE recording to verify success.
# A demo with errors is worse than no demo.

# Output filename — update README.md img src to match after recording
Output docs/images/demo-v0.71.0.gif

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 800
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

# ── 0. Version ────────────────────────────────────────────────────────────────
Type "agent-bom --version"
Enter
Sleep 3s

# ── 1. Pre-install guard — catch CVEs before they land ────────────────────────
Type "agent-bom check django@3.2.0 --ecosystem pypi"
Enter
Sleep 8s

Type "agent-bom check lodash@4.17.20 --ecosystem npm"
Enter
Sleep 6s

# ── 2. Full scan — discovery + vuln scan + blast radius ───────────────────────
Type "cd /tmp && agent-bom scan --demo -p /tmp"
Enter
Sleep 18s

# ── 3. Output formats — SARIF for GitHub Security tab ─────────────────────────
Type "agent-bom scan --demo -p /tmp -f sarif -o /tmp/results.sarif -q && echo '✓ SARIF written to /tmp/results.sarif'"
Enter
Sleep 8s

# ── 4. Focused commands — fs, cloud, proxy ────────────────────────────────────
Type "agent-bom fs --help | head -8"
Enter
Sleep 4s

Type "agent-bom proxy --help | head -12"
Enter
Sleep 5s

Sleep 1s
