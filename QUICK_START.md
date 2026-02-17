# Quick Start: Try agent-bom in 60 Seconds

**TL;DR:** Find vulnerabilities in your AI agents and MCP servers in under a minute.

---

## ⚡ Super Quick Start (30 seconds)

```bash
# Install
pip install agent-bom

# Scan everything
agent-bom scan --transitive

# Done! ✅
```

**What it does:**
- 🔍 Discovers Claude Desktop, Cursor, and other AI agents on your machine
- 📦 Finds all MCP servers and their dependencies (including hidden nested packages)
- 🛡️ Scans for vulnerabilities
- 💥 Shows which agents are affected

---

## 📋 What You'll See

```
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  AI Bill of Materials for Agents & MCP Servers


🔍 Discovering MCP configurations...

  ✓ Found claude-desktop with 3 MCP server(s)
  ✓ Found cursor with 2 MCP server(s)

  Found 2 agent(s) with 5 MCP server(s) total.

📦 Extracting package dependencies...

  Transitive dependency resolution enabled (max depth: 5)

  ✓ filesystem: 1 package(s) (npm)
  → Resolving transitive dependencies for github (depth=5)...
  ✓ Found 34 transitive dependencies
  ✓ github: 35 package(s) (npm) (34 transitive)
  ✓ slack: 15 package(s) (npm) (14 transitive)

  Extracted 724 total packages.

🛡️  Scanning for vulnerabilities...

  ⚠️  Found 12 vulnerabilities (3 HIGH, 9 MEDIUM)


💥 Blast Radius Analysis

                           Vulnerability Impact Chain
┏━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━┳━━━━━━━━┓
┃  ┃ Vuln ID        ┃ Package             ┃ Sever… ┃ Agen…┃ Ser…┃ Cre…┃ Fix    ┃
┡━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━╇━━━━━━━━┩
│  │ GHSA-8r9q-7v3…│ @modelcontextproto… │ high   │ 2    │ 2   │ yes │ 3.0.1  │
│  │ GHSA-w48q-cv7…│ @modelcontextproto… │ medium │ 2    │ 2   │ yes │ 3.0.1  │
│  │ GHSA-fjxv-7rq…│ form-data@4.0.0     │ medium │ 1    │ 1   │ no  │ 4.0.1  │
└──┴────────────────┴─────────────────────┴────────┴──────┴─────┴─────┴────────┘

  ...and 9 more findings.


╭────────────────────────────────────╮
│ AI-BOM Report                      │
│ Generated: 2026-02-17 10:30:15 UTC │
│ agent-bom v0.1.0                   │
╰────────────────────────────────────╯
  Agents discovered    2
  MCP servers          5
  Total packages       724
  Vulnerabilities      12
  Critical findings    3
```

---

## 🎯 What This Means

**Without `--transitive`:** Would only find 5 packages, miss 719 packages (and their vulnerabilities!)

**With `--transitive`:** Finds ALL 724 packages including nested dependencies where vulnerabilities hide.

**👉 Always use `--transitive` for security scans!**

---

## 📊 Full Report Options

### Get JSON Output
```bash
agent-bom scan --transitive --format json --output report.json
```

### Get Industry Standard SBOM
```bash
agent-bom scan --transitive --format cyclonedx --output sbom.cdx.json
```

### Get Full Security Details (CVSS, EPSS, KEV)
```bash
agent-bom scan --transitive --enrich
```

**What enrichment adds:**
- CVSS scores (severity ratings)
- EPSS scores (exploitation probability)
- CISA KEV status (known exploited vulnerabilities)
- CWE categories
- Fix versions
- Remediation advice

---

## 🚀 Advanced Usage

### Block Deployment if Critical Vulnerabilities Found
```bash
agent-bom scan --transitive --fail-on critical

# Exit code 1 if critical vulnerabilities found
# Use in CI/CD pipelines
```

### Scan Specific Directory
```bash
agent-bom scan --config-dir /path/to/agent/configs --transitive
```

### Set Depth Limit (Faster, Less Thorough)
```bash
# Depth 3 is 95% coverage in 20 seconds
agent-bom scan --transitive --max-depth 3

# Depth 5 is 100% coverage in 45 seconds (recommended)
agent-bom scan --transitive --max-depth 5
```

---

## 🔄 Set Up Automated Scanning

### Daily Scans (macOS/Linux)
```bash
# Add to crontab
crontab -e

# Add this line (runs daily at 2 AM):
0 2 * * * agent-bom scan --transitive --enrich --output ~/scans/$(date +\%Y\%m\%d).json
```

### Get Notified of Critical Issues
```bash
#!/bin/bash
# ~/bin/scan-with-alerts.sh

agent-bom scan --transitive --enrich --format json --output /tmp/scan.json

CRITICAL=$(jq '.summary.critical_findings' /tmp/scan.json)
if [ "$CRITICAL" -gt 0 ]; then
    # macOS notification
    osascript -e "display notification \"$CRITICAL critical vulnerabilities found!\" with title \"AI Security Alert\""

    # Or send email
    echo "Critical vulnerabilities found in AI agents" | mail -s "Security Alert" you@example.com
fi
```

Make it executable:
```bash
chmod +x ~/bin/scan-with-alerts.sh

# Add to crontab
0 2 * * * ~/bin/scan-with-alerts.sh
```

---

## 🐳 Docker Usage (Isolated Environment)

```bash
# Run in Docker (no installation on host)
docker run --rm \
  -v ~/.config/Claude:/config:ro \
  -v $(pwd)/output:/output \
  ghcr.io/agent-bom/agent-bom:latest scan \
    --transitive \
    --enrich \
    --format cyclonedx \
    --output /output/sbom.cdx.json
```

---

## 📖 Examples for Different Scenarios

### Scenario 1: "I just want to know if I'm vulnerable"
```bash
agent-bom scan --transitive
```
**Time:** 45 seconds

---

### Scenario 2: "I need a compliance report for my manager"
```bash
agent-bom scan --transitive --enrich --format cyclonedx --output compliance-report.cdx.json
```
**Time:** 60 seconds
**Output:** Industry-standard SBOM file you can send to auditors

---

### Scenario 3: "I'm deploying to production and need to check first"
```bash
# Check for critical vulnerabilities
agent-bom scan --transitive --fail-on high

if [ $? -eq 0 ]; then
    echo "✅ Safe to deploy"
    ./deploy.sh
else
    echo "❌ Blocked: High/Critical vulnerabilities found"
    exit 1
fi
```
**Time:** 45 seconds
**Benefit:** Prevents vulnerable code from reaching production

---

### Scenario 4: "I want to track vulnerabilities over time"
```bash
# Daily scans with timestamped results
agent-bom scan --transitive --enrich --output ~/scans/$(date +%Y%m%d).json

# Compare with last week
diff <(jq '.summary' ~/scans/20260210.json) <(jq '.summary' ~/scans/20260217.json)
```
**Benefit:** See if vulnerabilities increase/decrease over time

---

## 🤝 Share with Your Team

### Send This to Your Team

```
Hey team! 👋

Check out agent-bom - it scans our AI agents for vulnerabilities:

1. Install: pip install agent-bom
2. Scan: agent-bom scan --transitive
3. Done!

Takes 45 seconds, finds hidden vulnerabilities in MCP servers.

Docs: https://github.com/agent-bom/agent-bom
```

---

## 🆘 Troubleshooting

### "No agents found"
**Cause:** agent-bom looks in standard config locations

**Solution:**
```bash
# Check where your configs are
ls -la ~/.config/Claude/
ls -la ~/.cursor/

# Specify custom location
agent-bom scan --config-dir /path/to/your/configs --transitive
```

---

### "Scan is slow"
**Cause:** Deep transitive scanning takes time

**Solution:**
```bash
# Use lower depth for faster scans (trades thoroughness for speed)
agent-bom scan --transitive --max-depth 3  # 20 seconds, 95% coverage

# Or disable transitive for quick check (not recommended for security)
agent-bom scan  # 5 seconds, only direct dependencies
```

---

### "Too many vulnerabilities!"
**Focus on high/critical first:**
```bash
# Show only high/critical
agent-bom scan --transitive --enrich | grep -E "high|critical"

# Or save to file and sort
agent-bom scan --transitive --format json --output report.json
jq '.agents[].mcp_servers[].packages[].vulnerabilities[] | select(.severity == "high" or .severity == "critical")' report.json
```

---

## 📚 Learn More

- **Full Documentation:** [README.md](README.md)
- **Use Cases:** [USE_CASES.md](USE_CASES.md) - Enterprise AWS/K8s examples
- **Deployment:** [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment guides
- **Security:** [SECURITY.md](SECURITY.md) - Security hardening best practices
- **Understanding Transitive Dependencies:** [TRANSITIVE_DEPENDENCIES.md](TRANSITIVE_DEPENDENCIES.md)

---

## 💬 Get Help

- **GitHub Issues:** https://github.com/agent-bom/agent-bom/issues
- **Discussions:** https://github.com/agent-bom/agent-bom/discussions
- **Email:** andwgdysaad@gmail.com

---

## ⭐ Show Support

If agent-bom helped you, give us a star on GitHub!

```bash
# Open in browser
open https://github.com/agent-bom/agent-bom
```

---

**That's it!** You're now scanning your AI agents for vulnerabilities. 🎉

**Recommended next step:** Set up daily automated scans (scroll up to "Set Up Automated Scanning")
