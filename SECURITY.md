# Security Hardening & Best Practices

## Overview

This document covers security measures to protect both **agent-bom users** and the **scanner itself** from potential vulnerabilities and malicious use.

---

## 🛡️ Scanner Security Architecture

### 1. Input Validation & Sanitization

**Threat:** Malicious configuration files could exploit the scanner through code injection

**Mitigations Implemented:**

```python
# src/agent_bom/discovery.py
def load_config(config_path: str) -> dict:
    """Safely load agent configuration files"""

    # 1. Path traversal prevention
    config_path = os.path.realpath(config_path)
    if not config_path.startswith(os.path.expanduser("~/")):
        raise SecurityError("Config file must be in user directory")

    # 2. File size limit (prevent DoS)
    if os.path.getsize(config_path) > 10 * 1024 * 1024:  # 10MB
        raise SecurityError("Config file too large")

    # 3. Safe JSON parsing (no eval, no pickle)
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)  # json.load is safe
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON: {e}")

    # 4. Schema validation
    validate_config_schema(config)

    return config
```

**Additional Input Validation:**

- **Command validation**: Only allow known executables (`npx`, `uvx`, `python`, `node`, etc.)
- **Argument sanitization**: Reject shell metacharacters in arguments (`; | & $ \` ` etc.)
- **Environment variable filtering**: Reject dangerous env vars (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.)
- **URL validation**: Only allow HTTPS for remote package registries
- **Package name validation**: Enforce valid npm/PyPI naming conventions

```python
# Example: Command validation
ALLOWED_COMMANDS = {"npx", "uvx", "python", "python3", "node", "deno"}

def validate_mcp_server(server: dict) -> None:
    """Validate MCP server configuration"""

    # Command must be in allowlist
    command = server.get("command", "")
    if command not in ALLOWED_COMMANDS:
        raise SecurityError(f"Command not allowed: {command}")

    # Args must not contain shell metacharacters
    args = server.get("args", [])
    for arg in args:
        if any(char in arg for char in ";|&$`<>"):
            raise SecurityError(f"Dangerous character in argument: {arg}")

    # Env vars must not be dangerous
    env = server.get("env", {})
    dangerous_vars = {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"}
    if any(var in env for var in dangerous_vars):
        raise SecurityError(f"Dangerous environment variable: {var}")
```

---

### 2. Principle of Least Privilege

**Threat:** Scanner running with excessive permissions could be exploited

**Mitigations:**

#### File System Permissions

```bash
# Run scanner with minimal permissions
chmod 500 $(which agent-bom)  # Read and execute only

# Restrict config directory permissions
chmod 700 ~/.config/Claude
chmod 600 ~/.config/Claude/claude_desktop_config.json
```

#### Docker Isolation

```dockerfile
# Run as non-root user
FROM python:3.11-slim
RUN useradd -m -u 1000 scanner
USER scanner

# Read-only root filesystem
docker run --read-only \
  -v /tmp:/tmp \
  -v ~/.config/Claude:/config:ro \
  agent-bom:latest scan /config
```

#### Linux Capabilities (Drop unnecessary caps)

```bash
# Drop all capabilities except network access
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE agent-bom:latest
```

---

### 3. Sandboxing & Isolation

**Threat:** Malicious MCP server could compromise the scanning environment

**Mitigations:**

#### Process Isolation

```python
# src/agent_bom/resolvers/npm.py
import subprocess

def resolve_npm_package(package: str) -> dict:
    """Resolve npm package with sandboxing"""

    # 1. Timeout to prevent hang
    timeout = 30

    # 2. Limited resources
    # Use subprocess with resource limits
    result = subprocess.run(
        ["npm", "view", package, "--json"],
        capture_output=True,
        timeout=timeout,
        # Prevent subprocess from accessing parent env
        env={"PATH": os.environ["PATH"]},
        # Prevent shell injection
        shell=False,
        # Run in separate process group
        start_new_session=True
    )

    return json.loads(result.stdout)
```

#### Network Isolation

```bash
# Docker with network policies
docker run --network=restricted \
  --dns=8.8.8.8 \
  --add-host=registry.npmjs.org:104.16.0.0 \
  agent-bom:latest
```

#### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-bom-scanner
spec:
  podSelector:
    matchLabels:
      app: agent-bom
  policyTypes:
    - Egress
  egress:
    # Only allow HTTPS to specific registries
    - to:
        - podSelector: {}
      ports:
        - protocol: TCP
          port: 443
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

---

### 4. Secrets & Credential Handling

**Threat:** Scanner could leak credentials from MCP configurations

**Mitigations:**

#### Never Log Secrets

```python
# src/agent_bom/scanner.py
import re

SENSITIVE_PATTERNS = [
    r"token",
    r"password",
    r"secret",
    r"api[_-]?key",
    r"auth",
    r"credential"
]

def sanitize_env_vars(env: dict) -> dict:
    """Remove sensitive values from environment variables"""
    sanitized = {}
    for key, value in env.items():
        if any(re.search(pattern, key.lower()) for pattern in SENSITIVE_PATTERNS):
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized

def log_mcp_server(server: dict) -> None:
    """Log MCP server config without secrets"""
    safe_server = server.copy()
    if "env" in safe_server:
        safe_server["env"] = sanitize_env_vars(safe_server["env"])
    logger.info(f"Scanning MCP server: {safe_server}")
```

#### Credential Detection in Output

```python
# Mark servers with credentials for risk analysis
def analyze_credentials(server: dict) -> dict:
    """Detect credential usage"""
    env_vars = server.get("env", {})

    credential_vars = [
        var for var in env_vars.keys()
        if any(pattern in var.lower() for pattern in SENSITIVE_PATTERNS)
    ]

    return {
        "has_credentials": len(credential_vars) > 0,
        "credential_env_vars": credential_vars,
        # DON'T include values!
    }
```

#### Encrypted Output Option

```bash
# Encrypt output with age
agent-bom scan --format json | age -r age1xxx... > encrypted-sbom.age

# Or GPG
agent-bom scan --format json | gpg --encrypt --recipient security@example.com > sbom.json.gpg
```

---

### 5. API Security & Rate Limiting

**Threat:** Excessive API requests could lead to rate limiting or DoS

**Mitigations:**

#### Rate Limiting

```python
# src/agent_bom/enrichment.py
import time
from collections import deque

class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = deque()

    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()

        # Remove old requests outside window
        while self.requests and self.requests[0] < now - self.window:
            self.requests.popleft()

        # Wait if at limit
        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.window - now
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.requests.popleft()

        self.requests.append(now)

# NVD rate limits: 5 req/30s without key, 50 req/30s with key
nvd_limiter = RateLimiter(max_requests=5, window_seconds=30)

def query_nvd(cve_id: str) -> dict:
    """Query NVD with rate limiting"""
    nvd_limiter.wait_if_needed()

    # Use API key if available (increases limit to 50 req/30s)
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")
        nvd_limiter.max_requests = 50  # Increase limit

    response = httpx.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers=headers,
        timeout=30
    )

    return response.json()
```

#### Caching

```python
# src/agent_bom/cache.py
import hashlib
import json
from pathlib import Path

class Cache:
    """Simple file-based cache"""

    def __init__(self, cache_dir: Path, ttl_seconds: int):
        self.cache_dir = cache_dir
        self.ttl = ttl_seconds
        cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> dict | None:
        """Get cached value if not expired"""
        cache_file = self.cache_dir / self._hash(key)

        if not cache_file.exists():
            return None

        # Check expiry
        if time.time() - cache_file.stat().st_mtime > self.ttl:
            cache_file.unlink()
            return None

        with open(cache_file) as f:
            return json.load(f)

    def set(self, key: str, value: dict):
        """Set cached value"""
        cache_file = self.cache_dir / self._hash(key)
        with open(cache_file, 'w') as f:
            json.dump(value, f)

    def _hash(self, key: str) -> str:
        """Hash key for filename"""
        return hashlib.sha256(key.encode()).hexdigest()

# Cache configuration
nvd_cache = Cache(Path("~/.cache/agent-bom/nvd"), ttl_seconds=86400)  # 24h
kev_cache = Cache(Path("~/.cache/agent-bom/kev"), ttl_seconds=86400)  # 24h
epss_cache = Cache(Path("~/.cache/agent-bom/epss"), ttl_seconds=86400)  # 24h
```

#### Request Timeout & Retry

```python
# src/agent_bom/http.py
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True
)
def fetch_with_retry(url: str, timeout: int = 30) -> httpx.Response:
    """HTTP request with timeout and exponential backoff"""
    try:
        response = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            # Security headers
            headers={
                "User-Agent": "agent-bom/0.1.0 (security-scanner)"
            }
        )
        response.raise_for_status()
        return response
    except httpx.TimeoutException:
        logger.warning(f"Request timeout: {url}")
        raise
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:  # Rate limited
            logger.warning("Rate limited, backing off...")
        raise
```

---

### 6. Supply Chain Security (Scanner Itself)

**Threat:** agent-bom dependencies could have vulnerabilities

**Mitigations:**

#### Minimal Dependencies

```toml
# pyproject.toml - Keep dependencies minimal
[project]
dependencies = [
    "click>=8.0",           # CLI framework
    "rich>=13.0",           # Terminal output
    "httpx>=0.25",          # HTTP client
    "pydantic>=2.0",        # Data validation
    "cyclonedx-python-lib>=7.0",  # SBOM generation
    "packageurl-python>=0.15",    # PURL support
    "toml>=0.10",           # Config parsing
    "pyyaml>=6.0",          # YAML parsing
]
```

#### Pin Dependencies with Hashes

```bash
# Generate requirements with hashes
pip-compile --generate-hashes pyproject.toml -o requirements.txt

# Install with hash verification
pip install --require-hashes -r requirements.txt
```

#### Automated Dependency Scanning

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  push:
    branches: [main]

jobs:
  scan-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Scan agent-bom itself
      - name: Scan scanner dependencies
        run: |
          pip install agent-bom
          agent-bom scan-self --enrich --output scanner-sbom.json

      # Upload to Dependency-Track
      - name: Upload to Dependency-Track
        run: |
          curl -X POST "https://dtrack.company.com/api/v1/bom" \
            -H "X-API-Key: ${{ secrets.DTRACK_API_KEY }}" \
            -F "project=agent-bom" \
            -F "bom=@scanner-sbom.json"

      # Fail if critical vulnerabilities
      - name: Check for critical vulnerabilities
        run: |
          if [ "$(jq '.summary.critical_findings' scanner-sbom.json)" -gt 0 ]; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
```

#### SBOM for agent-bom Itself

```bash
# Generate SBOM for the scanner
pip install pip-audit
pip-audit --format cyclonedx --output agent-bom-scanner.cdx.json
```

#### Code Signing

```bash
# Sign releases with GPG
gpg --armor --detach-sign agent-bom-0.1.0.tar.gz

# Verify
gpg --verify agent-bom-0.1.0.tar.gz.asc agent-bom-0.1.0.tar.gz
```

---

### 7. Output Security

**Threat:** Output files could contain sensitive information or be tampered with

**Mitigations:**

#### File Permission Control

```python
# src/agent_bom/output/writer.py
import os

def write_secure(output_path: str, content: str):
    """Write output with secure permissions"""

    # Create file with restricted permissions (0600 = rw-------)
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    with os.fdopen(fd, 'w') as f:
        f.write(content)

    logger.info(f"Output written to {output_path} (permissions: 0600)")
```

#### Digital Signatures

```python
# Add signature to output
import hashlib
import hmac

def sign_output(content: str, secret_key: str) -> dict:
    """Sign output with HMAC"""
    signature = hmac.new(
        secret_key.encode(),
        content.encode(),
        hashlib.sha256
    ).hexdigest()

    return {
        "content": content,
        "signature": signature,
        "algorithm": "HMAC-SHA256"
    }

def verify_output(signed_output: dict, secret_key: str) -> bool:
    """Verify output signature"""
    expected_sig = hmac.new(
        secret_key.encode(),
        signed_output["content"].encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_sig, signed_output["signature"])
```

---

## 🔄 Vulnerability Data Freshness

### Data Sources & Update Frequency

| Source | Update Frequency | Data Lag | Cache TTL |
|--------|-----------------|----------|-----------|
| **OSV.dev** | Real-time | Minutes | No cache (always fresh) |
| **NVD** | Daily | Hours to days | 24 hours |
| **EPSS** | Daily | 24 hours | 24 hours |
| **CISA KEV** | Weekly | Days | 24 hours |

### OSV.dev (Primary Source)

**How it works:**
- Aggregates data from multiple sources (NVD, GitHub Advisory, PyPI Advisory, etc.)
- Updated in near real-time as new vulnerabilities are published
- No caching - always queries live API for freshness

```python
# Always gets latest data
def query_osv(package: str, version: str) -> list[dict]:
    """Query OSV.dev API (no caching)"""
    response = httpx.post(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"name": package, "ecosystem": "npm"},
            "version": version
        },
        timeout=30
    )
    return response.json().get("vulns", [])
```

**Freshness guarantee:** Within minutes of publication

### NVD (Enhanced Details)

**How it works:**
- Official US government CVE database
- Updated daily but can lag by days/weeks for new CVEs
- Cached for 24 hours to reduce API load

```python
# Cached for 24h
def query_nvd_cached(cve_id: str) -> dict | None:
    """Query NVD with caching"""

    # Check cache first
    cached = nvd_cache.get(cve_id)
    if cached:
        logger.debug(f"NVD cache hit: {cve_id}")
        return cached

    # Query API
    nvd_limiter.wait_if_needed()
    response = httpx.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        timeout=30
    )

    data = response.json()
    nvd_cache.set(cve_id, data)
    return data
```

**Force refresh:**
```bash
# Clear cache to force fresh data
rm -rf ~/.cache/agent-bom/nvd/

# Or use --no-cache flag
agent-bom scan --enrich --no-cache
```

### EPSS (Exploit Prediction)

**How it works:**
- Updated daily at midnight UTC
- Predicts exploitation likelihood based on real-world data
- Cached for 24 hours

```python
def get_epss_score(cve_id: str) -> dict | None:
    """Get EPSS score with daily refresh"""

    # EPSS updates daily, so 24h cache is appropriate
    cached = epss_cache.get(cve_id)
    if cached:
        return cached

    response = httpx.get(
        f"https://api.first.org/data/v1/epss?cve={cve_id}",
        timeout=30
    )

    data = response.json()
    epss_cache.set(cve_id, data)
    return data
```

### CISA KEV (Known Exploited)

**How it works:**
- Updated weekly (usually Thursdays)
- Small dataset (~1000 CVEs), downloaded once
- Cached for 24 hours

```python
def get_kev_catalog() -> dict:
    """Download CISA KEV catalog"""

    # Check cache (24h TTL)
    cached = kev_cache.get("catalog")
    if cached:
        return cached

    response = httpx.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=30
    )

    catalog = response.json()
    kev_cache.set("catalog", catalog)
    return catalog

def is_known_exploited(cve_id: str) -> bool:
    """Check if CVE is in CISA KEV catalog"""
    catalog = get_kev_catalog()
    return any(vuln["cveID"] == cve_id for vuln in catalog["vulnerabilities"])
```

### Ensuring Data Freshness

**1. No-cache mode:**
```bash
agent-bom scan --enrich --no-cache
```

**2. Clear cache manually:**
```bash
# Clear all caches
rm -rf ~/.cache/agent-bom/

# Clear specific source
rm -rf ~/.cache/agent-bom/nvd/
```

**3. Scheduled scans:**
```bash
# Run daily to get latest vulnerabilities
0 2 * * * agent-bom scan --enrich --output /var/log/agent-bom/$(date +\%Y\%m\%d).json
```

**4. Monitor data staleness:**
```python
# Add timestamp to output
{
    "scan_timestamp": "2026-02-17T01:27:12Z",
    "data_sources": {
        "osv": {"cached": false, "query_time": "2026-02-17T01:27:13Z"},
        "nvd": {"cached": true, "cache_time": "2026-02-16T02:00:00Z"},
        "epss": {"cached": true, "cache_time": "2026-02-17T00:00:00Z"},
        "kev": {"cached": true, "cache_time": "2026-02-16T02:00:00Z"}
    }
}
```

---

## 📋 Security Checklist

### For Scanner Deployment

- [ ] Run scanner with minimal file system permissions (0500)
- [ ] Use non-root user in Docker containers
- [ ] Enable read-only root filesystem
- [ ] Implement network policies (restrict to necessary registries)
- [ ] Use API keys for higher rate limits (NVD)
- [ ] Enable output file encryption for sensitive environments
- [ ] Set up automated dependency scanning for agent-bom itself
- [ ] Pin dependencies with hash verification
- [ ] Use code signing for releases
- [ ] Monitor cache freshness (clear old caches)
- [ ] Implement audit logging
- [ ] Set resource limits (CPU, memory, disk)

### For Scanner Users

- [ ] Review configuration files before scanning
- [ ] Run scanner in isolated environment (Docker/VM)
- [ ] Don't commit SBOM files with secrets to version control
- [ ] Encrypt SBOMs if they contain sensitive architecture details
- [ ] Set up alerts for critical vulnerabilities
- [ ] Schedule regular scans (daily/weekly)
- [ ] Integrate with vulnerability management platform
- [ ] Review and validate scan results
- [ ] Update agent-bom regularly
- [ ] Use `--transitive` flag for complete dependency analysis

---

## 🚨 Incident Response

### If Scanner is Compromised

1. **Isolate**: Stop scanner, disconnect from network
2. **Investigate**: Review logs, check for unauthorized access
3. **Remediate**: Update agent-bom, rotate API keys, clear caches
4. **Verify**: Re-scan with clean installation
5. **Monitor**: Watch for unusual activity

### If Vulnerabilities Found in Scanner

1. **Assess**: Check severity and exploitability
2. **Update**: `pip install --upgrade agent-bom`
3. **Verify**: Scan scanner itself with `agent-bom scan-self`
4. **Document**: Record incident and remediation

---

## 📞 Security Contact

**Report security vulnerabilities:**
- Email: crewnycgiving@gmail.com
- GitHub Security Advisory: https://github.com/agent-bom/agent-bom/security/advisories/new

**Please do not open public issues for security vulnerabilities.**

---

**Last updated:** 2026-02-17
**Document version:** 1.0
