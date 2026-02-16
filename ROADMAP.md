# Roadmap

**agent-bom** development roadmap with planned features and timelines.

---

## v0.1.0 - Foundation ✅ **(Current Release)**

**Focus**: Core CLI functionality for local MCP server scanning

- ✅ Auto-discovery of MCP client configs (Claude Desktop, Cursor, Windsurf, etc.)
- ✅ Package extraction from lock files (npm, pip, Go, Cargo)
- ✅ npx/uvx package detection
- ✅ Transitive dependency resolution (npm, PyPI)
- ✅ OSV.dev vulnerability scanning
- ✅ Blast radius analysis
- ✅ Console, JSON, and CycloneDX 1.6 output
- ✅ Credential detection in MCP server env vars

---

## v0.2.0 - Enhanced Discovery **(Next Release)**

**Focus**: Expand platform support and improve accuracy

**Target**: Q2 2025

### Features
- [ ] **Snowflake Cortex Agent Detection**
  - Scan Snowflake accounts for Cortex agents
  - Parse agent configurations from Snowflake
  - Extract dependencies from Cortex agent packages

- [ ] **Improved Version Resolution**
  - Semver range resolution for npm (use `semver` library)
  - PEP 440 version specifier support for PyPI
  - Resolve `^`, `~`, `>=` version ranges accurately

- [ ] **Container Image Scanning**
  - Extract packages from Docker images used by MCP servers
  - Support for `FROM` base image analysis
  - Layer-by-layer dependency extraction

- [ ] **Go Module Improvements**
  - Parse `go.mod` in addition to `go.sum`
  - Distinguish direct vs transitive deps
  - Handle replace directives

- [ ] **Configuration Profiles**
  - Save scan settings (depth, timeout, filters)
  - Reusable profiles for different environments
  - `.agent-bom.yaml` config file support

---

## v0.3.0 - Vulnerability Intelligence

**Focus**: Deeper vulnerability analysis and enrichment

**Target**: Q3 2025

### Features
- [ ] **NVD API Integration**
  - Query NIST NVD for additional CVE data
  - Enrich with CWE mappings
  - Cross-reference with OSV data

- [ ] **EPSS Scores**
  - Add EPSS (Exploit Prediction Scoring System) data
  - Prioritize vulnerabilities by exploit likelihood
  - Show trending CVEs

- [ ] **CISA KEV**
  - Flag Known Exploited Vulnerabilities from CISA
  - Highlight actively exploited CVEs
  - Compliance reporting for KEV tracking

- [ ] **GitHub Advisory Integration**
  - Direct queries to GitHub Security Advisory API
  - Language-specific advisory tracking
  - Dependabot compatibility

- [ ] **License Compliance**
  - Extract package licenses
  - Flag incompatible license combinations
  - SPDX license identifier support

- [ ] **Vulnerability Deduplication**
  - Merge aliases (GHSA-xxx → CVE-xxx)
  - Single record per unique vulnerability
  - Track all identifiers

---

## v0.4.0 - Security Analysis

**Focus**: Advanced threat modeling and risk analysis

**Target**: Q4 2025

### Features
- [ ] **Role & Privilege Mapping**
  - Parse MCP server tool definitions
  - Map tools to data access patterns (read/write/delete)
  - Identify privilege escalation paths

- [ ] **Data Sensitivity Analysis**
  - Detect PII access (email, SSN, credit cards)
  - Flag HIPAA/GDPR/PCI-relevant agents
  - Classify data by sensitivity level

- [ ] **Credential Exposure Scoring**
  - Score risk based on credential type (DB, API, SSH)
  - Weight by vulnerability severity
  - Alert on high-risk combinations

- [ ] **MITRE ATLAS Mapping**
  - Map findings to MITRE ATLAS tactics (ML-specific threats)
  - ATT&CK framework integration
  - Threat scenario generation

- [ ] **Policy Engine**
  - Define security policies (e.g., "no critical vulns with DB creds")
  - Evaluate agents against policies
  - Pass/fail scoring for compliance

- [ ] **Live MCP Introspection**
  - Connect to running MCP servers
  - Enumerate tools and resources dynamically
  - Validate config vs runtime state

---

## v1.0.0 - Production Ready

**Focus**: Stability, performance, and enterprise features

**Target**: Q1 2026

### Features
- [ ] **Performance Optimization**
  - Parallel scanning for multiple agents
  - Caching of registry queries (Redis/disk)
  - Incremental scans (only changed packages)

- [ ] **CI/CD Integration**
  - GitHub Actions workflow
  - GitLab CI template
  - Jenkins plugin
  - Pre-commit hooks

- [ ] **Remediation Guidance**
  - Auto-generate PRs to update vulnerable packages
  - Link to patch releases
  - Track remediation status over time

- [ ] **Diff Mode**
  - Compare two scans
  - Show new/fixed vulnerabilities
  - Regression detection

- [ ] **SPDX 3.0 Support**
  - Export SPDX 3.0 with AI-BOM profile
  - Full SBOM compatibility
  - NTIA Minimum Elements compliance

- [ ] **Comprehensive Testing**
  - 90%+ code coverage
  - Integration tests for all ecosystems
  - Security testing (OWASP ZAP, Bandit)

- [ ] **Documentation**
  - Full API reference
  - Integration guides
  - Video tutorials
  - Case studies

---

## v2.0.0 - Multi-Cloud & Platform

**Focus**: Universal agent scanning across all cloud providers

**Target**: Q3 2026

### Features
- [ ] **AWS Bedrock Agent Scanning**
  - Discover agents via AWS API
  - Parse agent definitions from CloudFormation/Terraform
  - Lambda function dependency analysis

- [ ] **Azure OpenAI Agent Inventory**
  - Scan Azure subscriptions for agents
  - ARM template parsing
  - Azure Functions integration

- [ ] **GCP Vertex AI Agent Discovery**
  - Query GCP projects for agents
  - Parse deployment configs
  - Cloud Run/Functions analysis

- [ ] **Kubernetes Support**
  - Scan K8s clusters for agent deployments
  - Parse Helm charts and operators
  - Service mesh integration (Istio, Linkerd)

- [ ] **Multi-Account Scanning**
  - Scan across multiple cloud accounts
  - Consolidated reporting
  - Cross-account IAM analysis

- [ ] **Terraform/IaC Scanning**
  - Parse agent definitions in Terraform
  - CloudFormation template analysis
  - Pulumi support

---

## v3.0.0 - Web Platform

**Focus**: Web UI, dashboards, and multi-tenant support

**Target**: Q1 2027

### Features
- [ ] **Web Dashboard**
  - Real-time metrics and trends
  - Filterable agent inventory
  - Vulnerability timeline charts

- [ ] **Interactive Dependency Graph**
  - D3.js/Cytoscape visualization
  - Zoomable, filterable tree view
  - Click-through to CVE details

- [ ] **Risk Heatmaps**
  - Color-coded agent grid by risk score
  - Drill-down to package level
  - Export to PNG/SVG

- [ ] **Remediation Workflow**
  - Track fix status (open/in-progress/fixed)
  - Assign to team members
  - SLA tracking

- [ ] **Multi-Tenant Support**
  - Organization isolation
  - Team-based access control
  - Cross-org aggregation

- [ ] **RBAC & Audit Logs**
  - Role-based permissions
  - Audit trail for all actions
  - Compliance reporting

- [ ] **API Server**
  - RESTful API for all CLI features
  - GraphQL endpoint
  - Webhook support

---

## v4.0.0 - Enterprise & Ecosystem

**Focus**: Enterprise integrations and marketplace

**Target**: Q3 2027

### Features
- [ ] **SIEM Integration**
  - Splunk app
  - Elastic/ELK plugin
  - QRadar connector

- [ ] **Ticketing Integration**
  - Jira issue creation
  - ServiceNow incidents
  - PagerDuty alerts

- [ ] **SSO & Identity**
  - SAML 2.0 support
  - OAuth 2.0 / OIDC
  - Active Directory integration

- [ ] **Notifications**
  - Slack/Teams webhooks
  - Email alerts
  - SMS via Twilio

- [ ] **MCP Registry Scanning**
  - Scan public MCP server registries
  - Pre-installation security checks
  - Community ratings

- [ ] **Marketplace**
  - Custom vulnerability sources
  - Policy templates
  - Third-party integrations

- [ ] **AI-Powered Insights**
  - ML-based risk prediction
  - Anomaly detection
  - Automated triage

---

## Research & Exploration

**Ongoing investigations for future releases**

- **Blockchain/Web3 Agents**: Scan smart contract agents, DeFi bots
- **IoT/Edge Agents**: Embedded agents, Raspberry Pi deployments
- **Federated Scanning**: Privacy-preserving multi-org scans
- **Zero-Knowledge Proofs**: Prove compliance without revealing data
- **Quantum-Resistant Crypto**: Future-proof security
- **Real-Time Monitoring**: Agent behavior anomaly detection
- **Supply Chain Attestation**: Verify package integrity with Sigstore
- **Prompt Injection Detection**: Integrate with mcp-scan/Cisco MCP Scanner

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Feature request process
- Development workflow
- Code standards
- Release process

---

## Versioning

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes

---

*Roadmap subject to change based on community feedback and priorities*
