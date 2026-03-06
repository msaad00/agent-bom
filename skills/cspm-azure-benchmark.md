# CSPM — Azure CIS Foundations Benchmark

> Azure CIS Foundations v2.1 assessment with controls mapping, AI Foundry security, and posture tracking — preparation skill for when agent-bom ships native Azure CIS checks.

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                      Azure Subscription                             │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │ Entra ID │  │  Storage │  │  Monitor │  │ Network  │           │
  │  │ (AD)     │  │ Accounts │  │  + Log   │  │  NSGs    │           │
  │  │ Users    │  │ Blobs    │  │  Analytic│  │  Firewall│           │
  │  │ MFA      │  │ Keys     │  │  Diag    │  │  VNets   │           │
  │  │ Roles    │  │ Encrypt  │  │  Alerts  │  │  ASGs    │           │
  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
  │       │              │             │              │                  │
  │       └──────────────┴──────┬──────┴──────────────┘                  │
  └─────────────────────────────┼────────────────────────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────┐
                  │      agent-bom           │
                  │  cis_benchmark           │
                  │  (provider="azure")      │
                  │                          │
                  │  + scan --azure          │
                  │  (AI Foundry, Functions, │
                  │   Container Instances,   │
                  │   ML endpoints)          │
                  └─────────────┬────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                   ▼
        ┌──────────┐    ┌──────────┐       ┌──────────┐
        │  SARIF   │    │  HTML    │       │  JSON    │
        └──────────┘    └──────────┘       └──────────┘
```

## CIS Azure Foundations v2.1 — Controls Map

### Identity Controls (Section 1)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 1.1 | MFA for all users | Conditional Access policy enforces MFA | CRITICAL | PR.AC-1 |
| 1.2 | MFA for privileged roles | Global Admin, Security Admin require phishing-resistant MFA | CRITICAL | PR.AC-1 |
| 1.3 | No guest users with elevated roles | Guest accounts have no Owner/Contributor | HIGH | PR.AC-4 |
| 1.4 | Self-service password reset | SSPR enabled with MFA verification | MEDIUM | PR.AC-1 |
| 1.5 | Conditional Access block legacy auth | Block protocols that bypass MFA | HIGH | PR.AC-1 |
| 1.6 | PIM for privileged roles | Just-in-time activation for Global/Security Admin | HIGH | PR.AC-4 |
| 1.7 | Custom blocked passwords | Banned password list configured | MEDIUM | PR.AC-1 |

### Storage Controls (Section 2)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 2.1 | HTTPS-only storage | Secure transfer required on all accounts | HIGH | PR.DS-2 |
| 2.2 | Storage account keys rotated | Keys rotated within 90 days (or use Entra ID auth) | MEDIUM | PR.AC-1 |
| 2.3 | No public blob access | Container public access disabled | CRITICAL | PR.AC-3 |
| 2.4 | CMK encryption | Customer-managed keys for sensitive data | MEDIUM | PR.DS-1 |
| 2.5 | Private endpoints for storage | Storage accounts use private endpoints | HIGH | PR.AC-5 |
| 2.6 | Soft delete enabled | Blob + container soft delete for recovery | MEDIUM | PR.DS-1 |

### Logging Controls (Section 3)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 3.1 | Diagnostic settings on all services | Activity log + resource logs to Log Analytics | CRITICAL | DE.AE-3 |
| 3.2 | Activity log retention 365+ days | Archive to storage account or Log Analytics | HIGH | DE.AE-5 |
| 3.3 | Key Vault logging | Diagnostic settings on all Key Vaults | HIGH | DE.CM-1 |
| 3.4 | NSG flow logs | Flow logs on all NSGs | MEDIUM | DE.CM-1 |
| 3.5 | Alert rules for critical operations | Alerts for policy assignment, NSG changes, Key Vault access | MEDIUM | DE.CM-1 |

### Networking Controls (Section 4)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 4.1 | No unrestricted SSH/RDP | NSGs block 0.0.0.0/0 on ports 22/3389 | HIGH | PR.AC-5 |
| 4.2 | No unrestricted UDP | NSGs restrict broad UDP access | HIGH | PR.AC-5 |
| 4.3 | Network Watcher enabled | Network Watcher in all used regions | MEDIUM | DE.CM-1 |
| 4.4 | Azure Firewall or NVA | Centralized egress filtering | MEDIUM | PR.AC-5 |

### AI Foundry Controls (Azure-Specific)

| # | Control | Check | Severity |
|---|---------|-------|----------|
| A.1 | Workspace auth | AI Foundry workspaces require Entra ID auth | CRITICAL |
| A.2 | Private endpoints | AI Foundry not exposed to public internet | CRITICAL |
| A.3 | CMEK for model data | Training data and model artifacts encrypted with CMK | HIGH |
| A.4 | Managed VNet | AI Foundry workspace uses managed VNet isolation | HIGH |
| A.5 | Prompt Shields enabled | Content Safety filters on all deployments | HIGH |
| A.6 | Outbound network rules | Restrict outbound to approved endpoints only | MEDIUM |

## Running the Assessment

### Azure discovery + benchmark (current)

```bash
# Discover AI Foundry, Container Instances, Functions, ML endpoints
agent-bom scan --azure --azure-subscription SUB_ID --enrich

# When Azure CIS checks ship:
agent-bom scan --azure --azure-subscription SUB_ID --azure-cis-benchmark
```

### Via MCP tool

```
# Current: discovery scan
scan()

# When Azure CIS ships:
cis_benchmark(provider="azure", subscription="SUB_ID")
```

### Manual assessment (until native checks ship)

<details>
<summary><b>Identity checks via az CLI</b></summary>

```bash
# 1.1 Check Conditional Access policies for MFA
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | \
  jq '.value[] | select(.grantControls.builtInControls[] == "mfa") | .displayName'

# 1.3 List guest users with elevated roles
az role assignment list --all --query "[?principalType=='User']" -o json | \
  jq -r '.[].principalId' | sort -u | while read id; do
    type=$(az ad user show --id "$id" --query "userType" -o tsv 2>/dev/null)
    [ "$type" = "Guest" ] && echo "GUEST WITH ROLE: $id"
  done

# 1.5 Check legacy auth blocking
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | \
  jq '.value[] | select(.conditions.clientAppTypes[] == "exchangeActiveSync")'
```

</details>

<details>
<summary><b>Storage + Networking checks via az CLI</b></summary>

```bash
# 2.3 Check for public blob containers
az storage account list --query "[].{name:name,rg:resourceGroup}" -o tsv | \
  while read name rg; do
    public=$(az storage account show -n "$name" -g "$rg" \
      --query "allowBlobPublicAccess" -o tsv 2>/dev/null)
    [ "$public" = "true" ] && echo "FAIL: Public access: $name"
  done

# 3.1 Check diagnostic settings
az monitor diagnostic-settings subscription list --subscription SUB_ID

# 4.1 Check NSGs for unrestricted SSH
az network nsg list --query "[].{nsg:name,rg:resourceGroup}" -o tsv | \
  while read nsg rg; do
    az network nsg rule list -g "$rg" --nsg-name "$nsg" \
      --query "[?destinationPortRange=='22' && sourceAddressPrefix=='*']" -o json | \
      jq '.[] | "FAIL: Open SSH on \(.name) in '$nsg'"'
  done
```

</details>

## Remediation Playbook

### Critical findings

```
  FINDING: AI Foundry workspace publicly accessible
  ──────────────────────────────────────────────────
  WHY:     Public AI endpoints = prompt injection + data exfiltration surface
  FIX:     az ml workspace update --name WS --resource-group RG \
             --public-network-access Disabled
           # Configure private endpoint for workspace access
  VERIFY:  az ml workspace show --name WS -g RG --query "publicNetworkAccess"
```

```
  FINDING: Storage account allows public blob access
  ──────────────────────────────────────────────────
  FIX:     az storage account update -n ACCOUNT -g RG --allow-blob-public-access false
  VERIFY:  az storage account show -n ACCOUNT -g RG --query "allowBlobPublicAccess"
```

### High findings

<details>
<summary><b>NSGs with open SSH/RDP</b></summary>

```bash
# Remove the offending rule
az network nsg rule delete -g RG --nsg-name NSG_NAME -n RULE_NAME

# Add restricted rule (specific IP range only)
az network nsg rule create -g RG --nsg-name NSG_NAME -n AllowSSH-Restricted \
  --priority 100 --direction Inbound --access Allow \
  --protocol Tcp --destination-port-ranges 22 \
  --source-address-prefixes 10.0.0.0/8  # Corporate CIDR only
```

</details>

## Posture Metrics

| Metric | Target |
|--------|--------|
| CIS Pass Rate | > 90% |
| Users without MFA | 0 |
| Guest Users with Elevated Roles | 0 |
| Public Storage Accounts | 0 |
| AI Foundry without Private Endpoints | 0 |
| NSGs with Unrestricted Ingress | 0 |
| Services without Diagnostic Settings | 0 |

## Outputs

| Artifact | Purpose |
|----------|---------|
| Azure scan results (JSON) | AI Foundry, Functions, Container Instances inventory |
| CIS assessment (JSON) | Per-control pass/fail (when native checks ship) |
| SARIF report | GitHub Security tab |
| Posture metrics | Time-series for SIEM/dashboard |
