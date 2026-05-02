# Policy Engine

Declarative policy-as-code for security gates and enforcement.

## Policy file

```json
{
  "rules": [
    {
      "id": "no-critical-cves",
      "action": "block",
      "condition": "severity == 'critical'"
    },
    {
      "id": "block-sensitive-paths",
      "action": "block",
      "arg_pattern": {
        "path": "(/etc/(passwd|shadow)|/root/\\.ssh)"
      }
    },
    {
      "id": "block-exec-tools",
      "action": "block",
      "block_tools": ["exec", "run_command", "shell"]
    }
  ]
}
```

## 17 policy conditions

16 declarative conditions plus a `condition` expression engine supporting AND/OR/NOT and comparisons.

## Usage

```bash
# CLI — evaluate scan results against policy
agent-bom agents --policy policy.json

# MCP tool
policy_check(policy_file="policy.json")

# Runtime — enforce in proxy
agent-bom proxy --policy policy.json --block-undeclared -- ...
```

## CI/CD gate

```yaml
- name: Security gate
  uses: msaad00/agent-bom@v0.84.6
  with:
    policy: policy.json
    fail-on-violation: true
```
