# Deployment Overview

| Mode | Best for | Command |
|------|----------|---------|
| **CLI** | Local scanning, CI/CD | `pip install agent-bom` |
| **MCP Server** | AI agent integration | `agent-bom mcp server` |
| **Docker** | Isolated scanning | `docker run ghcr.io/msaad00/agent-bom scan` |
| **GitHub Action** | PR checks | `uses: msaad00/agent-bom@v0.76.2` |
| **Kubernetes** | Fleet monitoring | Helm chart |
| **REST API** | Platform integration | `agent-bom serve` |
| **Runtime Proxy** | Real-time enforcement | `agent-bom runtime proxy` |

## Available on

- [PyPI](https://pypi.org/project/agent-bom/)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [GHCR](https://github.com/msaad00/agent-bom/pkgs/container/agent-bom)
- [GitHub Marketplace](https://github.com/marketplace/actions/agent-bom-ai-supply-chain-security-scan)
- [Smithery](https://smithery.ai/server/agent-bom/agent-bom)
- [Glama](https://glama.ai)
