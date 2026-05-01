# Windows Container Guide

agent-bom Docker images are Linux containers (amd64 and arm64). This document
covers how to use agent-bom in Windows environments.

---

## Recommended: Docker Desktop with Linux containers (default)

Docker Desktop for Windows runs Linux containers by default via WSL 2 or
Hyper-V. All agent-bom images work out of the box.

```powershell
# Scan from PowerShell
docker run --rm agentbom/agent-bom agents

# Mount Windows paths (Docker Desktop translates automatically)
docker run --rm -v "${env:APPDATA}:/root/.config:ro" agentbom/agent-bom agents

# MCP server mode
docker run --rm -p 8423:8423 `
  -e AGENT_BOM_MCP_BEARER_TOKEN=change-me `
  agentbom/agent-bom mcp server --transport streamable-http --host 0.0.0.0 --port 8423
```

### Volume mount paths

Windows paths need adjustment for Docker Desktop:

| Host path (Windows) | Container mount |
|----------------------|-----------------|
| `%APPDATA%\Claude\` | `/root/.config/claude/` |
| `%APPDATA%\Code\User\globalStorage\` | `/root/.config/Code/User/globalStorage/` |
| `%USERPROFILE%\.cursor\` | `/root/.cursor/` |
| `%USERPROFILE%\.claude\` | `/root/.claude/` |

PowerShell example with MCP config discovery:

```powershell
docker run --rm `
  -v "${env:APPDATA}/Claude:/root/.config/claude:ro" `
  -v "${env:USERPROFILE}/.cursor:/root/.cursor:ro" `
  agentbom/agent-bom agents
```

---

## Docker Compose on Windows

Use the standard `deploy/docker-compose.fullstack.yml` with Windows-adjusted paths:

```yaml
# docker-compose.override.yml (Windows)
services:
  api:
    volumes:
      # Override Linux home paths with Windows equivalents
      - ${APPDATA}/Claude:/root/.config/claude:ro
      - ${USERPROFILE}/.cursor:/root/.cursor:ro
      - ${USERPROFILE}/.claude:/root/.claude:ro
```

Then run:

```powershell
docker compose -f deploy/docker-compose.fullstack.yml -f docker-compose.override.yml up
```

---

## Python CLI on Windows (no Docker required)

For environments where Docker is not available or practical, install agent-bom
directly via pip:

```powershell
pip install agent-bom
agent-bom agents
```

The Python CLI works natively on Windows and auto-discovers MCP client configs
from Windows-native paths (`%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%`).

---

## GPU scanning on Windows

The `--gpu-scan` flag detects GPU infrastructure across platforms:

| Platform | Detection method | Notes |
|----------|-----------------|-------|
| Linux | Docker labels, NVIDIA container runtime, DCGM exporter | Full support |
| Windows (WDDM) | WDDM driver version via registry / WMI | Python CLI only |
| Windows (WSL 2) | Linux Docker containers via Docker Desktop | Accesses host GPU via WSL passthrough |

Windows WDDM GPU detection requires the Python CLI (not Docker), since
Windows-native GPU APIs are not accessible from within a Linux container.

For WSL 2 environments with GPU passthrough:

```powershell
# Docker Desktop with WSL 2 backend and NVIDIA GPU support
docker run --rm --gpus all agentbom/agent-bom agents --gpu-scan
```

---

## Windows containers (not supported)

agent-bom does not publish Windows container (nanoserver / servercore) images.
The scanner engine relies on Unix tooling and Linux-native
container inspection. Windows Server environments should use:

1. **Python CLI** -- `pip install agent-bom` works on Windows natively
2. **Docker Desktop** -- run the Linux container images on Windows via WSL 2
3. **CI/CD** -- use the GitHub Action (`uses: msaad00/agent-bom@v0.84.4`) which
   runs on Linux runners

---

## Troubleshooting

### "image platform does not match" error

Docker Desktop defaults to Linux containers. If you see a platform mismatch,
ensure Docker Desktop is set to "Use the WSL 2 based engine" (Settings >
General) and not switched to Windows containers mode.

### Volume mounts not working

Docker Desktop must have file sharing enabled for the drives you are mounting.
Check Settings > Resources > File sharing. WSL 2 backend handles this
automatically for most paths.

### MCP config not discovered

When running in Docker, agent-bom looks for configs at Linux paths inside the
container. Mount your Windows config directories to the corresponding Linux
paths as shown in the volume mount table above.
