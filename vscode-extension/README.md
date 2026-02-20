# agent-bom VS Code Extension

Scan AI agents and MCP servers for vulnerabilities directly from VS Code.

## Prerequisites

- [agent-bom CLI](https://github.com/agent-bom/agent-bom) installed (`pip install agent-bom`)
- Python 3.10+

## Commands

| Command | Description |
|---------|-------------|
| `agent-bom: Scan Workspace` | Run a vulnerability scan on MCP configs in the workspace |
| `agent-bom: Show Results` | Open a webview panel with scan results |

## Features

- **Diagnostics** — squiggly lines on MCP config files with vulnerabilities
- **Status bar** — shows vulnerability count after scanning
- **Results panel** — webview with scan summary table
- **SARIF-based** — parses standard SARIF 2.1.0 output from agent-bom CLI

## Development

```bash
cd vscode-extension
npm install
npm run compile
```

Press **F5** in VS Code to launch the Extension Development Host.

## Building

```bash
npm run vscode:prepublish
npx @vscode/vsce package
```

This produces an `.vsix` file you can install locally via:

```
code --install-extension agent-bom-0.13.0.vsix
```
