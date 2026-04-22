$ErrorActionPreference = "Stop"

$bundleRoot = Join-Path $env:ProgramData "agent-bom-endpoint"
New-Item -ItemType Directory -Force -Path $bundleRoot | Out-Null
Copy-Item (Join-Path $PSScriptRoot "..\\install-agent-bom-endpoint.ps1") (Join-Path $bundleRoot "install-agent-bom-endpoint.ps1") -Force
& (Join-Path $bundleRoot "install-agent-bom-endpoint.ps1")
