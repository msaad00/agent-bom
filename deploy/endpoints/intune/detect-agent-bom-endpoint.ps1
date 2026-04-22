$ErrorActionPreference = "Stop"

if (Get-Command agent-bom -ErrorAction SilentlyContinue) {
  exit 0
}
exit 1
