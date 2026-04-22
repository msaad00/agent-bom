$ErrorActionPreference = "Stop"

param(
  [Parameter(Mandatory = $true)][string]$BundleDir,
  [Parameter(Mandatory = $true)][string]$OutputPath,
  [string]$Version = "0.0.0",
  [switch]$DryRun
)

$stageDir = Join-Path $env:TEMP "agent-bom-msi-stage"
$wxsPath = Join-Path $stageDir "agent-bom-endpoint.wxs"
Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
Copy-Item -Recurse -Force (Join-Path $BundleDir "*") $stageDir

$wxs = @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="agent-bom Endpoint" Manufacturer="agent-bom" Version="$Version" UpgradeCode="8F1A44B0-AE74-4F7B-BA95-9C3ACD493630">
    <MediaTemplate />
    <Feature Id="MainFeature" Title="agent-bom Endpoint" Level="1">
      <ComponentGroupRef Id="EndpointBundle" />
    </Feature>
  </Package>
  <Fragment>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="agent-bom-endpoint" />
      </Directory>
    </Directory>
  </Fragment>
  <Fragment>
    <ComponentGroup Id="EndpointBundle" Directory="INSTALLFOLDER">
      <Files Include="$stageDir\**" />
    </ComponentGroup>
  </Fragment>
</Wix>
"@
Set-Content -Path $wxsPath -Value $wxs -Encoding UTF8

$buildCommand = @("wix", "build", $wxsPath, "-o", $OutputPath)
Write-Output ("+ " + ($buildCommand -join " "))

if ($DryRun) {
  exit 0
}

& $buildCommand[0] $buildCommand[1..($buildCommand.Length - 1)]
