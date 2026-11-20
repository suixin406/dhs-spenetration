# Atomic GitHub publish helper. It never pushes unless -Push is supplied.
[CmdletBinding()]
param(
  [string]$Remote = "origin",
  [string]$Branch = "main",
  [string]$Message = "release: update dsh-pentest-preset",
  [switch]$Push
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Invoke-Git {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
  & git -C $root @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "git failed ($LASTEXITCODE): git $($Arguments -join ' ')"
  }
}

Invoke-Git rev-parse --show-toplevel | Out-Null
$configured = (& git -C $root remote)
if ($LASTEXITCODE -ne 0 -or $configured -notcontains $Remote) {
  throw "remote '$Remote' is not configured"
}

Write-Host "Repository: $root"
Write-Host "Destination: $Remote/$Branch"
Write-Host "Changes:"
Invoke-Git status --short

if (-not $Push) {
  Write-Host "Dry run only. Re-run with -Push to validate, create one commit, and push atomically."
  exit 0
}

Invoke-Git diff --check
& npm --prefix $root test
if ($LASTEXITCODE -ne 0) { throw "npm test failed" }

Invoke-Git add -A -- .
& git -C $root diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
  Write-Host "Nothing to commit."
  exit 0
}
if ($LASTEXITCODE -ne 1) { throw "git diff --cached failed" }

Invoke-Git commit -m $Message
Invoke-Git push $Remote "HEAD:$Branch"
Write-Host "Published one atomic commit to $Remote/$Branch"
