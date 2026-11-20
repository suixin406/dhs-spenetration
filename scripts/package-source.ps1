[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Destination
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$version = (Get-Content -Raw -LiteralPath (Join-Path $root "package.json") | ConvertFrom-Json).version
$target = [IO.Path]::GetFullPath($Destination)
$targetParent = Split-Path -Parent $target
New-Item -ItemType Directory -Force -Path $targetParent | Out-Null

if (Test-Path -LiteralPath $target) {
  Remove-Item -LiteralPath $target -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [IO.File]::Open($target, [IO.FileMode]::CreateNew)
$archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)

try {
  $files = Get-ChildItem -LiteralPath $root -Recurse -Force -File | Where-Object {
    $relative = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
    $relative -notmatch '(^|/)\.git(/|$)' -and
    $relative -notmatch '(^|/)__pycache__(/|$)' -and
    $relative -notmatch '\.py[co]$' -and
    $relative -notmatch '(^|/)\.pytest_cache(/|$)' -and
    $relative -notmatch '(^|/)AUTHORIZED-TARGETS\.json$' -and
    $relative -notmatch '\.(tgz|zip)$'
  }
  foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $archive,
      $file.FullName,
      "dsh-pentest-preset-$version/$relative",
      [IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  }
} finally {
  $archive.Dispose()
  $stream.Dispose()
}

Write-Host "created $target"
