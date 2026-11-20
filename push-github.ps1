# push-github.ps1 - push files to GitHub via curl.exe (ASCII only)
param(
  [string]$Repo = "dhs-spenetration",
  [string]$Owner = "suixin406",
  [string]$Token = $env:GH_TOKEN
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $Token) { throw "missing GH_TOKEN" }

$tmp = Join-Path $env:TEMP ("ghpush_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$skipDirs = @(".git","node_modules","__pycache__",".venv","venv","targets","loot","recon","exploit","screens","logs")
$skipExt  = @(".pyc",".log",".zip",".bak")

function Get-Tree($dir, $base) {
  $out = @()
  Get-ChildItem $dir -Force | ForEach-Object {
    if ($_.PSIsContainer) {
      if ($skipDirs -notcontains $_.Name) { $out += Get-Tree $_.FullName $base }
    } else {
      if ($_.Name -notlike "_*" -and $skipExt -notcontains $_.Extension.ToLower()) {
        $rel = $_.FullName.Substring($base.Length).TrimStart('\','/').Replace('\','/')
        $out += [pscustomobject]@{ Rel = $rel; Full = $_.FullName }
      }
    }
  }
  return $out
}

Write-Host "[+] owner=$Owner repo=$Repo"
$repoJson = Join-Path $tmp "repo.json"
curl.exe -sS --max-time 30 -H "Authorization: Bearer $Token" -H "Accept: application/vnd.github+json" -H "User-Agent: dsh-push" "https://api.github.com/repos/$Owner/$Repo" -o $repoJson
$repo = Get-Content $repoJson -Raw | ConvertFrom-Json
if (-not $repo.default_branch) { throw "repo not found or no permission" }
$branch = $repo.default_branch
Write-Host "[+] repo ok: $($repo.html_url) branch=$branch"

$files = Get-Tree $root $root
Write-Host "[+] files to push: $($files.Count)"

$ok = 0; $fail = 0; $first = $true
foreach ($f in $files) {
  $url = "https://api.github.com/repos/$Owner/$Repo/contents/$($f.Rel)"

  $sha = $null
  $shaJson = Join-Path $tmp "sha.json"
  curl.exe -sS --max-time 30 -H "Authorization: Bearer $Token" -H "Accept: application/vnd.github+json" -H "User-Agent: dsh-push" "$url`?ref=$branch" -o $shaJson 2>$null
  try { $sj = Get-Content $shaJson -Raw -EA Stop | ConvertFrom-Json; if ($sj.sha) { $sha = $sj.sha } } catch {}

  $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.Full))
  $payload = @{ message = "sync"; content = $b64 }
  if ($sha) { $payload.sha = $sha }
  if (-not $first -or $sha) { $payload.branch = $branch }

  $body = Join-Path $tmp "body.json"
  $payload | ConvertTo-Json -Compress | Set-Content $body -Encoding UTF8 -NoNewline

  $resp = Join-Path $tmp "resp.json"
  $code = curl.exe -sS --max-time 90 -o $resp -w "%{http_code}" -X PUT -H "Authorization: Bearer $Token" -H "Accept: application/vnd.github+json" -H "User-Agent: dsh-push" -H "Content-Type: application/json" --data-binary "@$body" $url

  if ($code -eq "200" -or $code -eq "201") {
    $ok++; $first = $false
    if ($ok % 20 -eq 0) { Write-Host "  ... $ok/$($files.Count)" }
  } elseif ($payload.branch) {
    $payload.Remove("branch")
    $payload | ConvertTo-Json -Compress | Set-Content $body -Encoding UTF8 -NoNewline
    $code = curl.exe -sS --max-time 90 -o $resp -w "%{http_code}" -X PUT -H "Authorization: Bearer $Token" -H "Accept: application/vnd.github+json" -H "User-Agent: dsh-push" -H "Content-Type: application/json" --data-binary "@$body" $url
    if ($code -eq "200" -or $code -eq "201") { $ok++; $first = $false }
    else { $fail++; Write-Host "  ! $($f.Rel) -> $code" }
  } else {
    $fail++
    Write-Host "  ! $($f.Rel) -> $code"
  }
  Start-Sleep -Milliseconds 100
}

Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
Write-Host "=== DONE ==="
Write-Host "  ok $ok  fail $fail"
Write-Host "  repo: $($repo.html_url)"
