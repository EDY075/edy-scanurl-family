$ErrorActionPreference = 'Stop'
$familyRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$env:VITE_FAMILY_BROWSER_REVIEW = 'true'
Push-Location $familyRoot
try {
  & npm.cmd run build --workspace=@edy-scanurl/web
  if ($LASTEXITCODE -ne 0) { throw 'FAMILY_REVIEW_BUILD_FAILED' }
  & npm.cmd run preview --workspace=@edy-scanurl/web -- --host 127.0.0.1
} finally { Pop-Location }
