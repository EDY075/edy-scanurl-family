$ErrorActionPreference = 'Stop'
$projectPath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Set-Location -LiteralPath $projectPath
# Public development flags only. No credentials or remote deployment.
Remove-Item Env:VITE_FAMILY_BROWSER_REVIEW -ErrorAction SilentlyContinue
$env:VITE_WEB_LOCAL_PROXY = 'true'
$env:FAMILY_WORKER_REVIEW = 'true'
& npm.cmd run build --workspace=@edy-scanurl/web
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& npm.cmd run preview --workspace=@edy-scanurl/web -- --host 127.0.0.1 --port 4181
