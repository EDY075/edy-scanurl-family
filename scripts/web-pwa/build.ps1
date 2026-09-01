$ErrorActionPreference = 'Stop'
$projectPath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Set-Location -LiteralPath $projectPath
# Make the named production command independent of prior review flags.
Remove-Item Env:VITE_FAMILY_BROWSER_REVIEW -ErrorAction SilentlyContinue
Remove-Item Env:VITE_WEB_LOCAL_PROXY -ErrorAction SilentlyContinue
& npm.cmd run build --workspace=@edy-scanurl/web
exit $LASTEXITCODE
