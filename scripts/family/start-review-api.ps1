$ErrorActionPreference = 'Stop'
$familyRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$runtime = Join-Path $familyRoot '.runtime'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$env:NODE_ENV = 'development'
$env:FAMILY_DB_PATH = Join-Path $runtime 'review.sqlite'
$env:FAMILY_SINGLE_REPLICA = 'true'
$env:FAMILY_AUDIENCE = 'http://127.0.0.1:8788'
$env:FAMILY_HOST = '127.0.0.1'
$env:PORT = '8788'
$env:VIRUSTOTAL_ENABLED = 'false'
& node.exe (Join-Path $familyRoot 'apps\api\dist\src\family\server.js')
exit $LASTEXITCODE
