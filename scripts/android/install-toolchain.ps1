$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$toolchainRoot = Join-Path $projectRoot '.toolchains'
$downloadRoot = Join-Path $toolchainRoot 'downloads'
$jdkRoot = Join-Path $toolchainRoot 'jdk-21'
$sdkRoot = Join-Path $toolchainRoot 'android-sdk'
$jdkZip = Join-Path $downloadRoot 'microsoft-jdk-21.0.12.1-windows-x64.zip'
$jdkHash = Join-Path $downloadRoot 'microsoft-jdk-21.0.12.1-windows-x64.zip.sha256sum.txt'
$androidZip = Join-Path $downloadRoot 'commandlinetools-win-15859902_latest.zip'
$androidExpectedHash = '90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a'

New-Item -ItemType Directory -Force -Path $downloadRoot,$sdkRoot | Out-Null
$downloader = Join-Path $PSScriptRoot 'download.mjs'
if (-not (Test-Path -LiteralPath $jdkZip)) { & node.exe $downloader 'https://aka.ms/download-jdk/microsoft-jdk-21.0.12.1-windows-x64.zip' $jdkZip; if ($LASTEXITCODE -ne 0) { throw 'JDK_DOWNLOAD_FAILED' } }
if (-not (Test-Path -LiteralPath $jdkHash)) { & node.exe $downloader 'https://aka.ms/download-jdk/microsoft-jdk-21.0.12.1-windows-x64.zip.sha256sum.txt' $jdkHash; if ($LASTEXITCODE -ne 0) { throw 'JDK_HASH_DOWNLOAD_FAILED' } }
$jdkExpectedHash = ((Get-Content -Raw -LiteralPath $jdkHash).Trim() -split '\s+')[0].ToLowerInvariant()
$jdkActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $jdkZip).Hash.ToLowerInvariant()
if ($jdkExpectedHash -ne $jdkActualHash) { throw 'JDK_HASH_MISMATCH' }
if (-not (Test-Path -LiteralPath (Join-Path $jdkRoot 'bin\javac.exe'))) {
  $jdkExtract = Join-Path $toolchainRoot 'jdk-extracted'
  New-Item -ItemType Directory -Force -Path $jdkExtract | Out-Null
  Expand-Archive -LiteralPath $jdkZip -DestinationPath $jdkExtract -Force
  $jdkDirectory = Get-ChildItem -Directory -LiteralPath $jdkExtract | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin\javac.exe') } | Select-Object -First 1
  if ($null -eq $jdkDirectory) { throw 'JDK_ARCHIVE_INVALID' }
  Move-Item -LiteralPath $jdkDirectory.FullName -Destination $jdkRoot
}

if (-not (Test-Path -LiteralPath $androidZip)) { & node.exe $downloader 'https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip' $androidZip; if ($LASTEXITCODE -ne 0) { throw 'ANDROID_TOOLS_DOWNLOAD_FAILED' } }
$androidActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $androidZip).Hash.ToLowerInvariant()
if ($androidExpectedHash -ne $androidActualHash) { throw 'ANDROID_TOOLS_HASH_MISMATCH' }
$latestRoot = Join-Path $sdkRoot 'cmdline-tools\latest'
if (-not (Test-Path -LiteralPath (Join-Path $latestRoot 'bin\sdkmanager.bat'))) {
  $androidExtract = Join-Path $toolchainRoot 'android-tools-extracted'
  New-Item -ItemType Directory -Force -Path $androidExtract | Out-Null
  Expand-Archive -LiteralPath $androidZip -DestinationPath $androidExtract -Force
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $latestRoot) | Out-Null
  Move-Item -LiteralPath (Join-Path $androidExtract 'cmdline-tools') -Destination $latestRoot
}

. (Join-Path $PSScriptRoot 'android-env.ps1')
$yes = 1..30 | ForEach-Object { 'y' }
$yes | & sdkmanager.bat --sdk_root=$env:ANDROID_HOME --licenses | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'ANDROID_LICENSE_ACCEPTANCE_FAILED' }
$androidCli = Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin\android.exe'
& $androidCli --no-metrics --sdk=$env:ANDROID_HOME sdk install platform-tools platforms/android-36 build-tools/36.0.0 | Out-Host
if (-not (Test-Path -LiteralPath (Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe')) -or -not (Test-Path -LiteralPath (Join-Path $env:ANDROID_HOME 'platforms\android-36\android.jar')) -or -not (Test-Path -LiteralPath (Join-Path $env:ANDROID_HOME 'build-tools\36.0.0\aapt.exe'))) { throw 'ANDROID_SDK_PACKAGES_FAILED' }
& java.exe -version
& javac.exe -version
& adb.exe version
Write-Host 'ANDROID_TOOLCHAIN_READY'
