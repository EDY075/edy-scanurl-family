$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$toolchainRoot = Join-Path $projectRoot '.toolchains'
$env:JAVA_HOME = Join-Path $toolchainRoot 'jdk-21'
$env:ANDROID_HOME = Join-Path $toolchainRoot 'android-sdk'
$env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
$env:ANDROID_USER_HOME = Join-Path $toolchainRoot 'android-user'
$env:GRADLE_USER_HOME = Join-Path $toolchainRoot 'gradle-home'
New-Item -ItemType Directory -Force -Path $env:ANDROID_USER_HOME,$env:GRADLE_USER_HOME | Out-Null
$env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$(Join-Path $env:ANDROID_HOME 'platform-tools');$(Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin');$env:Path"
if (-not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME 'bin\javac.exe'))) { throw 'JDK_21_NOT_INSTALLED' }
if (-not (Test-Path -LiteralPath (Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin\sdkmanager.bat'))) { throw 'ANDROID_SDK_NOT_INSTALLED' }
