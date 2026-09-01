param([switch]$PreActivation, [string]$ApiOrigin = '')
$ErrorActionPreference = 'Stop'
[void][Reflection.Assembly]::LoadWithPartialName('System.Security')
$familyRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'android-env.ps1')
if (-not $ApiOrigin -and -not $PreActivation) { throw 'Use -PreActivation until the owner authorizes deployment and supplies the final HTTPS origin.' }
if ($PreActivation -and $ApiOrigin) { throw 'PREACTIVATION_MUST_NOT_HAVE_BACKEND' }
if ($ApiOrigin) {
  $uri = [Uri]$ApiOrigin
  if ($uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment -or $uri.UserInfo -or $uri.HostNameType -ne 'Dns' -or $uri.Host -notmatch '\.' -or $uri.Host -match '(^localhost$|\.local$|\.ts\.net$|\.invalid$)') { throw 'PUBLIC_HTTPS_ORIGIN_REQUIRED' }
  $ApiOrigin = $uri.GetLeftPart([UriPartial]::Authority)
}
$secretRoot = Join-Path $familyRoot '.secrets'
New-Item -ItemType Directory -Force -Path $secretRoot | Out-Null
# Restrict only this edition's signing directory, before generating any key.
$signingAcl = New-Object System.Security.AccessControl.DirectorySecurity
$ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
# Preserve ownership: setting even the existing owner also requests WRITE_OWNER,
# which a non-elevated owner need not have. Only the DACL needs tightening.
$signingAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($ownerSid, (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  $signingAcl.AddAccessRule($rule)
}
try { [IO.Directory]::SetAccessControl($secretRoot, $signingAcl) }
catch {
  Write-Warning ('SIGNING_ACL_DIAGNOSTIC: ' + $_.Exception.GetType().Name + ' / ' + $_.Exception.Message)
  if (-not $PreActivation) { throw 'SIGNING_DIRECTORY_ACL_REQUIRED_FOR_OPERATIONAL_RELEASE' }
  Write-Warning 'SIGNING_DIRECTORY_ACL_PENDING: preactivation only; restrict .secrets to the owner before an operational release. Password remains DPAPI-protected.'
}
$store = Join-Path $secretRoot 'family-release.p12'
$passwordFile = Join-Path $secretRoot 'family-release.password.dpapi'
if ((Test-Path -LiteralPath $store) -xor (Test-Path -LiteralPath $passwordFile)) { throw 'SIGNING_STATE_INCOMPLETE_DO_NOT_OVERWRITE' }
if (-not (Test-Path -LiteralPath $store)) {
  $random = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($random)
  $rng.Dispose()
  $secret = [Convert]::ToBase64String($random)
  $protected = [System.Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($secret), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes($passwordFile, $protected)
  $env:FAMILY_SIGNING_PASSWORD = $secret
  & (Join-Path $env:JAVA_HOME 'bin\keytool.exe') -genkeypair -keystore $store -storetype PKCS12 -storepass:env FAMILY_SIGNING_PASSWORD -keypass:env FAMILY_SIGNING_PASSWORD -alias edy-family-release -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=EDY ScanURL Family, OU=Family Release, O=EDY, C=BR' -noprompt
  if ($LASTEXITCODE -ne 0) { throw 'RELEASE_KEY_GENERATION_FAILED' }
} else {
  $unprotected = [System.Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($passwordFile), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  $env:FAMILY_SIGNING_PASSWORD = [Text.Encoding]::UTF8.GetString($unprotected)
}
$env:FAMILY_SIGNING_STORE = $store
$env:FAMILY_API_ORIGIN = $ApiOrigin
$env:VITE_FAMILY_BROWSER_REVIEW = 'false'
$env:NODE_OPTIONS = '--require=' + (Join-Path $PSScriptRoot 'node-userinfo-shim.cjs').Replace('\','/')
Push-Location $familyRoot
try {
  & npm.cmd run build --workspace=@edy-scanurl/web
  if ($LASTEXITCODE -ne 0) { throw 'FAMILY_WEB_BUILD_FAILED' }
  & npx.cmd cap sync android
  if ($LASTEXITCODE -ne 0) { throw 'FAMILY_CAPACITOR_SYNC_FAILED' }
  & .\android\gradlew.bat -p android --no-daemon assembleRelease testReleaseUnitTest
  if ($LASTEXITCODE -ne 0) { throw 'FAMILY_RELEASE_BUILD_FAILED' }
  $destinationRoot = Join-Path $familyRoot 'dist\android'
  New-Item -ItemType Directory -Force -Path $destinationRoot | Out-Null
  $filename = if ($PreActivation) { 'EDY-ScanURL-Family-release-preactivation.apk' } else { 'EDY-ScanURL-Family-release.apk' }
  $destination = Join-Path $destinationRoot $filename
  Copy-Item -LiteralPath (Join-Path $familyRoot 'android\app\build\outputs\apk\release\app-release.apk') -Destination $destination -Force
  & (Join-Path $env:ANDROID_HOME 'build-tools\36.0.0\apksigner.bat') verify --verbose --print-certs $destination
  if ($LASTEXITCODE -ne 0) { throw 'FAMILY_RELEASE_SIGNATURE_INVALID' }
  Write-Output ('FAMILY_APK_READY:' + $destination)
} finally {
  Pop-Location
  Remove-Item Env:\FAMILY_SIGNING_PASSWORD -ErrorAction SilentlyContinue
  Remove-Item Env:\FAMILY_SIGNING_STORE -ErrorAction SilentlyContinue
}
