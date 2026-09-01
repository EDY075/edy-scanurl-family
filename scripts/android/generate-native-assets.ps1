$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sourcePath = Join-Path $projectRoot 'apps\web\public\pwa-concept04-maskable-512.png'
$resourceRoot = Join-Path $projectRoot 'android\app\src\main\res'
Add-Type -AssemblyName System.Drawing

function Write-ScaledPng([string]$Destination, [int]$Size) {
  $source = [Drawing.Image]::FromFile($sourcePath)
  try {
    $canvas = New-Object Drawing.Bitmap($Size,$Size)
    try {
      $graphics = [Drawing.Graphics]::FromImage($canvas)
      try {
        $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.DrawImage($source,0,0,$Size,$Size)
      } finally { $graphics.Dispose() }
      $canvas.Save($Destination,[Drawing.Imaging.ImageFormat]::Png)
    } finally { $canvas.Dispose() }
  } finally { $source.Dispose() }
}

$sizes = @{ 'mdpi'=48; 'hdpi'=72; 'xhdpi'=96; 'xxhdpi'=144; 'xxxhdpi'=192 }
foreach ($density in $sizes.Keys) {
  $directory = Join-Path $resourceRoot "mipmap-$density"
  Write-ScaledPng (Join-Path $directory 'ic_launcher.png') $sizes[$density]
  Write-ScaledPng (Join-Path $directory 'ic_launcher_round.png') $sizes[$density]
}
Write-Host 'ANDROID_CONCEPT04_ASSETS_READY'
