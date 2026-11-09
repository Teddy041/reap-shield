# Builds "REAP-Shield Launcher.exe" in the project root from launcher\Launcher.cs.
# Uses the C# compiler that ships with the .NET Framework 4.x on every
# supported Windows version, so no SDK or extra download is required.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$launcherDir = $PSScriptRoot
$root = Split-Path -Parent $launcherDir
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe (.NET Framework 4.x) was not found.' }

# Convert build\icon.png into a 256x256 PNG-compressed .ico for the exe.
$iconPng = Join-Path $root 'build\icon.png'
$iconIco = Join-Path $launcherDir 'icon.ico'
$source = [System.Drawing.Image]::FromFile($iconPng)
try {
    $bitmap = New-Object System.Drawing.Bitmap 256, 256
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.DrawImage($source, 0, 0, 256, 256)
    $graphics.Dispose()
    $pngStream = New-Object System.IO.MemoryStream
    $bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
} finally {
    $source.Dispose()
}
$png = $pngStream.ToArray()
$ico = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter $ico
$writer.Write([UInt16]0); $writer.Write([UInt16]1); $writer.Write([UInt16]1)   # ICONDIR
$writer.Write([Byte]0); $writer.Write([Byte]0)                                 # 256 x 256
$writer.Write([Byte]0); $writer.Write([Byte]0)                                 # palette, reserved
$writer.Write([UInt16]1); $writer.Write([UInt16]32)                            # planes, bpp
$writer.Write([UInt32]$png.Length); $writer.Write([UInt32]22)                  # size, offset
$writer.Write($png)
$writer.Flush()
[System.IO.File]::WriteAllBytes($iconIco, $ico.ToArray())

$output = Join-Path $root 'REAP-Shield Launcher.exe'
& $csc /nologo /target:winexe /optimize+ /platform:anycpu `
    "/win32icon:$iconIco" "/out:$output" `
    /reference:System.Windows.Forms.dll `
    (Join-Path $launcherDir 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw "csc.exe failed with exit code $LASTEXITCODE." }
Remove-Item $iconIco
Write-Host "Built $output"
