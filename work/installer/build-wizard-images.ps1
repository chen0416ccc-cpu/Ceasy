#Requires -Version 5.1
<#
.SYNOPSIS
    从应用 logo 生成 Inno Setup 向导用的品牌图片（多 DPI 档位）。

.DESCRIPTION
    向导图片不手工制作，而是从 CodexGuardian\Assets\CeasyLogo.png 按品牌色板生成，
    这样 logo 或色板变了只要重跑一次，不会留下没人知道怎么再造的美术资产。

    输出是带 alpha 的 PNG。Inno Setup 6.6.0 起 WizardImageFile / WizardSmallImageFile
    支持 PNG（含透明），不必再转成 BMP。

    产物落在 installer\Assets\，由 Ceasy.iss 以逗号分隔的多档位形式引用。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File work\installer\build-wizard-images.ps1
#>
[CmdletBinding()]
param(
    [string]$LogoPath,
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$InstallerRoot = $PSScriptRoot
if (-not $LogoPath) {
    $LogoPath = Join-Path (Split-Path $InstallerRoot -Parent) 'CodexGuardian\Assets\CeasyLogo.png'
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $InstallerRoot 'Assets'
}

if (-not (Test-Path -LiteralPath $LogoPath -PathType Leaf)) {
    throw "找不到应用 logo：$LogoPath"
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# 取自 .codex\UI_DESIGN_SYSTEM.md 的浅色主题色板。向导用浅色，与应用首次启动时的
# 默认外观一致；深色主题的橙色 Signature 在安装向导的白底上会过于跳。
$CanvasTop    = [System.Drawing.ColorTranslator]::FromHtml('#F2EFE7')  # Canvas
$CanvasBottom = [System.Drawing.ColorTranslator]::FromHtml('#F7F3EB')  # Raised surface
$Signature    = [System.Drawing.ColorTranslator]::FromHtml('#3F6FC7')  # Signature / Command
$Structural   = [System.Drawing.ColorTranslator]::FromHtml('#CEC4B5')  # Structural line

# --- 尺寸档位 -------------------------------------------------------------------
# Inno Setup 6.6.0+ 的向导图像区尺寸序列（100%/125%/150%/175%/200%/225%/250% 缩放）：
#   大图 202x386 / 269x515 / 336x643 / 403x772 / 430x824 / 498x953 / 534x1022
#   小图 58 / 77 / 97 / 116 / 124 / 143 / 159（始终正方）
# 逗号分隔多个文件时 Setup 自己挑最接近当前 DPI 的那张再缩放一次，所以给
# 100% / 150% / 250% 三档就够覆盖常见 DPI，不必七档全出，安装包也不必为此变大。
$WizardImageSizes = @(
    @{ Width = 202; Height = 386 }
    @{ Width = 336; Height = 643 }
    @{ Width = 534; Height = 1022 }
)
$SmallImageSizes = @(58, 97, 159)

# --- 工具函数 -------------------------------------------------------------------

function Get-OpaqueBounds {
    <#
        原图四周有约 8% 的透明留白。按 512 画布几何居中会让视觉重心偏上或偏下，
        所以先量出真正有像素的那块区域，后续一律按它定位和缩放。
        用 LockBits 整块读，逐像素 GetPixel 在 512x512 上要几秒。
    #>
    param([Parameter(Mandatory)][System.Drawing.Bitmap]$Bitmap)

    $rect = New-Object System.Drawing.Rectangle 0, 0, $Bitmap.Width, $Bitmap.Height
    $data = $Bitmap.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $stride = 0
    $bytes = $null
    try {
        $stride = $data.Stride
        $bytes = New-Object byte[] ($stride * $Bitmap.Height)
        [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
    }
    finally {
        $Bitmap.UnlockBits($data)
    }

    $minX = $Bitmap.Width; $minY = $Bitmap.Height; $maxX = -1; $maxY = -1
    for ($y = 0; $y -lt $Bitmap.Height; $y++) {
        $row = $y * $stride
        for ($x = 0; $x -lt $Bitmap.Width; $x++) {
            # Format32bppArgb 在内存里是 BGRA 字节序，alpha 是第 4 个字节。
            # 阈值取 8 而不是 0：抗锯齿边缘会留下几乎看不见的残留 alpha。
            if ($bytes[$row + $x * 4 + 3] -gt 8) {
                if ($x -lt $minX) { $minX = $x }
                if ($x -gt $maxX) { $maxX = $x }
                if ($y -lt $minY) { $minY = $y }
                if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }
    if ($maxX -lt 0) {
        throw "logo 全透明，没有可用像素：$LogoPath"
    }
    New-Object System.Drawing.Rectangle $minX, $minY, ($maxX - $minX + 1), ($maxY - $minY + 1)
}

function New-HighQualityGraphics {
    param([Parameter(Mandatory)][System.Drawing.Bitmap]$Target)

    $g = [System.Drawing.Graphics]::FromImage($Target)
    $g.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g
}

function Save-WizardImage {
    <#
        欢迎页与完成页左侧的竖长条。比例固定 164:314，Setup 会把图拉到图像区尺寸，
        所以这里必须按给定的宽高精确出图，不能只出一张再指望它等比缩放。
    #>
    param(
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)][string]$Path
    )

    $bmp = New-Object System.Drawing.Bitmap $Width, $Height,
        ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = New-HighQualityGraphics -Target $bmp
    try {
        $area = New-Object System.Drawing.Rectangle 0, 0, $Width, $Height

        # 竖向柔和渐变。两个色阶只差一点点，目的是让大面积平色不显得死板，
        # 而不是做成显眼的渐变效果。
        $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $area, $CanvasTop, $CanvasBottom,
            [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
        try { $g.FillRectangle($brush, $area) } finally { $brush.Dispose() }

        # logo 宽度占栏宽 56%，视觉中心落在栏高 38% 处——向导标题在图的右侧上方，
        # logo 居中偏上才不会和标题在同一水平线上互相争。
        $logoWidth = [int][Math]::Round($Width * 0.56)
        $scale = $logoWidth / [double]$LogoBounds.Width
        $logoHeight = [int][Math]::Round($LogoBounds.Height * $scale)
        $dest = New-Object System.Drawing.Rectangle `
            ([int][Math]::Round(($Width - $logoWidth) / 2.0)),
            ([int][Math]::Round($Height * 0.38 - $logoHeight / 2.0)),
            $logoWidth, $logoHeight
        $g.DrawImage($Logo, $dest,
            $LogoBounds.X, $LogoBounds.Y, $LogoBounds.Width, $LogoBounds.Height,
            [System.Drawing.GraphicsUnit]::Pixel)

        # 底部品牌色条，作为左栏的收口。
        $barHeight = [Math]::Max(2, [int][Math]::Round($Height * 0.010))
        $barBrush = New-Object System.Drawing.SolidBrush $Signature
        try { $g.FillRectangle($barBrush, 0, $Height - $barHeight, $Width, $barHeight) }
        finally { $barBrush.Dispose() }

        # 右边缘细线，与向导右侧的白色内容区分隔。
        $lineWidth = [Math]::Max(1, [int][Math]::Round($Width / 202.0))
        $lineBrush = New-Object System.Drawing.SolidBrush $Structural
        try { $g.FillRectangle($lineBrush, $Width - $lineWidth, 0, $lineWidth, $Height - $barHeight) }
        finally { $lineBrush.Dispose() }
    }
    finally {
        $g.Dispose()
    }

    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

function Save-WizardSmallImage {
    <#
        除欢迎页/完成页外每一页右上角的小方图。
        背景留全透明：Inno Setup 6.6.0 起支持带 alpha 的 PNG，让 logo 直接与向导页
        自己的背景混合，比猜那块背景的确切颜色再填一层更稳——主题或版本换了也不会
        出现一个颜色略微不同的方块。
    #>
    param(
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][string]$Path
    )

    $bmp = New-Object System.Drawing.Bitmap $Size, $Size,
        ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = New-HighQualityGraphics -Target $bmp
    try {
        # 按长边等比缩放进正方形，四周留 6% 边距。logo 本身近似正方（430x451），
        # 按长边缩放不会在任一方向溢出。
        $inner = [int][Math]::Round($Size * 0.88)
        $longest = [Math]::Max($LogoBounds.Width, $LogoBounds.Height)
        $scale = $inner / [double]$longest
        $w = [int][Math]::Round($LogoBounds.Width * $scale)
        $h = [int][Math]::Round($LogoBounds.Height * $scale)
        $dest = New-Object System.Drawing.Rectangle `
            ([int][Math]::Round(($Size - $w) / 2.0)),
            ([int][Math]::Round(($Size - $h) / 2.0)),
            $w, $h
        $g.DrawImage($Logo, $dest,
            $LogoBounds.X, $LogoBounds.Y, $LogoBounds.Width, $LogoBounds.Height,
            [System.Drawing.GraphicsUnit]::Pixel)
    }
    finally {
        $g.Dispose()
    }

    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

# --- 主流程 ---------------------------------------------------------------------

Write-Host "logo       : $LogoPath" -ForegroundColor DarkGray
Write-Host "输出目录   : $OutputDir" -ForegroundColor DarkGray

$Logo = New-Object System.Drawing.Bitmap $LogoPath
try {
    Write-Host ("原图       : {0}x{1} {2}" -f $Logo.Width, $Logo.Height, $Logo.PixelFormat) -ForegroundColor DarkGray
    $LogoBounds = Get-OpaqueBounds -Bitmap $Logo
    Write-Host ("不透明区域 : {0},{1} {2}x{3}" -f `
        $LogoBounds.X, $LogoBounds.Y, $LogoBounds.Width, $LogoBounds.Height) -ForegroundColor DarkGray
    Write-Host ''

    $produced = [System.Collections.Generic.List[string]]::new()

    foreach ($size in $WizardImageSizes) {
        $name = 'WizardImage-{0}x{1}.png' -f $size.Width, $size.Height
        $path = Join-Path $OutputDir $name
        Save-WizardImage -Width $size.Width -Height $size.Height -Path $path
        $produced.Add($name)
        Write-Host ("   [生成]   {0,-28} {1,8:N0} 字节" -f $name, (Get-Item -LiteralPath $path).Length) `
            -ForegroundColor Green
    }

    foreach ($size in $SmallImageSizes) {
        $name = 'WizardSmallImage-{0}.png' -f $size
        $path = Join-Path $OutputDir $name
        Save-WizardSmallImage -Size $size -Path $path
        $produced.Add($name)
        Write-Host ("   [生成]   {0,-28} {1,8:N0} 字节" -f $name, (Get-Item -LiteralPath $path).Length) `
            -ForegroundColor Green
    }
}
finally {
    $Logo.Dispose()
}

Write-Host ''
Write-Host ("共 {0} 个文件。Ceasy.iss 的 WizardImageFile / WizardSmallImageFile 引用它们。" -f $produced.Count) `
    -ForegroundColor Cyan
Write-Host '改过 logo 或色板后重跑本脚本，然后重新编译安装包。' -ForegroundColor DarkGray
