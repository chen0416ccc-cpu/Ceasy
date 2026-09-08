#Requires -Version 5.1
<#
.SYNOPSIS
    构建 Ceasy 的 Windows 安装程序（单个 setup.exe）。

.DESCRIPTION
    独立于 work\package-release.ps1 运行，不触碰它的 outputs 事务目录，也不依赖它那套
    硬编码 SHA-256 基线。流程：

        1. 校验环境（pinned SDK、ISCC 编译器、简体中文语言文件）
        2. 把 CodexGuardian 与 Broker 发布到独立的 self-contained win-x64 目录
        3. 校验完整性，并用新构建验证器检查两套实际依赖和生产程序集边界
        4. 调 ISCC 编译 installer\Ceasy.iss
        5. 输出 setup.exe 并记录 SHA-256

    所有中间产物、TEMP 与输出默认落 D 盘，不占系统盘。

.PARAMETER StagingRoot
    发布与编译的暂存根目录，默认 D:\CodexData\CodexGuardian\installer-staging。

.PARAMETER OutputDir
    setup.exe 的输出目录，默认 <StagingRoot>\output。

.PARAMETER TempRoot
    构建临时目录；默认 <StagingRoot>\temp，可指定独立的阶段目录。

.PARAMETER SkipPublish
    复用 <StagingRoot>\publish 里已有的发布产物，只重新编译安装包。

.PARAMETER ValidateOnly
    只做环境与产物校验，不发布也不编译。

.PARAMETER PublishOnly
    只生成并验证两个隔离的运行目录，不编译 setup.exe，不安装或发布 Release。

.EXAMPLE
    pwsh -File work\build-installer.ps1

.EXAMPLE
    pwsh -File work\build-installer.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [string]$StagingRoot = 'D:\CodexData\CodexGuardian\installer-staging',
    [string]$OutputDir,
    [string]$TempRoot,
    [switch]$SkipPublish,
    [switch]$ValidateOnly,
    [switch]$PublishOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($ValidateOnly -and $PublishOnly) {
    throw '-ValidateOnly 与 -PublishOnly 不能同时使用。'
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Cyan
}

function Write-Detail {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "   $Message" -ForegroundColor DarkGray
}

function Assert-LastExitCode {
    param([Parameter(Mandatory)][string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation 失败，退出码 $LASTEXITCODE。"
    }
}

# ---------------------------------------------------------------------------
# 路径解析
# ---------------------------------------------------------------------------

$WorkRoot = $PSScriptRoot
$RepositoryRoot = Split-Path -Parent $WorkRoot

function Assert-ArtifactPath {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "产物路径必须是绝对路径：$Path" }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $full.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "构建产物与临时目录必须位于 D 盘：$full"
    }
    if ($full -eq [IO.Path]::GetPathRoot($full).TrimEnd('\') -or
        $full.Equals($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith($RepositoryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "产物不得写入驱动器根或源码树：$full"
    }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "产物路径包含重解析点：$cursor"
            }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        $cursor = if ($parent) { $parent.FullName } else { $null }
    }
    return $full
}

$StagingRoot = Assert-ArtifactPath $StagingRoot
$InstallerDir = Join-Path $WorkRoot 'installer'
$IssPath = Join-Path $InstallerDir 'Ceasy.iss'
$LanguageFile = Join-Path $InstallerDir 'Languages\ChineseSimplified.isl'
$GuardianProject = Join-Path $WorkRoot 'CodexGuardian\CodexGuardian.csproj'
$BrokerProject = Join-Path $WorkRoot 'CodexGuardian.Broker\CodexGuardian.Broker.csproj'
$TestsProject = Join-Path $WorkRoot 'CodexGuardian.Tests\CodexGuardian.Tests.csproj'
$IconPath = Join-Path $WorkRoot 'CodexGuardian\Assets\Ceasy.ico'
# 向导许可页的文本，[Languages] 按语言各引用一份。
$LicenseTexts = @(
    'License-ChineseSimplified.txt'
    'License-English.txt'
) | ForEach-Object { Join-Path $InstallerDir $_ }
# 随安装产物落地的许可与第三方声明，Ceasy.iss 的 [Files] 直接从仓库根引用。
$RepositoryNotices = @(
    'LICENSE'
    'THIRD-PARTY-NOTICES.md'
) | ForEach-Object { Join-Path $RepositoryRoot $_ }
# 向导品牌图片，由 installer\build-wizard-images.ps1 生成。Ceasy.iss 以逗号分隔的
# 多档尺寸引用它们，缺一档 ISCC 只会给一句「找不到文件」，这里先点名说清楚。
$WizardImages = @(
    'Assets\WizardImage-202x386.png'
    'Assets\WizardImage-336x643.png'
    'Assets\WizardImage-534x1022.png'
    'Assets\WizardSmallImage-58.png'
    'Assets\WizardSmallImage-97.png'
    'Assets\WizardSmallImage-159.png'
) | ForEach-Object { Join-Path $InstallerDir $_ }

$PublishDir = Join-Path $StagingRoot 'publish'
$BrokerPublishDir = Join-Path $PublishDir 'Broker'
if (-not $OutputDir) {
    $OutputDir = Join-Path $StagingRoot 'output'
}
$OutputDir = Assert-ArtifactPath $OutputDir
$ArtifactsRoot = Assert-ArtifactPath (Join-Path $StagingRoot 'artifacts')
if (-not $TempRoot) { $TempRoot = Join-Path $StagingRoot 'temp' }
$TempRoot = Assert-ArtifactPath $TempRoot

Write-Step '校验环境'
Write-Detail "仓库根       : $RepositoryRoot"
Write-Detail "暂存根       : $StagingRoot"
Write-Detail "发布目录     : $PublishDir"
Write-Detail "安装包输出   : $OutputDir"
Write-Detail "中间构建目录 : $ArtifactsRoot"

foreach ($required in @($IssPath, $LanguageFile, $GuardianProject, $BrokerProject, $TestsProject, $IconPath) +
                      $LicenseTexts + $RepositoryNotices) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "缺少必需文件：$required"
    }
}
Write-Detail 'Inno Setup 脚本、简体中文语言文件、两个项目文件、应用图标、两份许可页文本与第三方声明齐备。'

# 许可页文本的 BOM 检查。Inno 只在纯文本许可文件带 UTF-8 BOM 时才按 UTF-8 解读，
# 没有 BOM 会退回当前语言的 ANSI 代码页，中文那页整页乱码。而许可页只出现在交互式向导里，
# 静默安装看不到，verify-installer.ps1 也覆盖不到——这里不拦就只能等用户发现。
$Utf8Bom = [byte[]](0xEF, 0xBB, 0xBF)
foreach ($licenseText in $LicenseTexts) {
    $head = [System.IO.File]::ReadAllBytes($licenseText)
    $hasBom = $head.Length -ge 3 -and
        $head[0] -eq $Utf8Bom[0] -and $head[1] -eq $Utf8Bom[1] -and $head[2] -eq $Utf8Bom[2]
    if (-not $hasBom) {
        throw @"
$licenseText 缺少 UTF-8 BOM。

Inno Setup 只在纯文本许可文件带 BOM 时才按 UTF-8 解读，否则按当前语言的 ANSI 代码页
解读，中文许可页会整页乱码。请把该文件另存为「UTF-8 带 BOM」后重跑。
"@
    }
}
Write-Detail '两份许可页文本均带 UTF-8 BOM。'

$missingWizardImages = @($WizardImages | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
if ($missingWizardImages.Count -gt 0) {
    throw (
        "缺少向导品牌图片，先跑 work\installer\build-wizard-images.ps1 生成：`n    " +
        (($missingWizardImages | ForEach-Object { Split-Path $_ -Leaf }) -join "`n    "))
}
Write-Detail ("向导品牌图片齐备（{0} 档尺寸）。" -f $WizardImages.Count)

# ---------------------------------------------------------------------------
# 定位 ISCC.exe（Inno Setup 命令行编译器）
# ---------------------------------------------------------------------------

$IsccCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)

$IsccPath = $null
foreach ($candidate in $IsccCandidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
        $IsccPath = (Resolve-Path -LiteralPath $candidate).Path
        break
    }
}

if (-not $IsccPath) {
    $onPath = Get-Command -Name 'ISCC.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($onPath) {
        $IsccPath = $onPath.Source
    }
}

if (-not $IsccPath) {
    throw @'
找不到 Inno Setup 命令行编译器 ISCC.exe。安装方式：

    winget install --id JRSoftware.InnoSetup --exact

安装后重跑本脚本。
'@
}
Write-Detail "ISCC         : $IsccPath"

# ---------------------------------------------------------------------------
# 读取版本号：单一来源是 CodexGuardian.csproj 的 <Version>
# ---------------------------------------------------------------------------

[xml]$guardianXml = Get-Content -LiteralPath $GuardianProject -Raw
$AppVersion = ($guardianXml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1)
if (-not $AppVersion) {
    throw "无法从 $GuardianProject 读出 <Version>。"
}
$AppVersion = $AppVersion.ToString().Trim()
if ($AppVersion -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
    throw "从 csproj 读到的版本号形态异常：'$AppVersion'"
}
Write-Detail "产品版本     : $AppVersion"

# ---------------------------------------------------------------------------
# TEMP 重定向：构建期的临时文件不落系统盘
# ---------------------------------------------------------------------------

New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
$env:WINDIR = 'C:\Windows'
$env:SystemRoot = 'C:\Windows'
$env:DOTNET_CLI_HOME = Assert-ArtifactPath (Join-Path $StagingRoot 'dotnet-home')
$env:NUGET_PACKAGES = Assert-ArtifactPath (Join-Path $StagingRoot 'nuget-packages')
$env:NUGET_HTTP_CACHE_PATH = Assert-ArtifactPath (Join-Path $StagingRoot 'nuget-http')
$env:NUGET_PLUGINS_CACHE_PATH = Assert-ArtifactPath (Join-Path $StagingRoot 'nuget-plugins')
$env:NUGET_SCRATCH = Assert-ArtifactPath (Join-Path $TempRoot 'nuget')
$env:TEMP = $TempRoot
$env:TMP = $TempRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
Write-Detail "TEMP         : $TempRoot"

if ($ValidateOnly -and -not (Test-Path -LiteralPath $PublishDir)) {
    Write-Step '仅校验模式：环境检查通过，尚无发布产物可校验'
    return
}

# ---------------------------------------------------------------------------
# 发布 self-contained win-x64 产物
# ---------------------------------------------------------------------------

if ($ValidateOnly) {
    Write-Step '仅校验模式：跳过发布'
}
elseif ($SkipPublish) {
    Write-Step '复用已有发布产物（-SkipPublish）'
    if (-not (Test-Path -LiteralPath $PublishDir)) {
        throw "指定了 -SkipPublish，但 $PublishDir 不存在。"
    }
}
else {
    Write-Step '发布 self-contained win-x64 产物'

    if (Test-Path -LiteralPath $PublishDir) {
        throw "发布暂存目录已存在，请使用新的 StagingRoot；仅重编安装包时用 -SkipPublish：$PublishDir"
    }
    New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null

    foreach ($project in @($GuardianProject, $BrokerProject, $TestsProject)) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($project)
        Write-Detail "还原 $name"
        & dotnet restore $project -r win-x64 --locked-mode --configfile (Join-Path $WorkRoot 'NuGet.config') `
            "-p:ArtifactsPath=$ArtifactsRoot" -p:UseArtifactsOutput=true
        if ($LASTEXITCODE -ne 0) {
            throw @"
还原 $name 失败，退出码 $LASTEXITCODE。

若报 NU1004（锁定文件的运行时标识符不一致），说明 packages.lock.json 与 win-x64 目标
失配，需要先带 RID 重算锁文件：

    dotnet restore work\CodexGuardian.Control\CodexGuardian.Control.csproj -r win-x64 --force-evaluate

这会改动被追踪的 packages.lock.json，属于源码改动，因此本脚本不自动执行。
"@
        }
    }

    foreach ($project in @($GuardianProject, $BrokerProject)) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($project)
        # 两个 deps.json 选择不同的 Pkcs 提供者，不能合并同名 DLL。
        $destination = if ($project -eq $BrokerProject) { $BrokerPublishDir } else { $PublishDir }
        Write-Detail "发布 $name"
        & dotnet publish $project `
            -c Release `
            -r win-x64 `
            --self-contained true `
            --disable-build-servers `
            --no-restore `
            --artifacts-path $ArtifactsRoot `
            -p:CodexGuardianTestFriend=false `
            -o $destination
        Assert-LastExitCode "发布 $name"
    }
}

# ---------------------------------------------------------------------------
# 校验发布产物
# ---------------------------------------------------------------------------

Write-Step '校验发布产物'

$RequiredExecutables = @('CodexGuardian.exe', 'Broker\CodexGuardian.Broker.exe')
foreach ($exe in $RequiredExecutables) {
    $exePath = Join-Path $PublishDir $exe
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "发布产物缺少 $exe（查找路径 $exePath）。"
    }
}

if (Test-Path -LiteralPath (Join-Path $PublishDir 'CodexGuardian.Broker.exe')) {
    throw '检测到旧的混合运行目录；Broker 必须独立发布到 Broker 子目录，不能复用这个候选。'
}

foreach ($marker in @('hostfxr.dll', 'coreclr.dll', 'System.Security.Cryptography.Pkcs.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $BrokerPublishDir $marker))) {
        throw "Broker 隔离运行目录缺少 $marker。"
    }
}

# self-contained 的标志：运行时宿主与 WPF 原生库都必须在产物里，
# 否则用户机器上没装 .NET 8 桌面运行时就起不来。
$SelfContainedMarkers = @('hostfxr.dll', 'coreclr.dll', 'PresentationNative_cor3.dll')
foreach ($marker in $SelfContainedMarkers) {
    if (-not (Test-Path -LiteralPath (Join-Path $PublishDir $marker))) {
        throw "发布产物缺少 $marker，说明这不是 self-contained 发布。"
    }
}

# 已废弃的外部使用说明文件：使用说明已内置为 Views\UserGuidePage.xaml，
# 若它重新出现在产物里，说明 csproj 又被加回了 <None Include="UserGuide.md">。
$staleFiles = Get-ChildItem -LiteralPath $PublishDir -Filter 'UserGuide.md' -File -ErrorAction SilentlyContinue
if ($staleFiles) {
    throw '发布产物里出现了已废弃的 UserGuide.md，请移除 CodexGuardian.csproj 中对它的引用。'
}

$guardianExe = Join-Path $PublishDir 'CodexGuardian.exe'
$versionInfo = (Get-Item -LiteralPath $guardianExe).VersionInfo
if ($versionInfo.ProductName -ne 'Ceasy') {
    throw "CodexGuardian.exe 的 ProductName 是 '$($versionInfo.ProductName)'，期望 'Ceasy'。"
}

$expectedEntryVersion = [version]$AppVersion
if ($expectedEntryVersion.Revision -lt 0) {
    $expectedEntryVersion = [version]::new(
        $expectedEntryVersion.Major, $expectedEntryVersion.Minor, $expectedEntryVersion.Build, 0)
}
foreach ($entry in @($guardianExe, (Join-Path $BrokerPublishDir 'CodexGuardian.Broker.exe'))) {
    $entryVersion = (Get-Item -LiteralPath $entry).VersionInfo.FileVersion
    if ([version]$entryVersion -ne $expectedEntryVersion) {
        throw "发布入口版本不一致：$entry，实际 $entryVersion，项目 $AppVersion。"
    }
}

Write-Step '验证主程序与 Broker 的实际依赖闭包'
$TestsAssembly = Join-Path $ArtifactsRoot 'bin\CodexGuardian.Tests\release_win-x64\CodexGuardian.Tests.dll'
if (-not $ValidateOnly) {
    & dotnet build $TestsProject -c Release -r win-x64 --disable-build-servers `
        --artifacts-path $ArtifactsRoot -p:RestoreLockedMode=true --nologo
    Assert-LastExitCode '构建定向依赖验证器'
}
if (-not (Test-Path -LiteralPath $TestsAssembly -PathType Leaf)) {
    throw "缺少本阶段的依赖验证器：$TestsAssembly。不能只凭 exe 存在判定安装包完整。"
}

$runtimeRoles = @(
    @{ Name = 'CodexGuardian'; Root = $PublishDir },
    @{ Name = 'CodexGuardian.Broker'; Root = $BrokerPublishDir }
)
Push-Location $RepositoryRoot
try {
    foreach ($role in $runtimeRoles) {
        $verification = @(& dotnet $TestsAssembly --verify-published-runtime-closure `
            --published-runtime-root $role.Root `
            --published-runtime-nuget-packages-root $env:NUGET_PACKAGES `
            --published-runtime-root-assembly $role.Name --require-production-runtime-surface 2>&1)
        $verificationExit = $LASTEXITCODE
        $verification | ForEach-Object { Write-Host $_ }
        if ($verificationExit -ne 0 -or
            @($verification | Where-Object { "$_" -eq 'PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED' }).Count -ne 1 -or
            @($verification | Where-Object { "$_" -eq 'PUBLISHED_PRODUCTION_RUNTIME_SURFACE_VERIFIED' }).Count -ne 1) {
            throw "$($role.Name) 依赖或生产程序集边界验证失败，拒绝生成安装包。"
        }
    }
}
finally {
    Pop-Location
}

$publishFiles = Get-ChildItem -LiteralPath $PublishDir -Recurse -File
$publishBytes = ($publishFiles | Measure-Object -Property Length -Sum).Sum
Write-Detail ("文件数       : {0}" -f $publishFiles.Count)
Write-Detail ("产物体积     : {0:N1} MB" -f ($publishBytes / 1MB))
Write-Detail "ProductName  : $($versionInfo.ProductName)"
Write-Detail "FileVersion  : $($versionInfo.FileVersion)"

if ($ValidateOnly -or $PublishOnly) {
    Write-Step '两个隔离运行目录校验通过，不编译安装包'
    return
}

# ---------------------------------------------------------------------------
# 编译安装包
# ---------------------------------------------------------------------------

Write-Step '编译安装包'

if (Test-Path -LiteralPath $OutputDir) {
    if (Get-ChildItem -LiteralPath $OutputDir -Filter 'Ceasy-*-Setup.exe' -File) {
        throw "安装包输出目录已有候选包，请使用新的 OutputDir：$OutputDir"
    }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ISCC 的输出编码是 GBK，PowerShell 默认按 UTF-8 解会变成乱码。
$previousOutputEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)

    & $IsccPath `
        "/DPublishDir=$PublishDir" `
        "/DOutputDir=$OutputDir" `
        "/DAppVersion=$AppVersion" `
        $IssPath
    Assert-LastExitCode 'ISCC 编译'
}
finally {
    [Console]::OutputEncoding = $previousOutputEncoding
}

# ---------------------------------------------------------------------------
# 输出结果与校验和
# ---------------------------------------------------------------------------

Write-Step '结果'

$setupPath = Join-Path $OutputDir "Ceasy-$AppVersion-Setup.exe"
if (-not (Test-Path -LiteralPath $setupPath)) {
    throw "ISCC 报告成功，但没找到预期的安装包：$setupPath"
}

$setupItem = Get-Item -LiteralPath $setupPath
$setupHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash
$checksumPath = Join-Path $OutputDir 'SHA256SUMS.txt'
"$setupHash  $($setupItem.Name)" | Set-Content -LiteralPath $checksumPath -Encoding ASCII

Write-Host "安装包       : $setupPath" -ForegroundColor Green
Write-Host ("体积         : {0:N1} MB（压缩自 {1:N1} MB）" -f ($setupItem.Length / 1MB), ($publishBytes / 1MB)) -ForegroundColor Green
Write-Host "SHA-256      : $setupHash" -ForegroundColor Green
Write-Host "校验和文件   : $checksumPath" -ForegroundColor Green
Write-Host ''
Write-Host '安装体验：per-user 安装到 %LocalAppData%\Programs\Ceasy，不弹 UAC，安装目录可改。' -ForegroundColor DarkGray
Write-Host '安装包检查：powershell -ExecutionPolicy Bypass -File work\installer\verify-installer.ps1 -SetupExe <安装包绝对路径>' -ForegroundColor DarkGray
Write-Host '           默认只读；完整安装与卸载验证仅允许在显式指定的空白一次性环境执行，失败保留现场。' -ForegroundColor DarkGray
Write-Host '尚未覆盖：交互式安装向导的中文界面需人眼过一遍；安装包未做代码签名，' -ForegroundColor Yellow
Write-Host '           用户首次运行会看到 SmartScreen 未知发布者警告。' -ForegroundColor Yellow
