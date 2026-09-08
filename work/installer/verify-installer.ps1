#Requires -Version 5.1
<#
.SYNOPSIS
    默认只读检查安装包；只有空白一次性环境可执行安装生命周期验证。
.DESCRIPTION
    默认不创建目录、不启动程序、不修改注册表、不安装或卸载。
    -Execute 必须同时指定 -DisposableEnvironment，通过所有真实环境检查。
    现有安装、用户数据、快捷方式、自启项、Guardian 进程都会阻止执行。
    运行只用 D 盘独立目录和 --safe-preview，失败保留现场，不自动卸载或删除。
    不验证默认用户数据迁移、自启迁移、真实监控、交互向导或 DPI。
.PARAMETER OlderSetupExe
    执行模式必需的真实旧版安装包，不再篡改注册表版本模拟降级。
.EXAMPLE
    pwsh -File work\installer\verify-installer.ps1 -SetupExe D:\CodexData\CodexGuardian\candidate\output\Ceasy-2.1.0-Setup.exe
#>
[CmdletBinding()]
param(
    [string]$SetupExe,
    [string]$OutputDir = 'D:\CodexData\CodexGuardian\installer-staging\output',
    [string]$LogDir = 'D:\CodexData\CodexGuardian\installer-validation',
    [string]$TempRoot = 'D:\CodexTemp\CodexGuardian\installer-validation',
    [string]$OlderSetupExe,
    [switch]$Execute,
    [switch]$DisposableEnvironment
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Comparison = [StringComparison]::OrdinalIgnoreCase
function Assert-Check {
    param([string]$Message, [bool]$Condition)
    if (-not $Condition) { throw $Message }
}
function Resolve-PhasePath {
    param([string]$Path, [string]$AllowedRoot)
    Assert-Check "路径必须为绝对路径：$Path" ([IO.Path]::IsPathRooted($Path))
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    Assert-Check "路径必须位于指定 D 盘根的子目录：$Path" (
        $full.StartsWith($AllowedRoot.TrimEnd('\') + '\', $Comparison))
    Assert-Check "产物不能位于源码树：$Path" (
        -not $full.StartsWith($RepositoryRoot.TrimEnd('\') + '\', $Comparison))
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            Assert-Check "路径包含重解析点：$cursor" (
                -not ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint))
        }
        $parent = [IO.Directory]::GetParent($cursor)
        $cursor = if ($parent) { $parent.FullName } else { $null }
    }
    return $full
}
function Get-PackageIdentity {
    param([string]$Path)
    $full = Resolve-PhasePath $Path 'D:\CodexData\CodexGuardian'
    $file = Get-Item -LiteralPath $full
    Assert-Check "安装包不是文件：$full" (-not $file.PSIsContainer)
    Assert-Check "安装包产品名不是 Ceasy：$full" ($file.VersionInfo.ProductName.Trim() -eq 'Ceasy')
    foreach ($field in @('CompanyName', 'FileDescription', 'LegalCopyright')) {
        Assert-Check "安装包缺少属性：$field" (-not [string]::IsNullOrWhiteSpace($file.VersionInfo.$field))
    }
    [pscustomobject]@{
        Path = $full; Length = $file.Length; LastWriteTimeUtc = $file.LastWriteTimeUtc
        Sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
        Version = $file.VersionInfo.ProductVersion.Trim()
        Signature = [string](Get-AuthenticodeSignature -LiteralPath $full).Status
    }
}
function Get-UninstallEntries {
    $id = '{8F3A1C9E-7D42-4B58-A6E1-2C5B9D0F4A73}_is1'
    foreach ($hive in @('HKCU:', 'HKLM:')) {
        foreach ($branch in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
            $root = "$hive\$branch\Microsoft\Windows\CurrentVersion\Uninstall"
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($key in Get-ChildItem -LiteralPath $root) {
                $value = Get-ItemProperty -LiteralPath $key.PSPath
                $name = $value.PSObject.Properties['DisplayName']
                if ($key.PSChildName -eq $id -or ($name -and [string]$name.Value -eq 'Ceasy')) { $value }
            }
        }
    }
}
function Get-GuardianProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name='CodexGuardian.exe' OR Name='CodexGuardian.Broker.exe'")
}
$LogDir = Resolve-PhasePath $LogDir 'D:\CodexData\CodexGuardian'
$TempRoot = Resolve-PhasePath $TempRoot 'D:\CodexTemp\CodexGuardian'
$AppDir = Resolve-PhasePath (Join-Path $LogDir 'app') 'D:\CodexData\CodexGuardian'
$DataDir = Resolve-PhasePath (Join-Path $LogDir 'test-data') 'D:\CodexData\CodexGuardian'
$LiveDataDir = Join-Path $env:LOCALAPPDATA 'CodexGuardian'
$StartMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Ceasy'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Ceasy.lnk'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not $SetupExe) {
    $candidate = Get-ChildItem -LiteralPath $OutputDir -Filter 'Ceasy-*-Setup.exe' -File |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Assert-Check "在 $OutputDir 找不到安装包。" ($null -ne $candidate)
    $SetupExe = $candidate.FullName
}
$package = Get-PackageIdentity $SetupExe
[xml]$project = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'work\CodexGuardian\CodexGuardian.csproj') -Raw
$expectedVersion = [string]$project.SelectSingleNode('/Project/PropertyGroup/Version').InnerText
Assert-Check "安装包版本 $($package.Version) 与当前项目 $expectedVersion 不一致。" ($package.Version -eq $expectedVersion)
$olderPackage = if ($OlderSetupExe) { Get-PackageIdentity $OlderSetupExe } else { $null }
if ($olderPackage) {
    Assert-Check '降级检查必须提供版本确实更低的真实安装包。' ([version]$olderPackage.Version -lt [version]$package.Version)
}
$blockers = [Collections.Generic.List[string]]::new()
if (@(Get-UninstallEntries).Count -ne 0) { $blockers.Add('检测到现有 Ceasy 卸载注册项；不会升级或卸载用户安装。') }
foreach ($path in @($LiveDataDir, $StartMenuDir, $DesktopLink,
        (Join-Path $env:LOCALAPPDATA 'Programs\Ceasy'), 'D:\Ceasy', $LogDir, $TempRoot)) {
    if (Test-Path -LiteralPath $path) { $blockers.Add("保护已有路径，不覆盖：$path") }
}
$run = Get-ItemProperty -LiteralPath $RunKey -ErrorAction SilentlyContinue
if ($run -and $run.PSObject.Properties['CodexGuardian']) { $blockers.Add('检测到现有自启项；不会改写。') }
if (@(Get-GuardianProcesses).Count -ne 0) { $blockers.Add('检测到 Guardian 进程；不会终止任何既有实例。') }
if ((Get-PSDrive D).Free -lt 1GB) { $blockers.Add('D 盘可用空间不足 1 GiB。') }
[pscustomobject]@{
    Mode = if ($Execute) { 'ExecuteRequested' } else { 'ReadOnly' }
    Package = $package; ExpectedVersion = $expectedVersion; OlderPackage = $olderPackage
    ArtifactRoot = $LogDir; TempRoot = $TempRoot
    InstallDirectory = $AppDir; IsolatedDataDirectory = $DataDir
    OsIntegrationPaths = @($StartMenuDir, $DesktopLink, $RunKey,
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
    EnvironmentBlockers = $blockers.ToArray()
    ExecuteAllowed = ($blockers.Count -eq 0 -and $DisposableEnvironment -and $null -ne $olderPackage)
    LifecycleVerified = $false
} | ConvertTo-Json -Depth 5
if (-not $Execute) {
    Write-Host '只读检查完成；没有安装、卸载、启动应用、创建目录或修改配置。'
    return
}
Assert-Check '必须显式指定 -DisposableEnvironment，在空白一次性测试环境执行。' $DisposableEnvironment
Assert-Check ('安装生命周期验证已拒绝：' + ($blockers -join [Environment]::NewLine)) ($blockers.Count -eq 0)
Assert-Check '执行模式必须提供 -OlderSetupExe，不能伪造降级版本。' ($null -ne $olderPackage)
$env:WINDIR = 'C:\Windows'; $env:SystemRoot = 'C:\Windows'
$env:TEMP = $TempRoot; $env:TMP = $TempRoot
New-Item -ItemType Directory -Path $LogDir, $TempRoot, $DataDir | Out-Null
$steps = [Collections.Generic.List[object]]::new()
$script:owned = $null
function Save-Report {
    param([string]$Status, [string]$Failure)
    $report = [ordered]@{
        Status = $Status; Failure = $Failure; Package = $package; OlderPackage = $olderPackage
        ArtifactRoot = $LogDir; TempRoot = $TempRoot; Steps = $steps.ToArray()
        DefaultUserDataMigrationVerified = $false; StartupMigrationVerified = $false
        LiveMonitoringVerified = $false; VisualMatrixVerified = $false; EvidenceRetained = $true
    }
    $pending = Join-Path $LogDir 'result.pending.json'
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $pending -Encoding UTF8
    Move-Item -LiteralPath $pending -Destination (Join-Path $LogDir 'result.json') -Force
}
function Invoke-Setup {
    param($Identity, [string]$LogName)
    Assert-Check '测试期间出现 Guardian 进程，已停止安装操作。' (@(Get-GuardianProcesses).Count -eq 0)
    Assert-Check '安装包字节在验证后变化，已停止。' (
        (Get-FileHash -LiteralPath $Identity.Path -Algorithm SHA256).Hash -eq $Identity.Sha256)
    $p = Start-Process -FilePath $Identity.Path -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS=desktopicon',
        ('/DIR="{0}"' -f $AppDir), ('/LOG="{0}"' -f (Join-Path $LogDir $LogName))
    ) -WindowStyle Hidden -Wait -PassThru
    $steps.Add([pscustomobject]@{ Step = $LogName; ExitCode = $p.ExitCode })
    return $p.ExitCode
}
function Get-InstalledManifest {
    @(Get-ChildItem -LiteralPath $AppDir -File -Recurse | Sort-Object FullName | ForEach-Object {
        '{0}|{1}|{2}' -f $_.FullName.Substring($AppDir.Length), $_.Length,
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
}
function Assert-OwnedInstall {
    $entries = @(Get-UninstallEntries)
    Assert-Check '卸载注册项数量不是 1。' ($entries.Count -eq 1)
    $entry = $entries[0]
    Assert-Check '卸载项不属于当前用户或测试安装目录。' (
        $entry.PSPath -like '*HKEY_CURRENT_USER*' -and
        [string]$entry.'Inno Setup: App Path' -eq $AppDir -and [string]$entry.DisplayVersion -eq $package.Version)
}
function Stop-OwnedPreview {
    if (-not $script:owned) { return }
    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:owned.ProcessId)"
    if (-not $current) {
        $script:owned = $null
        throw '预览在正常关闭检查前已经退出，不能计为正常退出验收。'
    }
    Assert-Check '预览进程身份变化；拒绝终止。' (
        $current.ExecutablePath -eq $script:owned.ExecutablePath -and
        $current.CreationDate -eq $script:owned.CreationDate -and $current.CommandLine -eq $script:owned.CommandLine)
    $p = Get-Process -Id $current.ProcessId
    $closed = $p.CloseMainWindow() -and $p.WaitForExit(10000)
    if (-not $closed) {
        # 等待后重新校验创建时间、路径和命令行，PID 本身不是实例身份。
        $again = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:owned.ProcessId)"
        if ($again) {
            Assert-Check '等待退出期间进程身份变化；拒绝终止。' (
                $again.CreationDate -eq $script:owned.CreationDate -and
                $again.ExecutablePath -eq $script:owned.ExecutablePath -and $again.CommandLine -eq $script:owned.CommandLine)
            Stop-Process -Id $again.ProcessId -Force
            Assert-Check '预览进程未在限定时间内退出。' ($p.WaitForExit(10000))
        }
    }
    $steps.Add([pscustomobject]@{ Step = 'preview-exit'; GracefulWindowExit = [bool]$closed })
    $script:owned = $null
    Assert-Check '预览未正常关闭；受控终止不计为正常退出验收。' ([bool]$closed)
}
try {
    Assert-Check '首次安装失败。' ((Invoke-Setup $package 'install.log') -eq 0)
    Assert-OwnedInstall
    $exe = Join-Path $AppDir 'CodexGuardian.exe'
    foreach ($name in @('CodexGuardian.exe', 'Broker\CodexGuardian.Broker.exe',
            'Broker\System.Security.Cryptography.Pkcs.dll', 'Broker\hostfxr.dll', 'wpfgfx_cor3.dll',
            'hostfxr.dll', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.md', 'unins000.exe')) {
        Assert-Check "安装缺少必需文件：$name" (Test-Path -LiteralPath (Join-Path $AppDir $name) -PathType Leaf)
    }
    Assert-Check '安装后仍存在旧的根目录 Broker 入口。' (
        -not (Test-Path -LiteralPath (Join-Path $AppDir 'CodexGuardian.Broker.exe')))
    Assert-Check '安装仍带已废弃帮助文件。' (-not (Test-Path -LiteralPath (Join-Path $AppDir 'UserGuide.md')))
    Assert-Check '英文卫星资源缺失。' (Test-Path -LiteralPath (Join-Path $AppDir 'en'))
    Assert-Check '桌面或开始菜单快捷方式缺失。' (
        (Test-Path -LiteralPath $DesktopLink) -and (Test-Path -LiteralPath (Join-Path $StartMenuDir 'Ceasy.lnk')))
    $arguments = '--safe-preview --follow-up-preview-fixture --data-directory "{0}"' -f $DataDir
    $p = Start-Process -FilePath $exe -WorkingDirectory $AppDir -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $script:owned = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)"
    Assert-Check '未能记录测试预览进程身份。' ($null -ne $script:owned)
    Assert-Check '测试进程不符合隔离约定。' (
        $script:owned.ExecutablePath -eq $exe -and $script:owned.CommandLine.Contains($arguments))
    Start-Sleep -Seconds 12
    Assert-Check '隔离预览未持续运行 12 秒。' (-not $p.HasExited)
    Stop-OwnedPreview
    Assert-Check '隔离预览意外创建默认用户数据目录。' (-not (Test-Path -LiteralPath $LiveDataDir))
    $dataBefore = @(Get-ChildItem -LiteralPath $DataDir -Recurse -File | Sort-Object FullName | ForEach-Object {
        '{0}|{1}' -f $_.FullName, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    Assert-Check '预览没有生成可验证的隔离数据。' ($dataBefore.Count -gt 0)
    $before = @(Get-InstalledManifest)
    Assert-Check '同版本覆盖安装失败。' ((Invoke-Setup $package 'overinstall.log') -eq 0)
    Assert-OwnedInstall
    Assert-Check '覆盖安装改变了文件清单。' (
        -not (Compare-Object @($before | ForEach-Object { ($_ -split '\|')[0] }) @(
            Get-InstalledManifest | ForEach-Object { ($_ -split '\|')[0] })))
    # Inno 会更新自己的卸载账本，其余负载必须逐字节保持一致。
    $payloadBefore = @($before | Where-Object { $_ -notmatch '^\\unins\d+\.' })
    $payloadAfter = @(Get-InstalledManifest | Where-Object { $_ -notmatch '^\\unins\d+\.' })
    Assert-Check '覆盖安装改变了产品负载字节。' (-not (Compare-Object $payloadBefore $payloadAfter))
    $beforeDowngrade = @(Get-InstalledManifest)
    Assert-Check '真实旧版本安装没有被拒绝。' ((Invoke-Setup $olderPackage 'downgrade.log') -ne 0)
    $downgradeLog = Get-Content -LiteralPath (Join-Path $LogDir 'downgrade.log') -Raw
    Assert-Check '降级退出由安装脚本错误导致，不能计为保护通过。' (
        $downgradeLog -notmatch '(?i)runtime error|unknown custom message|internal error')
    Assert-OwnedInstall
    Assert-Check '降级尝试改变了安装文件。' (-not (Compare-Object $beforeDowngrade @(Get-InstalledManifest)))
    Assert-Check '卸载前出现 Guardian 进程，拒绝卸载。' (@(Get-GuardianProcesses).Count -eq 0)
    Assert-OwnedInstall
    $null = Resolve-PhasePath $AppDir 'D:\CodexData\CodexGuardian'
    $u = Start-Process -FilePath (Join-Path $AppDir 'unins000.exe') -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        ('/LOG="{0}"' -f (Join-Path $LogDir 'uninstall.log'))
    ) -WindowStyle Hidden -Wait -PassThru
    $steps.Add([pscustomobject]@{ Step = 'uninstall'; ExitCode = $u.ExitCode })
    Assert-Check '卸载器退出码不是 0。' ($u.ExitCode -eq 0)
    $deadline = (Get-Date).AddSeconds(90)
    while ((Test-Path -LiteralPath $AppDir) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    Assert-Check '卸载后的安装目录仍存在。' (-not (Test-Path -LiteralPath $AppDir))
    Assert-Check '卸载后仍存在注册项或快捷方式。' (
        @(Get-UninstallEntries).Count -eq 0 -and -not (Test-Path -LiteralPath $StartMenuDir) -and
        -not (Test-Path -LiteralPath $DesktopLink))
    $dataAfter = @(Get-ChildItem -LiteralPath $DataDir -Recurse -File | Sort-Object FullName | ForEach-Object {
        '{0}|{1}' -f $_.FullName, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    Assert-Check '卸载改变了隔离数据。' (-not (Compare-Object $dataBefore $dataAfter))
    Assert-Check '生命周期验证意外创建默认用户数据目录。' (-not (Test-Path -LiteralPath $LiveDataDir))
    Save-Report 'Passed' ''
    Write-Host '一次性环境的安装、隔离预览、同版本覆盖、真实旧包降级拦截和卸载通过；证据保留。'
}
catch {
    $failure = $_.Exception.Message
    try { Stop-OwnedPreview } catch { $failure += "；预览收尾：$($_.Exception.Message)" }
    Save-Report 'Failed' $failure
    throw
}
