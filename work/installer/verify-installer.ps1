#Requires -Version 5.1
<#
.SYNOPSIS
    Ceasy 安装包实机验证：install → 启动 → 覆盖升级 → 降级拦截 → uninstall 全链路。

.DESCRIPTION
    必须在真实用户会话里跑（会读写 HKCU、开始菜单、桌面），结束时恢复到验证前的状态，
    不留安装痕迹。会短暂真正安装并启动程序，所以不要在 Ceasy 正在使用时执行。

    默认从 work\build-installer.ps1 的输出目录挑最新的 Ceasy-*-Setup.exe。

    覆盖不到的部分：交互式向导的中文界面（含许可页的排版）、向导品牌图片、以及
    「升级时跳过目录选择页」。静默安装不显示任何页面，那三项只能人眼过。

.PARAMETER SetupExe
    要验证的安装包路径。缺省时在 -OutputDir 里按修改时间取最新的 Ceasy-*-Setup.exe。

.PARAMETER OutputDir
    安装包所在目录，需与 build-installer.ps1 的 -OutputDir 一致。

.PARAMETER LogDir
    安装器/卸载器日志的落地目录，默认 <StagingRoot>\verify。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File work\installer\verify-installer.ps1
#>
[CmdletBinding()]
param(
    [string]$SetupExe,
    [string]$OutputDir = 'D:\CodexData\CodexGuardian\installer-staging\output',
    [string]$LogDir = 'D:\CodexData\CodexGuardian\installer-staging\verify'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $SetupExe) {
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        throw "安装包输出目录不存在：$OutputDir（先跑 work\build-installer.ps1）"
    }
    $candidate = Get-ChildItem -LiteralPath $OutputDir -Filter 'Ceasy-*-Setup.exe' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $candidate) {
        throw "在 $OutputDir 里找不到 Ceasy-*-Setup.exe（先跑 work\build-installer.ps1）"
    }
    $SetupExe = $candidate.FullName
}

$AppDir = Join-Path $env:LOCALAPPDATA 'Programs\Ceasy'
$DataDir = Join-Path $env:LOCALAPPDATA 'CodexGuardian'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValueName = 'CodexGuardian'
$StartMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Ceasy'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Ceasy.lnk'

$script:Failures = 0
function Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Ok { param([string]$m) Write-Host "   [OK]   $m" -ForegroundColor Green }
function Bad { param([string]$m) Write-Host "   [FAIL] $m" -ForegroundColor Red; $script:Failures++ }
function Info { param([string]$m) Write-Host "   ....   $m" -ForegroundColor DarkGray }

function Check {
    param([string]$Label, [bool]$Condition)
    if ($Condition) { Ok $Label } else { Bad $Label }
}

# 只终止本次验证自己装出来的那份实例。用户可能同时在跑开发构建或绿色版守护实例，
# 那些进程不属于本脚本，宁可中止验证也不能替用户杀掉——守护进程被静默终止会丢监控。
function Stop-Guardian {
    $procs = @(Get-Process -Name 'CodexGuardian', 'CodexGuardian.Broker' -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) { return }

    $foreign = @()
    $mine = @()
    foreach ($p in $procs) {
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        if ($path -and $path.StartsWith($AppDir, [StringComparison]::OrdinalIgnoreCase)) {
            $mine += $p
        }
        else {
            $foreign += [pscustomobject]@{ Id = $p.Id; Name = $p.ProcessName; Path = $path }
        }
    }

    if ($foreign.Count -gt 0) {
        $desc = ($foreign | ForEach-Object { "PID $($_.Id) $($_.Name) [$($_.Path)]" }) -join '; '
        throw @"
检测到不属于本次验证的 Guardian 进程，已中止：
    $desc
这些可能是你正在用的守护实例或开发构建。本脚本不会替你终止它们。
请自行关闭后重跑；安装器本身也需要独占单实例 Mutex。
"@
    }

    Info ("终止本次验证装出的实例：PID " + (($mine | ForEach-Object { $_.Id }) -join ', '))
    $mine | Stop-Process -Force
    Start-Sleep -Seconds 2
}

function Wait-Gone {
    param([string]$Path, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Test-Path -LiteralPath $Path) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    return -not (Test-Path -LiteralPath $Path)
}

# StrictMode 下直接点属性名取不存在的注册表值会抛 PropertyNotFoundStrict，
# 所以走 PSObject.Properties 判定。
function Get-RunValue {
    $item = Get-ItemProperty -Path $RunKey -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $prop = $item.PSObject.Properties[$RunValueName]
    if ($null -eq $prop) { return $null }
    return [string]$prop.Value
}

# 同理：卸载项集合里多数条目没有 DisplayName，StrictMode 下不能直接点属性。
function Get-CeasyUninstallEntries {
    return @(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object {
            $p = $_.PSObject.Properties['DisplayName']
            $null -ne $p -and ([string]$p.Value) -eq 'Ceasy'
        })
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# 快捷方式的鼠标悬停提示存在 .lnk 的 Description 字段里，只能通过 Shell COM 读。
function Get-ShortcutComment {
    param([string]$LinkPath)
    $shell = New-Object -ComObject WScript.Shell
    try {
        return [string]$shell.CreateShortcut($LinkPath).Description
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Step '0. 记录验证前状态'

if (-not (Test-Path -LiteralPath $SetupExe)) { throw "找不到安装包：$SetupExe" }
Info ("安装包：{0}（{1:N1} MB）" -f $SetupExe, ((Get-Item $SetupExe).Length / 1MB))

# setup.exe 自身的文件属性。缺了这些，用户右键看「详细信息」是一片空白，
# 企业软件清点与部分杀软的信誉判定也读它们。不需要安装就能验。
# Inno 在版本资源里给每个字段留了固定长度并用空格补齐（实测 ProductName 60 字符、
# LegalCopyright 100 字符），读出来全带尾随空格，所以比较前一律 Trim。
$SetupInfo = (Get-Item -LiteralPath $SetupExe).VersionInfo
$SetupProductName    = ([string]$SetupInfo.ProductName).Trim()
$SetupProductVersion = ([string]$SetupInfo.ProductVersion).Trim()
$SetupCompanyName    = ([string]$SetupInfo.CompanyName).Trim()
$SetupFileDesc       = ([string]$SetupInfo.FileDescription).Trim()
$SetupCopyright      = ([string]$SetupInfo.LegalCopyright).Trim()
Info ("安装包属性：ProductName={0} / ProductVersion={1} / Company={2}" -f `
    $SetupProductName, $SetupProductVersion, $SetupCompanyName)
Info ("            FileDescription={0} / LegalCopyright={1}" -f $SetupFileDesc, $SetupCopyright)
Check 'setup.exe 的 ProductName 为 Ceasy' ($SetupProductName -eq 'Ceasy')
Check 'setup.exe 带 CompanyName' (-not [string]::IsNullOrWhiteSpace($SetupCompanyName))
Check 'setup.exe 带 FileDescription' (-not [string]::IsNullOrWhiteSpace($SetupFileDesc))
Check 'setup.exe 带 LegalCopyright' (-not [string]::IsNullOrWhiteSpace($SetupCopyright))
Check 'setup.exe 的 ProductVersion 为 2.0.0' ($SetupProductVersion -eq '2.0.0')

# 代码签名状态如实记录，不作为通过/失败判定——当前没有代码签名证书。
$SetupSignature = Get-AuthenticodeSignature -LiteralPath $SetupExe
Info ("代码签名：{0}（未签名时用户首次运行会看到 SmartScreen 未知发布者警告）" -f $SetupSignature.Status)

# 外来实例检查必须排在任何副作用（临时数据目录、临时 Run 值）之前：
# Stop-Guardian 在这里 throw 就走不到第 8 步的恢复逻辑，不能留下需要清理的痕迹。
Stop-Guardian

$PreDataExists = Test-Path -LiteralPath $DataDir
$CreatedTestData = $false
$SentinelFile = Join-Path $DataDir 'installer-verify-sentinel.txt'
$PreDataCount = 0
if ($PreDataExists) {
    $PreDataCount = (Get-ChildItem -LiteralPath $DataDir -Recurse -File -ErrorAction SilentlyContinue).Count
    Info "数据目录已存在，含 $PreDataCount 个文件（卸载后必须仍然存在）"
}
else {
    # 造一个带标记文件的数据目录，用来真正验证"静默卸载不删用户数据"这条路径。
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Set-Content -LiteralPath $SentinelFile -Value 'installer verification sentinel' -Encoding ASCII
    $CreatedTestData = $true
    $PreDataCount = 1
    Info "数据目录原本不存在，已创建含 1 个标记文件的临时数据目录用于验证卸载不删数据"
}

# 记录并模拟"用户开过开机自启"，用于验证安装期路径刷新与卸载期清理
$PreRunValue = Get-RunValue
if ($PreRunValue) {
    Info "开机自启项原值：$PreRunValue"
}
else {
    Info '开机自启项原本不存在，临时写入一个旧路径值以验证安装期刷新与卸载期清理'
    Set-ItemProperty -Path $RunKey -Name $RunValueName -Value '"D:\stale\path\CodexGuardian.exe" --background'
}

Check '验证开始前系统中没有已安装的 Ceasy' (-not (Test-Path -LiteralPath $AppDir))

# ---------------------------------------------------------------------------
Step '1. 首次静默安装'

$installLog = Join-Path $LogDir 'install-1.log'
$p = Start-Process -FilePath $SetupExe -ArgumentList @(
    '/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS=desktopicon', "/LOG=$installLog"
) -Wait -PassThru
Check "安装器退出码为 0（实际 $($p.ExitCode)）" ($p.ExitCode -eq 0)

# ---------------------------------------------------------------------------
Step '2. 校验安装结果'

Check "安装目录存在：$AppDir" (Test-Path -LiteralPath $AppDir)
$installedExe = Join-Path $AppDir 'CodexGuardian.exe'
$brokerExe = Join-Path $AppDir 'CodexGuardian.Broker.exe'
$uninstExe = Join-Path $AppDir 'unins000.exe'
Check '主程序 CodexGuardian.exe 已安装' (Test-Path -LiteralPath $installedExe)
Check '辅助进程 CodexGuardian.Broker.exe 已安装' (Test-Path -LiteralPath $brokerExe)
Check '卸载程序 unins000.exe 已生成' (Test-Path -LiteralPath $uninstExe)
Check 'WPF 原生库 wpfgfx_cor3.dll 已安装（self-contained 完整性）' `
    (Test-Path -LiteralPath (Join-Path $AppDir 'wpfgfx_cor3.dll'))
Check '运行时宿主 hostfxr.dll 已安装' (Test-Path -LiteralPath (Join-Path $AppDir 'hostfxr.dll'))
Check '中文资源为内嵌默认语言，附带 en 卫星目录' (Test-Path -LiteralPath (Join-Path $AppDir 'en'))
Check '已废弃的 UserGuide.md 未被安装' (-not (Test-Path -LiteralPath (Join-Path $AppDir 'UserGuide.md')))
# MIT 要求在所有副本中保留许可声明，安装目录就是一份副本。这两个文件由 Ceasy.iss 的
# [Files] 从仓库根引用，不在发布产物里，所以只有装完才能验证它们真的落地了。
Check 'MIT 许可副本 LICENSE.txt 已安装' (Test-Path -LiteralPath (Join-Path $AppDir 'LICENSE.txt'))
Check '第三方声明 THIRD-PARTY-NOTICES.md 已安装' `
    (Test-Path -LiteralPath (Join-Path $AppDir 'THIRD-PARTY-NOTICES.md'))

$installedCount = (Get-ChildItem -LiteralPath $AppDir -Recurse -File).Count
$installedBytes = (Get-ChildItem -LiteralPath $AppDir -Recurse -File | Measure-Object Length -Sum).Sum
Info ("安装后文件数 {0}，占用 {1:N1} MB" -f $installedCount, ($installedBytes / 1MB))

Check '开始菜单程序组已创建' (Test-Path -LiteralPath $StartMenuDir)
$StartMenuLink = Join-Path $StartMenuDir 'Ceasy.lnk'
Check '开始菜单主快捷方式存在' (Test-Path -LiteralPath $StartMenuLink)
Check '桌面快捷方式存在（/TASKS=desktopicon）' (Test-Path -LiteralPath $DesktopLink)

if (Test-Path -LiteralPath $StartMenuLink) {
    $linkComment = Get-ShortcutComment -LinkPath $StartMenuLink
    Info "快捷方式悬停提示：$linkComment"
    Check '快捷方式带鼠标悬停提示（[Icons] 的 Comment）' (-not [string]::IsNullOrWhiteSpace($linkComment))
}

$uninstallEntries = @(Get-CeasyUninstallEntries)
$uninstallEntry = $uninstallEntries | Select-Object -First 1
Check '控制面板卸载项已注册到 HKCU' ($null -ne $uninstallEntry)
if ($uninstallEntry) {
    $dv = [string](Get-Prop $uninstallEntry 'DisplayVersion')
    $il = [string](Get-Prop $uninstallEntry 'InstallLocation')
    Info "DisplayName    : $(Get-Prop $uninstallEntry 'DisplayName')"
    Info "DisplayVersion : $dv"
    Info "InstallLocation: $il"
    Check '卸载项版本号为 2.0.0' ($dv -eq '2.0.0')
    Check '卸载项写在 HKCU（per-user 安装，无需管理员）' `
        ([string]$uninstallEntry.PSPath -like '*HKEY_CURRENT_USER*')
    # 这个值是 UsePreviousAppDir 的依据，「升级时跳过目录页」和降级检测都读它。
    $appPathValue = [string](Get-Prop $uninstallEntry 'Inno Setup: App Path')
    Info "App Path       : $appPathValue"
    Check '卸载项记录了安装目录（升级跳过目录页与降级检测都依赖它）' ($appPathValue -eq $AppDir)
    Check '卸载项带 Publisher' (-not [string]::IsNullOrWhiteSpace([string](Get-Prop $uninstallEntry 'Publisher')))
    Check '卸载项带 DisplayIcon' (-not [string]::IsNullOrWhiteSpace([string](Get-Prop $uninstallEntry 'DisplayIcon')))
}

$postRunValue = Get-RunValue
Info "安装后开机自启项：$postRunValue"
Check '开机自启项已被刷新到新安装路径' ($postRunValue -like "*$AppDir*")

# ---------------------------------------------------------------------------
Step '3. 启动安装后的程序'

# 用 --background 启动：这正是开机自启走的那条路径，同时避免抢占用户前台窗口。
$launched = Start-Process -FilePath $installedExe -ArgumentList '--background' -PassThru
Start-Sleep -Seconds 12
$alive = Get-Process -Id $launched.Id -ErrorAction SilentlyContinue
Check '安装后的程序能启动并持续运行 12 秒（未崩溃、无缺失依赖）' ($null -ne $alive)
if ($alive) {
    Info ("进程 PID {0}，工作集 {1:N0} MB" -f $alive.Id, ($alive.WorkingSet64 / 1MB))
    Check '进程主模块指向安装目录' ($alive.Path -eq $installedExe)
}
else {
    Info '进程已退出，读取事件日志中的 .NET 运行时错误：'
    Get-EventLog -LogName Application -Newest 40 -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -like '*NET Runtime*' -or $_.Message -like '*CodexGuardian*' } |
        Select-Object -First 3 |
        ForEach-Object { Info ($_.Message -split "`n")[0] }
}

Stop-Guardian

# ---------------------------------------------------------------------------
Step '4. 覆盖升级（在已安装状态下再次运行同一安装包）'

$upgradeLog = Join-Path $LogDir 'install-2-upgrade.log'
$p2 = Start-Process -FilePath $SetupExe -ArgumentList @(
    '/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$upgradeLog"
) -Wait -PassThru
Check "覆盖安装退出码为 0（实际 $($p2.ExitCode)）" ($p2.ExitCode -eq 0)
Check '覆盖后主程序仍存在' (Test-Path -LiteralPath $installedExe)

$upgradeCount = (Get-ChildItem -LiteralPath $AppDir -Recurse -File).Count
Check "覆盖后文件数未膨胀（$installedCount → $upgradeCount）" ($upgradeCount -eq $installedCount)

$entriesAfterUpgrade = @(Get-CeasyUninstallEntries)
Check "覆盖后卸载项仍只有 1 条（实际 $($entriesAfterUpgrade.Count) 条，AppId 稳定）" ($entriesAfterUpgrade.Count -eq 1)

# ---------------------------------------------------------------------------
Step '5. 降级保护（拿旧包覆盖更新的版本必须被拦住）'

# 把卸载项的 DisplayVersion 临时抬到 99.0.0，再静默装同一个包，就等价于「用旧包
# 覆盖新版」。Ceasy.iss 的 InitializeSetup 应该在静默模式下取默认的 No 并中止。
# 这一项同时验证了 DowngradeWarning 这条 CustomMessage 在 InitializeSetup 阶段确实
# 可用——语言初始化如果晚于 InitializeSetup，CustomMessage() 会让安装器直接报错，
# 而那种崩溃同样是非 0 退出码，所以下面还要查日志排除它。
$entryForDowngrade = @(Get-CeasyUninstallEntries) | Select-Object -First 1
if ($null -eq $entryForDowngrade) {
    Bad '降级保护：找不到卸载项，无法构造降级场景'
}
else {
    $downgradeKeyPath = [string]$entryForDowngrade.PSPath
    $realVersion = [string](Get-Prop $entryForDowngrade 'DisplayVersion')
    $downgradeLog = Join-Path $LogDir 'install-3-downgrade-blocked.log'
    try {
        Set-ItemProperty -Path $downgradeKeyPath -Name 'DisplayVersion' -Value '99.0.0'
        Info "已把 DisplayVersion 临时改为 99.0.0（原值 $realVersion）"

        $p4 = Start-Process -FilePath $SetupExe -ArgumentList @(
            '/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$downgradeLog"
        ) -Wait -PassThru
        Check "降级安装被拒绝（退出码 $($p4.ExitCode)，0 表示没拦住）" ($p4.ExitCode -ne 0)
        Check '降级被拒后原有安装仍然完好' (Test-Path -LiteralPath $installedExe)

        # 排除「因为脚本自身报错才非 0」这种假通过。日志里 match 的是英文关键词，
        # 所以不受 Get-Content 默认按 ANSI 解码中文的影响。
        $downgradeLogText = ''
        if (Test-Path -LiteralPath $downgradeLog) {
            $downgradeLogText = [string](Get-Content -LiteralPath $downgradeLog -Raw -ErrorAction SilentlyContinue)
        }
        Check '拦截来自降级检查本身，不是 Pascal 脚本运行时错误' `
            ($downgradeLogText -notmatch 'Runtime [Ee]rror' -and
             $downgradeLogText -notmatch 'Unknown custom message' -and
             $downgradeLogText -notmatch 'Internal error')
    }
    finally {
        Set-ItemProperty -Path $downgradeKeyPath -Name 'DisplayVersion' -Value $realVersion
        Info "已恢复 DisplayVersion 为 $realVersion"
    }
}

# ---------------------------------------------------------------------------
Step '6. 静默卸载'

# /SUPPRESSMSGBOXES 下"是否删除用户数据"的询问会取默认按钮（No），即保留数据。
$uninstallLog = Join-Path $LogDir 'uninstall.log'
$p3 = Start-Process -FilePath $uninstExe -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$uninstallLog"
) -Wait -PassThru
Info "卸载器退出码 $($p3.ExitCode)"
Check '安装目录已被完全移除' (Wait-Gone -Path $AppDir -TimeoutSeconds 90)

# ---------------------------------------------------------------------------
Step '7. 校验卸载后的清理与数据保留'

Check '开始菜单程序组已移除' (-not (Test-Path -LiteralPath $StartMenuDir))
Check '桌面快捷方式已移除' (-not (Test-Path -LiteralPath $DesktopLink))

$entriesAfterUninstall = @(Get-CeasyUninstallEntries)
Check '控制面板卸载项已移除' ($entriesAfterUninstall.Count -eq 0)

$finalRunValue = Get-RunValue
Check '开机自启项已清理，未留下指向已删除 exe 的死启动项' ($null -eq $finalRunValue)
if ($finalRunValue) { Info "残留值：$finalRunValue" }

Check "用户数据目录在静默卸载后保留（$DataDir）" (Test-Path -LiteralPath $DataDir)
$postDataCount = 0
if (Test-Path -LiteralPath $DataDir) {
    $postDataCount = (Get-ChildItem -LiteralPath $DataDir -Recurse -File -ErrorAction SilentlyContinue).Count
}
Check "数据目录文件数未减少（$PreDataCount → $postDataCount）" ($postDataCount -ge $PreDataCount)
if ($CreatedTestData) {
    Check '标记文件在卸载后仍然存在' (Test-Path -LiteralPath $SentinelFile)
}

# ---------------------------------------------------------------------------
Step '8. 恢复验证前状态'

if ($PreRunValue) {
    Set-ItemProperty -Path $RunKey -Name $RunValueName -Value $PreRunValue
    Info '已恢复原有的开机自启项'
}
else {
    Remove-ItemProperty -Path $RunKey -Name $RunValueName -ErrorAction SilentlyContinue
    Info '已移除测试用的临时开机自启项'
}

if ($CreatedTestData -and (Test-Path -LiteralPath $DataDir)) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Info '已移除验证用的临时数据目录'
}

Step '汇总'
if ($script:Failures -eq 0) {
    Write-Host '   全部检查项通过：install / 启动 / upgrade / 降级拦截 / uninstall 五条路径均已实机验证。' -ForegroundColor Green
    Write-Host '   注意：交互式向导的中文界面（含许可页排版）、品牌图片和「升级时跳过目录页」只能人眼验证，' -ForegroundColor DarkGray
    Write-Host '   静默安装不显示任何页面，本脚本覆盖不到。' -ForegroundColor DarkGray
    exit 0
}
else {
    Write-Host "   有 $($script:Failures) 项检查失败，见上面的 [FAIL] 行。" -ForegroundColor Red
    exit 1
}
