#Requires -Version 5.1
<#
.SYNOPSIS
    只读核对 package-release.ps1 里钉死的 SHA-256 基线是否仍与当前工作树、工具链一致。

.DESCRIPTION
    package-release.ps1 是 fail-closed 设计：任何一条钉死基线不符就整段拒绝发布。
    问题是它要跑到很深才报出来，而且会先做 restore/publish。本脚本把那些比对单独拎出来，
    纯只读、几秒钟跑完，用来回答"现在为什么发不了"。

    基线不在本脚本里复制一份，而是用 AST 从 package-release.ps1 原地提取，
    避免两处副本失同步。

    退出码 0 表示全部一致；1 表示至少一项漂移。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File work\check-release-baselines.ps1
#>
[CmdletBinding()]
param(
    [string]$ReleaseScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$WorkRoot = $PSScriptRoot
if (-not $ReleaseScript) {
    $ReleaseScript = Join-Path $WorkRoot 'package-release.ps1'
}
if (-not (Test-Path -LiteralPath $ReleaseScript)) {
    throw "找不到发布脚本：$ReleaseScript"
}

$script:Drift = 0
function Ok { param([string]$m) Write-Host "   [一致]   $m" -ForegroundColor Green }
function Bad {
    param([string]$m, [string]$expected, [string]$actual)
    Write-Host "   [漂移]   $m" -ForegroundColor Red
    Write-Host "            基线 $expected" -ForegroundColor DarkGray
    Write-Host "            实际 $actual" -ForegroundColor Yellow
    $script:Drift++
}
function Step { param([string]$m) Write-Host ''; Write-Host "== $m" -ForegroundColor Cyan }
function Info { param([string]$m) Write-Host "   ....   $m" -ForegroundColor DarkGray }

# --- 从 package-release.ps1 原地提取基线常量 ------------------------------------
# 这些常量全是字面量赋值（字符串、[ordered]@{}、[Version]'...'），
# 把赋值语句原文抽出来在本作用域里执行即可，不会带出发布脚本的任何副作用。

$WantedNames = @(
    'ExpectedGlobalJsonSha256'
    'ExpectedNuGetConfigSha256'
    'ExpectedControlLockFileSha256'
    'ExpectedProjectFileHashes'
    'ExpectedDotnetExecutablePath'
    'ExpectedDotnetExecutableSha256'
    'ExpectedDotnetExecutableLength'
    'ExpectedDotnetSdkVersion'
    'ExpectedDotnetSdkArtifacts'
    'ExpectedDotnetSdkArtifactLengths'
    'ExpectedProjectVersion'
    'ExpectedFileVersion'
)

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $ReleaseScript).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    throw "发布脚本自身有语法错误，先修它：$($errors[0].Message)"
}

$assignments = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [System.Management.Automation.Language.VariableExpressionAst]
}, $true)

$seen = @{}
$snippets = [System.Collections.Generic.List[string]]::new()
foreach ($a in $assignments) {
    $name = $a.Left.VariablePath.UserPath
    if ($WantedNames -notcontains $name) { continue }
    if ($seen.ContainsKey($name)) { continue }   # 只认第一次赋值，忽略后续重用
    $seen[$name] = $true
    $snippets.Add($a.Extent.Text)
}

$missing = @($WantedNames | Where-Object { -not $seen.ContainsKey($_) })
if ($missing.Count -gt 0) {
    throw ("发布脚本里找不到这些基线常量，说明它被重构过，本脚本需要同步更新：" +
        ($missing -join ', '))
}

. ([scriptblock]::Create($snippets -join "`n"))

Write-Host "核对对象   : $ReleaseScript" -ForegroundColor DarkGray
Write-Host "工作树     : $WorkRoot" -ForegroundColor DarkGray
Info ("提取到 {0} 条基线常量" -f $snippets.Count)

# --- 1. 受保护的源码文件 --------------------------------------------------------

Step '1. 受保护的源码文件哈希'

function Test-FileHashBaseline {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    $full = Join-Path $WorkRoot $RelativePath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Bad $RelativePath $ExpectedSha256 '文件不存在'
        return
    }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    if ([string]::Equals($actual, $ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        Ok $RelativePath
    }
    else {
        Bad $RelativePath $ExpectedSha256 $actual
    }
}

Test-FileHashBaseline 'global.json' $ExpectedGlobalJsonSha256
Test-FileHashBaseline 'NuGet.config' $ExpectedNuGetConfigSha256
Test-FileHashBaseline 'CodexGuardian.Control\packages.lock.json' $ExpectedControlLockFileSha256
foreach ($rel in $ExpectedProjectFileHashes.Keys) {
    Test-FileHashBaseline $rel ([string]$ExpectedProjectFileHashes[$rel])
}

# --- 2. 钉死的 .NET 工具链 ------------------------------------------------------

Step '2. 钉死的 .NET 工具链'

if (-not (Test-Path -LiteralPath $ExpectedDotnetExecutablePath -PathType Leaf)) {
    Bad 'dotnet host 路径' $ExpectedDotnetExecutablePath '不存在'
}
else {
    $hostItem = Get-Item -LiteralPath $ExpectedDotnetExecutablePath
    $hostHash = (Get-FileHash -LiteralPath $ExpectedDotnetExecutablePath -Algorithm SHA256).Hash
    if ([string]::Equals($hostHash, $ExpectedDotnetExecutableSha256, [StringComparison]::OrdinalIgnoreCase)) {
        Ok 'dotnet.exe SHA-256'
    }
    else {
        Bad 'dotnet.exe SHA-256' $ExpectedDotnetExecutableSha256 $hostHash
        # host muxer 会随 .NET 运行时补丁被整体替换，这是正常的系统更新行为而非篡改。
        # 判定依据是 Authenticode 签名，不是哈希本身。
        $sig = Get-AuthenticodeSignature -LiteralPath $ExpectedDotnetExecutablePath
        Info ("当前 host 签名 : {0} / {1}" -f $sig.Status, $sig.SignerCertificate.Subject)
        Info ("当前 host 版本 : {0}" -f $hostItem.VersionInfo.ProductVersion)
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Corporation*') {
            Info '签名有效且来自 Microsoft：属于运行时补丁导致的正常漂移，更新基线是安全的。'
        }
        else {
            Info '签名不可信：不要更新基线，先查工具链是否被替换。'
        }
    }

    if ($hostItem.Length -eq $ExpectedDotnetExecutableLength) {
        Ok 'dotnet.exe 文件长度'
    }
    else {
        Bad 'dotnet.exe 文件长度' ([string]$ExpectedDotnetExecutableLength) ([string]$hostItem.Length)
    }
}

$sdkRoot = Join-Path (Split-Path $ExpectedDotnetExecutablePath -Parent) ('sdk\' + $ExpectedDotnetSdkVersion)
if (-not (Test-Path -LiteralPath $sdkRoot -PathType Container)) {
    Bad "SDK $ExpectedDotnetSdkVersion 目录" $sdkRoot '不存在'
}
else {
    Ok "SDK $ExpectedDotnetSdkVersion 已安装"
    foreach ($rel in $ExpectedDotnetSdkArtifacts.Keys) {
        $p = Join-Path $sdkRoot $rel
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            Bad "SDK $rel" ([string]$ExpectedDotnetSdkArtifacts[$rel]) '不存在'
            continue
        }
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        if ([string]::Equals($h, [string]$ExpectedDotnetSdkArtifacts[$rel], [StringComparison]::OrdinalIgnoreCase)) {
            Ok "SDK $rel SHA-256"
        }
        else {
            Bad "SDK $rel SHA-256" ([string]$ExpectedDotnetSdkArtifacts[$rel]) $h
        }
        $len = (Get-Item -LiteralPath $p).Length
        if ($len -eq [long]$ExpectedDotnetSdkArtifactLengths[$rel]) {
            Ok "SDK $rel 文件长度"
        }
        else {
            Bad "SDK $rel 文件长度" ([string]$ExpectedDotnetSdkArtifactLengths[$rel]) ([string]$len)
        }
    }
}

# --- 3. 版本号一致性 ------------------------------------------------------------

Step '3. 版本号一致性'

$guardianProject = Join-Path $WorkRoot 'CodexGuardian\CodexGuardian.csproj'
[xml]$guardianXml = Get-Content -LiteralPath $guardianProject -Raw
$declaredVersion = ($guardianXml.Project.PropertyGroup.Version |
    Where-Object { $_ } | Select-Object -First 1)
if ($declaredVersion) { $declaredVersion = $declaredVersion.ToString().Trim() }
if ($declaredVersion -eq $ExpectedProjectVersion) {
    Ok "CodexGuardian.csproj <Version> = $ExpectedProjectVersion"
}
else {
    Bad 'CodexGuardian.csproj <Version>' $ExpectedProjectVersion ([string]$declaredVersion)
}
Info ("已发布 exe 需为 FileVersion {0}，本脚本不校验（需要发布产物）" -f $ExpectedFileVersion)

# --- 4. -ValidateOnly 的前置条件 ------------------------------------------------

Step '4. -ValidateOnly 的前置条件'

# 发布脚本对源码树里的 bin/obj 是 fail-closed 的：那些残留会让它在很早就拒绝执行。
# 这不是基线漂移，是可清理的前置条件，所以单独计数、不计入退出码。
$staleRoots = @()
$staleBytes = 0L
foreach ($projectDir in @(
        'CodexGuardian', 'CodexGuardian.Tests', 'CodexGuardian.Control',
        'CodexGuardian.Trust', 'CodexGuardian.Broker')) {
    foreach ($sub in @('bin', 'obj')) {
        $p = Join-Path (Join-Path $WorkRoot $projectDir) $sub
        if (Test-Path -LiteralPath $p -PathType Container) {
            $staleRoots += "$projectDir\$sub"
            $sum = (Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            if ($sum) { $staleBytes += [long]$sum }
        }
    }
}
if ($staleRoots.Count -eq 0) {
    Ok '源码树没有 bin/obj 残留'
}
else {
    Write-Host ("   [阻塞]   源码树存在 {0} 个 bin/obj 残留，共 {1:N1} MB" -f `
        $staleRoots.Count, ($staleBytes / 1MB)) -ForegroundColor Yellow
    Info ($staleRoots -join ', ')
    Info 'package-release.ps1 会因此 fail-closed。清掉它们只会让下次构建变成全量重编，'
    Info '但会打断正在用 bin 下产物调试的实例，所以本脚本不代为删除。'
}

# --- 汇总 ----------------------------------------------------------------------

Step '汇总'
if ($script:Drift -eq 0) {
    Write-Host '   全部基线与当前工作树、工具链一致。' -ForegroundColor Green
    exit 0
}
else {
    Write-Host "   有 $($script:Drift) 条基线漂移，见上面的 [漂移] 行。" -ForegroundColor Red
    Write-Host '   受保护源码文件漂移：确认改动是有意的之后，把实际值填回 package-release.ps1。' -ForegroundColor DarkGray
    Write-Host '   工具链漂移：先看签名判定，不要为了让脚本通过而盲目改基线。' -ForegroundColor DarkGray
    exit 1
}
