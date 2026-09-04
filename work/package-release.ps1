param(
    [switch]$ValidateOnly,
    [string]$ScratchRoot,
    [Parameter(DontShow = $true)]
    [string]$InternalReleaseTransactionRequestPath
)

$ErrorActionPreference = 'Stop'
$currentHostInjectionVariables = @(Get-ChildItem Env: -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^(?i:COR_|CORECLR_|COMPlus_)' -or
    $_.Name -in @(
        'DOTNET_DiagnosticPorts',
        'DOTNET_EnableDiagnostics'
    )
} | ForEach-Object { [string]$_.Name })
if ($currentHostInjectionVariables.Count -gt 0) {
    throw (
        'The current PowerShell host environment contains forbidden CLR injection variables: ' +
        ($currentHostInjectionVariables -join ', '))
}
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'

$WorkRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$RepositoryRoot = [System.IO.Path]::GetFullPath((Split-Path $WorkRoot -Parent))
$ProjectRoot = Join-Path $WorkRoot 'CodexGuardian'
$ProjectFile = Join-Path $ProjectRoot 'CodexGuardian.csproj'
$TestsRoot = Join-Path $WorkRoot 'CodexGuardian.Tests'
$TestsProject = Join-Path $TestsRoot 'CodexGuardian.Tests.csproj'
$ControlRoot = Join-Path $WorkRoot 'CodexGuardian.Control'
$ControlProject = Join-Path $ControlRoot 'CodexGuardian.Control.csproj'
$ControlLockFilePath = Join-Path $ControlRoot 'packages.lock.json'
$TrustRoot = Join-Path $WorkRoot 'CodexGuardian.Trust'
$TrustProject = Join-Path $TrustRoot 'CodexGuardian.Trust.csproj'
$BrokerProbeRoot = Join-Path $WorkRoot 'CodexGuardian.Broker'
$BrokerProbeProject = Join-Path $BrokerProbeRoot 'CodexGuardian.Broker.csproj'
$SourceProjectRoots = @($ProjectRoot, $TestsRoot, $ControlRoot, $TrustRoot, $BrokerProbeRoot)
$GlobalJsonPath = Join-Path $WorkRoot 'global.json'
$NuGetConfigPath = Join-Path $WorkRoot 'NuGet.config'
$ExpectedGlobalJsonSha256 = '05CB6A541BB9EAAD38D13300C6557AA8BECD0A04B0D570DB4181CDD654C89001'
$ExpectedNuGetConfigSha256 = '1B7D09F1EFC7B80C109803EB4CF3CA5EAFA6D392D87061F89DD256FECD520362'
$ExpectedControlLockFileSha256 = 'A94F3A16B20FF4CB3B0AE2EE7BBE6301892DE225F921C2309B40FD1EDDDDD6D7'
$ExpectedProjectFileHashes = [ordered]@{
    'CodexGuardian\CodexGuardian.csproj' = 'C413A86557D667F642421FD67C3894A0EBBA2E67CA0229FCF9A02F9331C37D1E'
    'CodexGuardian.Tests\CodexGuardian.Tests.csproj' = '88980B1FBFB626E55CA011F528692D152334B544CFFD4AFA07AA55C903CFCD3D'
    'CodexGuardian.Control\CodexGuardian.Control.csproj' = '0CC5F00AB2F48C9BF8F3119C1C09486D6A37A0D0B85A6CCBF944358D02CBDE59'
    'CodexGuardian.Trust\CodexGuardian.Trust.csproj' = 'CA5D75EE5364BAB04B177E8E47C0B9429AE809D5B481A752506372A5A0C77E58'
    'CodexGuardian.Broker\CodexGuardian.Broker.csproj' = 'D96A82986D70FF3914DBFA522C9B06DF29A95D0E2603C81843D3CB864A1B2374'
}
$ExpectedDotnetExecutablePath = 'C:\Program Files\dotnet\dotnet.exe'
$ExpectedDotnetExecutableSha256 = '76E6472063F53379B86FE8370203AB6C46C75D27F405B722845F0E495D8F5FD0'
$ExpectedDotnetExecutableLength = 157480L
$ExpectedDotnetSdkVersion = '8.0.418'
$ExpectedDotnetSdkArtifacts = [ordered]@{
    'dotnet.dll' = '97C49DCFBA2A41CA7D36885FAE38F6AC694FE16FEDC0E8F25E309495D6E69956'
    'MSBuild.dll' = 'FEFD554FE95596FF7DECD4F28404E4A2FB9DE5152E209DF8555FF50FB6C511B1'
    'Roslyn\bincore\csc.dll' = '3029D1C2CE381DB5B222E7CAF12A1B767BC1606E71CAD6A3662F13AB82F35068'
}
$ExpectedDotnetSdkArtifactLengths = [ordered]@{
    'dotnet.dll' = 2550064L
    'MSBuild.dll' = 842000L
    'Roslyn\bincore\csc.dll' = 141576L
}
$DotnetExecutable = $null
$DotnetAuthority = $null
$DataRoot = 'D:\CodexData\CodexGuardian'
$TempRoot = 'D:\CodexTemp\CodexGuardian\package-release'
$DotnetCliHome = Join-Path $DataRoot 'dotnet-home'
$ProtectedR13EvidenceRoot = Join-Path $DataRoot 'r13-cdp-poc'
$GuardianReleaseMutexName = 'Local\CodexGuardian.ReleaseExchange'
$NativeUserPresenceCapabilityProbeMarker = 'NATIVE_USER_PRESENCE_CAPABILITY_PROBE_COMPLETE'
$NativeUserPresenceCapabilityProbeTimeoutSeconds = 60
$NativePeerProbeMarker = 'NATIVE_PEER_PROBE_COMPLETE'
$NativePeerProbeTimeoutSeconds = 120
$ConnectedClientProbeMarker = 'NATIVE_CONNECTED_CLIENT_PROBE_COMPLETE'
$ConnectedClientProbeTimeoutSeconds = 120
$RunId = 'CodexGuardian-release-' + $PID + '-' + [Guid]::NewGuid().ToString('N')
$OutputsRoot = Join-Path $RepositoryRoot 'outputs'
$RuntimeOutput = Join-Path $OutputsRoot 'CodexGuardian-win-x64'
$SourceOutput = Join-Path $OutputsRoot 'CodexGuardian-source'
$ScratchRootWasProvided = ![string]::IsNullOrWhiteSpace($ScratchRoot)
$ScratchRoot = if ($ScratchRootWasProvided) {
    [System.IO.Path]::GetFullPath($ScratchRoot)
}
else {
    Join-Path $DataRoot 'release-package'
}
$ScratchWorkspace = Join-Path $ScratchRoot $RunId
$TempWorkspace = Join-Path $TempRoot $RunId
$NugetPackages = Join-Path $ScratchWorkspace 'nuget-packages'
$NugetHttpCache = Join-Path $ScratchWorkspace 'nuget-http-cache'
$NugetPluginsCache = Join-Path $ScratchWorkspace 'nuget-plugins-cache'
$NugetScratch = Join-Path $TempWorkspace 'nuget-scratch'
$DotnetBundleExtractRoot = Join-Path $TempWorkspace 'bundle-extract'
$ToolEnvironmentRoot = Join-Path $ScratchWorkspace 'tool-environment'
$ToolUserProfile = Join-Path $ToolEnvironmentRoot 'profile'
$ToolAppData = Join-Path $ToolUserProfile 'AppData\Roaming'
$ToolLocalAppData = Join-Path $ToolUserProfile 'AppData\Local'
$MSBuildUserExtensionsPath = Join-Path $TempWorkspace 'msbuild-user-extensions'
$CleanupManifestPath = Join-Path $DataRoot (
    'cleanup-package-release-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $RunId + '.json')
$CleanupPendingManifestPath = $CleanupManifestPath -replace '\.json$', '.pending.json'
$StagingRoot = Join-Path $ScratchWorkspace 'staging'
$ArtifactsRoot = Join-Path $ScratchWorkspace 'artifacts'
$FormalArtifactsRoot = Join-Path $ScratchWorkspace 'formal-artifacts'
$TestDataRoot = Join-Path $ScratchWorkspace 'test-data'
$BrokerConsentLedgerTestData = Join-Path $TempRoot (
    'l-' + $PID + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))
$NativeUserPresenceEvidenceRoot = Join-Path $TestDataRoot 'native-user-presence-evidence'
$RuntimeStage = Join-Path $StagingRoot 'runtime'
$BrokerRuntimeStage = Join-Path $RuntimeStage 'Broker'
$SourceStage = Join-Path $StagingRoot 'source'
$StagedProjectRoot = Join-Path $SourceStage 'CodexGuardian'
$StagedProjectFile = Join-Path $StagedProjectRoot 'CodexGuardian.csproj'
$StagedTestsRoot = Join-Path $SourceStage 'CodexGuardian.Tests'
$StagedTestsProject = Join-Path $StagedTestsRoot 'CodexGuardian.Tests.csproj'
$StagedControlRoot = Join-Path $SourceStage 'CodexGuardian.Control'
$StagedControlProject = Join-Path $StagedControlRoot 'CodexGuardian.Control.csproj'
$StagedControlLockFilePath = Join-Path $StagedControlRoot 'packages.lock.json'
$StagedTrustRoot = Join-Path $SourceStage 'CodexGuardian.Trust'
$StagedTrustProject = Join-Path $StagedTrustRoot 'CodexGuardian.Trust.csproj'
$StagedBrokerRoot = Join-Path $SourceStage 'CodexGuardian.Broker'
$StagedBrokerProject = Join-Path $StagedBrokerRoot 'CodexGuardian.Broker.csproj'
$StagedGlobalJsonPath = Join-Path $SourceStage 'global.json'
$StagedNuGetConfigPath = Join-Path $SourceStage 'NuGet.config'
$StagedProjects = @(
    $StagedProjectFile,
    $StagedTestsProject,
    $StagedControlProject,
    $StagedTrustProject,
    $StagedBrokerProject
)
$SourceBuildResiduePaths = @($SourceProjectRoots | ForEach-Object {
    Join-Path $_ 'bin'
    Join-Path $_ 'obj'
})
$ExpectedProjectVersion = '2.0.0'
$ExpectedFileVersion = [Version]'2.0.0.0'
$ExcludedDirectoryPatterns = @(
    'bin',
    'obj',
    'publish',
    '.vs',
    '.release-staging',
    '.release-scratch',
    'bridge-self-test',
    'test-output',
    'test-data',
    'desktop-ipc-probe',
    'TestResults',
    'temp',
    'tmp',
    'npm-cache',
    'node_modules',
    'work-*'
)
$ForbiddenReleasePathFragments = @(
    'DesktopBridge',
    'install-codex',
    'patch-codex'
)

foreach ($environmentOverride in @(
    'DOTNET_STARTUP_HOOKS',
    'DOTNET_ADDITIONAL_DEPS',
    'DOTNET_SHARED_STORE',
    'DOTNET_ROOT',
    'DOTNET_ROOT_X64',
    'DOTNET_ROOT_X86',
    'DOTNET_ROLL_FORWARD',
    'DOTNET_ROLL_FORWARD_TO_PRERELEASE',
    'DOTNET_BUNDLE_EXTRACT_BASE_DIR',
    'DOTNET_BUNDLE_EXTRACT_TO_TEMP',
    'DOTNET_DiagnosticPorts',
    'DOTNET_EnableDiagnostics',
    'NUGET_PLUGIN_PATHS',
    'NUGET_NETCORE_PLUGIN_PATHS',
    'NUGET_CREDENTIALPROVIDERS_PATH',
    'NUGET_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED',
    'NUGET_HTTP_CACHE_PATH',
    'NUGET_SCRATCH',
    'NUGET_PLUGINS_CACHE_PATH',
    'VSS_NUGET_EXTERNAL_FEED_ENDPOINTS',
    'ARTIFACTS_CREDENTIALPROVIDER_FEED_ENDPOINTS',
    'COREHOST_TRACE',
    'COREHOST_TRACEFILE',
    'DOTNET_HOST_TRACE',
    'DOTNET_HOST_TRACEFILE',
    'CustomBeforeMicrosoftCommonProps',
    'CustomAfterMicrosoftCommonProps',
    'CustomBeforeMicrosoftCommonTargets',
    'CustomAfterMicrosoftCommonTargets',
    'MSBuildSDKsPath',
    'MSBUILD_EXE_PATH',
    'MSBuildExtensionsPath',
    'MSBuildExtensionsPath32',
    'MSBuildExtensionsPath64',
    'CscToolPath',
    'CscToolExe',
    'CompilerToolPath',
    'RoslynTargetsPath',
    'DOTNET_HOST_PATH',
    'MSBuildOverrideTasksPath',
    'MSBuildToolsPath',
    'MSBuildLoadMicrosoftTargetsReadOnly',
    'MSBUILDDEBUGENGINE',
    'MSBUILDDEBUGPATH',
    'MSBUILDDEBUGCOMM'
)) {
    Remove-Item -LiteralPath ('Env:' + $environmentOverride) -ErrorAction SilentlyContinue
}
$env:WINDIR = 'C:\Windows'
$env:SystemRoot = 'C:\Windows'
$env:DOTNET_ROOT = 'C:\Program Files\dotnet'
$env:DOTNET_ROOT_X64 = 'C:\Program Files\dotnet'
$env:DOTNET_HOST_PATH = $ExpectedDotnetExecutablePath
$env:DOTNET_MULTILEVEL_LOOKUP = '0'
$env:DOTNET_CLI_HOME = $DotnetCliHome
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_NOLOGO = '1'
$env:DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER = '1'
$env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = '1'
$env:DOTNET_BUNDLE_EXTRACT_BASE_DIR = $DotnetBundleExtractRoot
$env:NUGET_PACKAGES = $NugetPackages
$env:NUGET_HTTP_CACHE_PATH = $NugetHttpCache
$env:NUGET_SCRATCH = $NugetScratch
$env:NUGET_PLUGINS_CACHE_PATH = $NugetPluginsCache
$env:NUGET_XMLDOC_MODE = 'skip'
$env:MSBUILDDISABLENODEREUSE = '1'
$env:TEMP = $TempWorkspace
$env:TMP = $TempWorkspace
$env:MSBuildUserExtensionsPath = $MSBuildUserExtensionsPath
$env:CODEX_GUARDIAN_TEST_DATA_ROOT = $TestDataRoot

function Assert-OutputPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($OutputsRoot).TrimEnd('\')
    $rootPrefix = $fullRoot + '\'
    if (!$fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the formal outputs tree: $fullPath"
    }

    $null = Assert-NoReparseTraversal $fullPath
    return $fullPath
}

function Assert-DDrivePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if (![string]::Equals($pathRoot, 'D:\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Release build, cache, scratch, and temporary paths must be on D: $fullPath"
    }

    if ([string]::Equals(
            $fullPath.TrimEnd('\'),
            $pathRoot.TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "A release write path cannot be a drive or volume root: $fullPath"
    }

    return $fullPath
}

function Assert-NoReparseReadTraversal {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $existingAncestor = $fullPath
    while (!(Test-Path -LiteralPath $existingAncestor)) {
        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }

    while (Test-Path -LiteralPath $existingAncestor) {
        $item = Get-Item -LiteralPath $existingAncestor -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A pinned read path cannot traverse a reparse point: $existingAncestor"
        }
        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }

    return $fullPath
}

function Get-PinnedDotnetFilePlan {
    $resolved = Assert-NoReparseReadTraversal $ExpectedDotnetExecutablePath
    if (![string]::Equals(
            $resolved,
            $ExpectedDotnetExecutablePath,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        !(Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "The release dotnet host is not the pinned executable: $resolved"
    }

    $sdkRoot = Assert-NoReparseReadTraversal (
        Join-Path (Split-Path $resolved -Parent) ('sdk\' + $ExpectedDotnetSdkVersion))
    if (!(Test-Path -LiteralPath $sdkRoot -PathType Container)) {
        throw "The pinned .NET SDK is unavailable: $sdkRoot"
    }
    $plan = [System.Collections.Generic.List[object]]::new()
    $plan.Add([pscustomobject][ordered]@{
        Path = $resolved
        Sha256 = $ExpectedDotnetExecutableSha256
        Length = [long]$ExpectedDotnetExecutableLength
    })
    foreach ($relativePath in $ExpectedDotnetSdkArtifacts.Keys) {
        $artifactPath = Assert-NoReparseReadTraversal (Join-Path $sdkRoot $relativePath)
        if (!(Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
            throw "A pinned .NET SDK artifact is unavailable: $artifactPath"
        }
        $plan.Add([pscustomobject][ordered]@{
            Path = $artifactPath
            Sha256 = [string]$ExpectedDotnetSdkArtifacts[$relativePath]
            Length = [long]$ExpectedDotnetSdkArtifactLengths[$relativePath]
        })
    }
    return $plan.ToArray()
}

function Get-PinnedLeaseStreamSha256 {
    param([Parameter(Mandatory = $true)][System.IO.FileStream]$Stream)

    $position = $Stream.Position
    try {
        $Stream.Position = 0
        return (Get-FileHash -InputStream $Stream -Algorithm SHA256).Hash
    }
    finally {
        $Stream.Position = $position
    }
}

function Open-PinnedDotnetLeases {
    $leases = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($entry in @(Get-PinnedDotnetFilePlan)) {
            $stream = [System.IO.File]::Open(
                [string]$entry.Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            try {
                $item = Get-Item -LiteralPath $entry.Path -Force
                if ($item.Length -ne [long]$entry.Length -or
                    $stream.Length -ne [long]$entry.Length -or
                    (Get-PinnedLeaseStreamSha256 -Stream $stream) -cne [string]$entry.Sha256) {
                    throw "A pinned .NET artifact changed while opening its read lease: $($entry.Path)"
                }
                $signature = Get-AuthenticodeSignature -LiteralPath $entry.Path
                $subject = if ($null -ne $signature.SignerCertificate) {
                    [string]$signature.SignerCertificate.Subject
                }
                else { '' }
                if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
                    !$subject.Contains('O=Microsoft Corporation') -or
                    !$subject.Contains('CN=.NET')) {
                    throw "A pinned .NET executable artifact has an invalid signer: $($entry.Path) status=$($signature.Status)"
                }
                $leases.Add([pscustomobject][ordered]@{
                    Path = [string]$entry.Path
                    Sha256 = [string]$entry.Sha256
                    Length = [long]$entry.Length
                    LastWriteTimeUtcTicks = $item.LastWriteTimeUtc.Ticks
                    Lease = $stream
                })
                $stream = $null
            }
            finally {
                if ($null -ne $stream) {
                    $stream.Dispose()
                }
            }
        }
        return [pscustomobject][ordered]@{
            ExecutablePath = [string]$leases[0].Path
            Artifacts = $leases.ToArray()
        }
    }
    catch {
        for ($index = $leases.Count - 1; $index -ge 0; $index--) {
            try { $leases[$index].Lease.Dispose() } catch { }
        }
        throw
    }
}

function Assert-PinnedDotnetLeases {
    param([Parameter(Mandatory = $true)][object]$Authority)

    if ($null -eq $Authority -or
        ![string]::Equals(
            [string]$Authority.ExecutablePath,
            $ExpectedDotnetExecutablePath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The pinned .NET authority is unavailable or points at an unexpected executable.'
    }
    $plan = @(Get-PinnedDotnetFilePlan)
    $leases = @($Authority.Artifacts)
    if ($leases.Count -ne $plan.Count) {
        throw 'The pinned .NET authority artifact count changed.'
    }
    for ($index = 0; $index -lt $plan.Count; $index++) {
        $expected = $plan[$index]
        $actual = $leases[$index]
        if (![string]::Equals([string]$actual.Path, [string]$expected.Path, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$actual.Sha256 -cne [string]$expected.Sha256 -or
            [long]$actual.Length -ne [long]$expected.Length -or
            $null -eq $actual.Lease -or
            !$actual.Lease.CanRead) {
            throw "The pinned .NET authority identity changed: $($expected.Path)"
        }
        $item = Get-Item -LiteralPath $actual.Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne [long]$actual.Length -or
            $item.LastWriteTimeUtc.Ticks -ne [long]$actual.LastWriteTimeUtcTicks -or
            (Get-PinnedLeaseStreamSha256 -Stream $actual.Lease) -cne [string]$actual.Sha256) {
            throw "The pinned .NET authority lease no longer matches its captured identity: $($actual.Path)"
        }
    }
}

function Close-PinnedDotnetLeases {
    param([AllowNull()][object]$Authority)

    if ($null -eq $Authority) {
        return
    }
    $failure = $null
    $artifacts = @($Authority.Artifacts)
    for ($index = $artifacts.Count - 1; $index -ge 0; $index--) {
        try {
            $artifacts[$index].Lease.Dispose()
        }
        catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
    if ($null -ne $failure) {
        throw $failure
    }
}

function Resolve-PinnedDotnetExecutable {
    $plan = @(Get-PinnedDotnetFilePlan)
    if ($plan.Count -eq 0 -or
        ![string]::Equals(
            [string]$plan[0].Path,
            $ExpectedDotnetExecutablePath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The pinned .NET executable plan is unavailable.'
    }
    return [string]$plan[0].Path
}

function Get-HermeticDotnetChildEnvironment {
    $root = Split-Path $ExpectedDotnetExecutablePath -Parent
    $environment = [ordered]@{
        WINDIR = 'C:\Windows'
        SystemRoot = 'C:\Windows'
        COMSPEC = 'C:\Windows\System32\cmd.exe'
        PATH = 'C:\Windows\System32;C:\Windows;C:\Program Files\dotnet'
        PATHEXT = '.COM;.EXE;.BAT;.CMD'
        TEMP = $TempWorkspace
        TMP = $TempWorkspace
        CODEX_GUARDIAN_TEST_DATA_ROOT = $TestDataRoot
        USERPROFILE = $ToolUserProfile
        HOMEDRIVE = 'D:'
        HOMEPATH = $ToolUserProfile.Substring(2)
        APPDATA = $ToolAppData
        LOCALAPPDATA = $ToolLocalAppData
        ProgramData = 'C:\ProgramData'
        ProgramFiles = 'C:\Program Files'
        'ProgramFiles(x86)' = 'C:\Program Files (x86)'
        CommonProgramFiles = 'C:\Program Files\Common Files'
        'CommonProgramFiles(x86)' = 'C:\Program Files (x86)\Common Files'
        PROCESSOR_ARCHITECTURE = 'AMD64'
        NUMBER_OF_PROCESSORS = [string][Environment]::ProcessorCount
        OS = 'Windows_NT'
        DOTNET_ROOT = $root
        DOTNET_ROOT_X64 = $root
        DOTNET_HOST_PATH = $ExpectedDotnetExecutablePath
        DOTNET_MULTILEVEL_LOOKUP = '0'
        DOTNET_CLI_HOME = $DotnetCliHome
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        DOTNET_NOLOGO = '1'
        DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER = '1'
        DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = '1'
        DOTNET_BUNDLE_EXTRACT_BASE_DIR = $DotnetBundleExtractRoot
        NUGET_PACKAGES = $NugetPackages
        NUGET_HTTP_CACHE_PATH = $NugetHttpCache
        NUGET_SCRATCH = $NugetScratch
        NUGET_PLUGINS_CACHE_PATH = $NugetPluginsCache
        NUGET_XMLDOC_MODE = 'skip'
        MSBuildUserExtensionsPath = $MSBuildUserExtensionsPath
        MSBUILDDISABLENODEREUSE = '1'
    }
    return [pscustomobject][ordered]@{
        Names = [string[]]$environment.Keys
        Values = [string[]]$environment.Values
    }
}

function Assert-ReleaseDotnetEnvironment {
    $forbidden = @(Get-ChildItem Env: -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(?i:COR_|CORECLR_|COMPlus_|DOTNET_STARTUP_HOOKS$|DOTNET_ADDITIONAL_DEPS$|DOTNET_SHARED_STORE$|DOTNET_DiagnosticPorts$|DOTNET_EnableDiagnostics$|NUGET_PLUGIN_PATHS$|NUGET_NETCORE_PLUGIN_PATHS$|NUGET_CREDENTIALPROVIDERS_PATH$|VSS_NUGET_EXTERNAL_FEED_ENDPOINTS$|ARTIFACTS_CREDENTIALPROVIDER_FEED_ENDPOINTS$)'
    })
    if ($forbidden.Count -gt 0) {
        throw ('The release dotnet environment contains forbidden variables: ' +
            (($forbidden | ForEach-Object { [string]$_.Name }) -join ', '))
    }
    $required = [ordered]@{
        WINDIR = 'C:\Windows'
        SystemRoot = 'C:\Windows'
        DOTNET_ROOT = 'C:\Program Files\dotnet'
        DOTNET_ROOT_X64 = 'C:\Program Files\dotnet'
        DOTNET_HOST_PATH = $ExpectedDotnetExecutablePath
        DOTNET_MULTILEVEL_LOOKUP = '0'
        DOTNET_CLI_HOME = $DotnetCliHome
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        DOTNET_NOLOGO = '1'
        DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER = '1'
        DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = '1'
        DOTNET_BUNDLE_EXTRACT_BASE_DIR = $DotnetBundleExtractRoot
        NUGET_PACKAGES = $NugetPackages
        NUGET_HTTP_CACHE_PATH = $NugetHttpCache
        NUGET_SCRATCH = $NugetScratch
        NUGET_PLUGINS_CACHE_PATH = $NugetPluginsCache
        NUGET_XMLDOC_MODE = 'skip'
        MSBuildUserExtensionsPath = $MSBuildUserExtensionsPath
        MSBUILDDISABLENODEREUSE = '1'
        TEMP = $TempWorkspace
        TMP = $TempWorkspace
        CODEX_GUARDIAN_TEST_DATA_ROOT = $TestDataRoot
    }
    foreach ($name in $required.Keys) {
        $actual = [Environment]::GetEnvironmentVariable([string]$name, 'Process')
        if (![string]::Equals($actual, [string]$required[$name], [System.StringComparison]::Ordinal)) {
            throw "The parent dotnet environment is not pinned: $name"
        }
    }
}

function Invoke-PinnedDotnetCommand {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1800)][int]$TimeoutSeconds,
        [string]$ExpectedSuccessMarker = '',
        [switch]$RequireEmptyStderr
    )

    $result = Invoke-BoundedReleaseProcess `
        -Authority $Authority `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -Label $Label `
        -TimeoutSeconds $TimeoutSeconds `
        -MaximumOutputBytes (8L * 1024 * 1024)
    if (![string]::IsNullOrWhiteSpace([string]$result.Stdout)) {
        Write-Host ([string]$result.Stdout).TrimEnd()
    }
    if (![string]::IsNullOrWhiteSpace([string]$result.Stderr)) {
        Write-Host ([string]$result.Stderr).TrimEnd()
    }
    if ($result.ExitCode -ne 0 -or
        $result.TimedOut -or
        $result.OutputExceeded -or
        $result.DrainIncomplete -or
        $result.InternalFailure -or
        $result.ResidualProcessCount -ne 0) {
        throw "$Label failed: exit=$($result.ExitCode) timeout=$($result.TimedOut) outputExceeded=$($result.OutputExceeded) drainIncomplete=$($result.DrainIncomplete) residual=$($result.ResidualProcessCount)"
    }
    if ($RequireEmptyStderr -and
        ![string]::IsNullOrEmpty([string]$result.Stderr)) {
        throw "$Label emitted unexpected stderr."
    }
    if (![string]::IsNullOrEmpty($ExpectedSuccessMarker)) {
        $markerCount = @(
            [regex]::Split([string]$result.Stdout, '\r?\n') | Where-Object {
                [string]::Equals(
                    [string]$_,
                    $ExpectedSuccessMarker,
                    [System.StringComparison]::Ordinal)
            }
        ).Count
        if ($markerCount -ne 1) {
            throw "$Label emitted $markerCount exact success markers; expected one."
        }
    }
}

function Assert-NoReparseTraversal {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-DDrivePath $Path
    $existingAncestor = $fullPath
    while (!(Test-Path -LiteralPath $existingAncestor)) {
        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }

    while (Test-Path -LiteralPath $existingAncestor) {
        $ancestorItem = Get-Item -LiteralPath $existingAncestor -Force
        if (($ancestorItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A release write path cannot descend through a reparse point: $existingAncestor"
        }

        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }

    return $fullPath
}

function Get-ExactPathEntry {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-DDrivePath $Path
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($volumeRoot) -or
        [string]::Equals(
            $fullPath.TrimEnd('\'),
            $volumeRoot.TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "An exact release path entry cannot be a drive root: $fullPath"
    }

    $relativePath = $fullPath.Substring($volumeRoot.Length)
    $segments = @($relativePath.Split(
        [char[]]@('\', '/'),
        [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($segments.Count -eq 0) {
        throw "An exact release path entry requires at least one path segment: $fullPath"
    }

    $current = [System.IO.DirectoryInfo]::new($volumeRoot)
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        $matches = @($current.EnumerateFileSystemInfos() | Where-Object {
            [string]::Equals(
                $_.Name,
                $segment,
                [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($matches.Count -eq 0) {
            return $null
        }
        if ($matches.Count -ne 1) {
            throw "An exact release path resolved to multiple directory entries: $fullPath"
        }

        $entry = $matches[0]
        if ($index -eq $segments.Count - 1) {
            return $entry
        }

        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "An exact release path cannot traverse a reparse point: $($entry.FullName)"
        }
        if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
            throw "An exact release path ancestor is not a directory: $($entry.FullName)"
        }

        $current = [System.IO.DirectoryInfo]::new($entry.FullName)
    }

    throw "An exact release path traversal ended without a result: $fullPath"
}

function Assert-NoReparsePointsInTree {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Assert-NoReparseTraversal $Path
    if (!(Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "$Label is not an existing directory: $fullPath"
    }

    $pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $pending.Push([System.IO.DirectoryInfo]::new($fullPath))
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse point: $($entry.FullName)"
            }
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push([System.IO.DirectoryInfo]$entry)
            }
        }
    }

    return $fullPath
}

function Initialize-DDriveDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Assert-NoReparseTraversal $Path
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        throw "$Label is a file: $fullPath"
    }
    if (!(Test-Path -LiteralPath $fullPath -PathType Container)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }

    $item = Get-Item -LiteralPath $fullPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label cannot be a reparse point: $fullPath"
    }

    return $fullPath
}

function Assert-NoSourceBuildResidue {
    $residue = @($SourceBuildResiduePaths | Where-Object {
        Test-Path -LiteralPath $_
    })
    if ($residue.Count -gt 0) {
        throw "The authoritative source tree contains generated build residue: $($residue -join ', ')"
    }
}

function Assert-DDriveCapacity {
    $drive = Get-PSDrive -Name D -ErrorAction Stop
    $minimumFreeBytes = 4L * 1024 * 1024 * 1024
    if ($drive.Free -lt $minimumFreeBytes) {
        throw "CodexGuardian release validation requires at least 4 GiB free on D:; available bytes: $($drive.Free)"
    }
}

function Remove-ManagedDirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-OutputPath $Path
    $rootItem = Get-ExactPathEntry $fullPath
    if ($null -eq $rootItem) {
        return
    }

    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to recursively remove a managed reparse point: $fullPath"
    }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        throw "Refusing to recursively remove a managed non-directory: $fullPath"
    }
    $null = Assert-NoReparsePointsInTree -Path $fullPath -Label 'Managed cleanup tree'

    try {
        Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
    }
    catch {
        $extendedPath = if ($fullPath.StartsWith('\\')) {
            '\\?\UNC\' + $fullPath.TrimStart('\')
        }
        else {
            '\\?\' + $fullPath
        }
        [System.IO.Directory]::Delete($extendedPath, $true)
    }

    if ($null -ne (Get-ExactPathEntry $fullPath)) {
        throw "Could not remove managed directory: $fullPath"
    }
}

function Reset-ManagedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-OutputPath $Path
    Remove-ManagedDirectoryTree $fullPath
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
}

function Remove-ManagedFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-OutputPath $Path
    $entry = Get-ExactPathEntry $fullPath
    if ($null -eq $entry) {
        return
    }
    if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or
        ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a managed file path with unexpected authority: $fullPath"
    }

    Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($null -ne (Get-ExactPathEntry $fullPath)) {
        throw "Could not remove managed file: $fullPath"
    }
}

function Assert-ScratchPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullRoot = [System.IO.Path]::GetFullPath($ScratchRoot).TrimEnd('\')
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $fullRoot + '\'
    if (!$fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the release scratch root: $fullPath"
    }

    return $fullPath
}

function Assert-TempPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullRoot = [System.IO.Path]::GetFullPath($TempRoot).TrimEnd('\')
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $fullRoot + '\'
    if (!$fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the release temporary root: $fullPath"
    }

    return $fullPath
}

function Assert-NoPathOverlap {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string[]]$ProtectedRoots,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullCandidate = [System.IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $candidatePrefix = $fullCandidate + '\'
    foreach ($protectedRoot in $ProtectedRoots) {
        $fullProtected = [System.IO.Path]::GetFullPath($protectedRoot).TrimEnd('\')
        $protectedPrefix = $fullProtected + '\'
        if ([string]::Equals(
                $fullCandidate,
                $fullProtected,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            $fullCandidate.StartsWith($protectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            $fullProtected.StartsWith($candidatePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label overlaps a protected tree: $fullCandidate <-> $fullProtected"
        }
    }
}

function Initialize-ScratchWorkspace {
    $fullRoot = (Assert-DDrivePath $ScratchRoot).TrimEnd('\')
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullRoot).TrimEnd('\')
    if ([string]::Equals($fullRoot, $volumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The release scratch root cannot be a drive or volume root: $fullRoot"
    }

    $workspace = Assert-ScratchPath $ScratchWorkspace
    Assert-NoPathOverlap `
        -Candidate $workspace `
        -ProtectedRoots @(
            $RepositoryRoot,
            $OutputsRoot,
            $TempRoot,
            $DotnetCliHome,
            $ProtectedR13EvidenceRoot
        ) `
        -Label 'The release scratch workspace'

    $existingAncestor = $fullRoot
    while (!(Test-Path -LiteralPath $existingAncestor)) {
        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }
    while (Test-Path -LiteralPath $existingAncestor) {
        $ancestorItem = Get-Item -LiteralPath $existingAncestor -Force
        if (($ancestorItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The release scratch path cannot descend through a reparse point: $existingAncestor"
        }

        $parent = Split-Path $existingAncestor -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or
            [string]::Equals($parent, $existingAncestor, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $existingAncestor = $parent
    }

    if (Test-Path -LiteralPath $fullRoot -PathType Leaf) {
        throw "The release scratch root is a file: $fullRoot"
    }

    if (Test-Path -LiteralPath $fullRoot -PathType Container) {
        $rootItem = Get-Item -LiteralPath $fullRoot -Force
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The release scratch root cannot be a reparse point: $fullRoot"
        }
    }
    else {
        New-Item -ItemType Directory -Path $fullRoot -Force | Out-Null
    }

    if (Test-Path -LiteralPath $workspace) {
        throw "The unique release scratch workspace already exists: $workspace"
    }

    New-Item -ItemType Directory -Path $workspace -Force | Out-Null
    $workspaceItem = Get-Item -LiteralPath $workspace -Force
    if (($workspaceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The release scratch workspace cannot be a reparse point: $workspace"
    }
}

function Initialize-TempWorkspace {
    $fullRoot = Initialize-DDriveDirectory -Path $TempRoot -Label 'The release temporary root'
    $workspace = Assert-TempPath $TempWorkspace
    Assert-NoPathOverlap `
        -Candidate $workspace `
        -ProtectedRoots @(
            $RepositoryRoot,
            $OutputsRoot,
            $ScratchRoot,
            $DotnetCliHome,
            $ProtectedR13EvidenceRoot
        ) `
        -Label 'The release temporary workspace'

    if (Test-Path -LiteralPath $workspace) {
        throw "The unique release temporary workspace already exists: $workspace"
    }

    New-Item -ItemType Directory -Path $workspace -Force | Out-Null
    $workspaceItem = Get-Item -LiteralPath $workspace -Force
    if (($workspaceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The release temporary workspace cannot be a reparse point: $workspace"
    }
}

function Remove-ScratchDirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-ScratchPath $Path
    $item = Get-ExactPathEntry $fullPath
    if ($null -eq $item) {
        return
    }

    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to recursively clean a scratch reparse point: $fullPath"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        throw "Refusing to recursively clean a scratch non-directory: $fullPath"
    }
    $null = Assert-NoReparsePointsInTree -Path $fullPath -Label 'Release scratch cleanup tree'

    try {
        Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
    }
    catch {
        $extendedPath = if ($fullPath.StartsWith('\\')) {
            '\\?\UNC\' + $fullPath.TrimStart('\')
        }
        else {
            '\\?\' + $fullPath
        }
        [System.IO.Directory]::Delete($extendedPath, $true)
    }

    if ($null -ne (Get-ExactPathEntry $fullPath)) {
        throw "Could not remove release scratch workspace: $fullPath"
    }
}

function Remove-TempDirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-TempPath $Path
    $item = Get-ExactPathEntry $fullPath
    if ($null -eq $item) {
        return
    }

    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to recursively clean a temporary reparse point: $fullPath"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        throw "Refusing to recursively clean a temporary non-directory: $fullPath"
    }
    $null = Assert-NoReparsePointsInTree -Path $fullPath -Label 'Release temporary cleanup tree'

    try {
        Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
    }
    catch {
        $extendedPath = if ($fullPath.StartsWith('\\')) {
            '\\?\UNC\' + $fullPath.TrimStart('\')
        }
        else {
            '\\?\' + $fullPath
        }
        [System.IO.Directory]::Delete($extendedPath, $true)
    }

    if ($null -ne (Get-ExactPathEntry $fullPath)) {
        throw "Could not remove release temporary workspace: $fullPath"
    }
}

function Get-CleanupTargetSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $entry = Get-ExactPathEntry $fullPath
    if ($null -eq $entry) {
        return [ordered]@{
            path = $fullPath
            existed = $false
            fileCount = 0
            directoryCount = 0
            byteCount = 0
        }
    }

    if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($entry.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        throw "Release cleanup snapshot target has unexpected authority: $fullPath"
    }

    $null = Assert-NoReparsePointsInTree -Path $fullPath -Label 'Release cleanup target'

    $entries = @(Get-ChildItem -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop)
    $files = @($entries | Where-Object { !$_.PSIsContainer })
    $directories = @($entries | Where-Object { $_.PSIsContainer })
    $bytes = ($files | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $bytes) {
        $bytes = 0
    }

    return [ordered]@{
        path = $fullPath
        existed = $true
        fileCount = $files.Count
        directoryCount = $directories.Count
        byteCount = [long]$bytes
    }
}

function Write-CleanupManifest {
    param(
        [Parameter(Mandatory = $true)][object[]]$Targets,
        [Parameter(Mandatory = $true)][bool]$VerifiedAbsentAfterDelete
    )

    $manifest = [ordered]@{
        schemaVersion = 1
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
        reason = 'Clean the unique D-drive scratch and TEMP-owned workspaces for one package-release run.'
        source = $RepositoryRoot
        protectedRoots = @(
            $RepositoryRoot,
            $OutputsRoot,
            (Join-Path $DataRoot 'r13-cdp-poc'),
            $DotnetCliHome,
            $CleanupManifestPath,
            $CleanupPendingManifestPath
        )
        targets = $Targets
        verifiedAbsentAfterDelete = $VerifiedAbsentAfterDelete
    }
    $json = $manifest | ConvertTo-Json -Depth 8
    $manifestTemp = $CleanupManifestPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
    [System.IO.File]::WriteAllText(
        $manifestTemp,
        $json + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false))
    $roundTrip = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestTemp |
        ConvertFrom-Json
    if ($roundTrip.targets.Count -ne $Targets.Count -or
        [bool]$roundTrip.verifiedAbsentAfterDelete -ne $VerifiedAbsentAfterDelete) {
        throw 'The release cleanup manifest failed its UTF-8 round-trip gate.'
    }
    if (Test-Path -LiteralPath $CleanupManifestPath) {
        if (Test-Path -LiteralPath $CleanupPendingManifestPath) {
            throw "The release cleanup pending-manifest path already exists: $CleanupPendingManifestPath"
        }
        [System.IO.File]::Replace(
            $manifestTemp,
            $CleanupManifestPath,
            $CleanupPendingManifestPath)
    }
    else {
        Move-Item -LiteralPath $manifestTemp -Destination $CleanupManifestPath
    }
}

function Invoke-Robocopy {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $fullSource = Assert-NoReparsePointsInTree -Path $Source -Label 'Release source project'
    $fullDestination = [System.IO.Path]::GetFullPath($Destination)
    $sourceStagePrefix = [System.IO.Path]::GetFullPath($SourceStage).TrimEnd('\') + '\'
    if (!$fullDestination.StartsWith($sourceStagePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "A release source copy destination escaped the source stage: $fullDestination"
    }
    $null = Assert-NoReparseTraversal $fullDestination

    $arguments = @(
        $fullSource,
        $fullDestination,
        '/E',
        '/R:2',
        '/W:1',
        '/NFL',
        '/NDL',
        '/NJH',
        '/NJS',
        '/NP',
        '/XJ',
        '/XD'
    ) + $ExcludedDirectoryPatterns + @(
        '/XF',
        '*.user',
        '*.suo'
    )
    & robocopy @arguments
    if ($LASTEXITCODE -ge 8) {
        throw "robocopy failed with exit code $LASTEXITCODE while copying $Source"
    }
}

function Assert-NoExcludedDirectories {
    param([Parameter(Mandatory = $true)][string]$Root)

    $excluded = @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force | Where-Object {
        $name = $_.Name
        @($ExcludedDirectoryPatterns | Where-Object { $name -like $_ }).Count -gt 0
    })
    if ($excluded.Count -gt 0) {
        throw "Package contains excluded directories: $($excluded.FullName -join ', ')"
    }
}

function Test-ForbiddenReleasePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    foreach ($fragment in $ForbiddenReleasePathFragments) {
        if ($Path.IndexOf($fragment, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }

    return $false
}

function Get-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $fullRoot + '\'
    if (!$fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Release entry is outside its expected root: $fullPath"
    }

    return $fullPath.Substring($rootPrefix.Length)
}

function Assert-NoDesktopModificationPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    $forbidden = @(Get-ChildItem -LiteralPath $fullRoot -Recurse -Force | Where-Object {
        $relativePath = Get-ReleaseRelativePath -Root $fullRoot -Path $_.FullName
        Test-ForbiddenReleasePath $relativePath
    })
    if ($forbidden.Count -gt 0) {
        $relativePaths = @($forbidden | ForEach-Object {
            Get-ReleaseRelativePath -Root $fullRoot -Path $_.FullName
        })
        throw "$Label contains forbidden Codex modification payloads: $($relativePaths -join ', ')"
    }
}

function Assert-NoDesktopModificationArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $forbiddenEntries = @($archive.Entries | Where-Object {
            Test-ForbiddenReleasePath $_.FullName
        })
        if ($forbiddenEntries.Count -gt 0) {
            throw "$Label contains forbidden Codex modification payloads: $($forbiddenEntries.FullName -join ', ')"
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-ArchiveEntryCount {
    param([Parameter(Mandatory = $true)][string]$Path)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        return @($archive.Entries | Where-Object {
            !$_.FullName.EndsWith('/', [System.StringComparison]::Ordinal)
        }).Count
    }
    finally {
        $archive.Dispose()
    }
}

function Test-IsRuntimeTestPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    foreach ($component in ($Path -split '[\\/]')) {
        if ($component.StartsWith('CodexGuardian.Tests', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Assert-NoRuntimeTestPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullRoot = Assert-NoReparsePointsInTree -Path $Root -Label $Label
    $forbidden = @(Get-ChildItem -LiteralPath $fullRoot -File -Recurse -Force | Where-Object {
        Test-IsRuntimeTestPayloadPath (Get-ReleaseRelativePath -Root $fullRoot -Path $_.FullName)
    })
    if ($forbidden.Count -gt 0) {
        throw "$Label contains a test-only runtime payload: $($forbidden.FullName -join ', ')"
    }
}

function Assert-NoRuntimeTestArchiveEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $forbidden = @($archive.Entries | Where-Object {
            Test-IsRuntimeTestPayloadPath $_.FullName
        })
        if ($forbidden.Count -gt 0) {
            throw "$Label contains a test-only runtime payload: $($forbidden.FullName -join ', ')"
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-CanonicalContentPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrEmpty($Path) -or
        $Path.StartsWith('/', [System.StringComparison]::Ordinal) -or
        $Path.EndsWith('/', [System.StringComparison]::Ordinal) -or
        $Path.Contains('\') -or
        $Path.Contains(':') -or
        $Path.IndexOf([char]0) -ge 0) {
        throw "$Label contains a non-canonical content path: $Path"
    }

    $components = $Path.Split(
        [char[]]@('/'),
        [System.StringSplitOptions]::None)
    foreach ($component in $components) {
        if ([string]::IsNullOrEmpty($component) -or
            [string]::Equals($component, '.', [System.StringComparison]::Ordinal) -or
            [string]::Equals($component, '..', [System.StringComparison]::Ordinal)) {
            throw "$Label contains a non-canonical content path component: $Path"
        }
    }

    return $Path
}

function Get-FileContentManifestEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    $fullPath = Assert-NoReparseReadTraversal $Path
    if (!(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Label is missing a manifest file: $fullPath"
    }

    $relativePath = (Get-ReleaseRelativePath -Root $fullRoot -Path $fullPath).Replace('\', '/')
    $null = Assert-CanonicalContentPath -Path $relativePath -Label $Label
    $stream = [System.IO.File]::Open(
        $fullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $length = [long]$stream.Length
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream)
        }
        finally {
            $sha256.Dispose()
        }

        if ([long]$stream.Length -ne $length -or [long]$stream.Position -ne $length) {
            throw "$Label changed length while it was being hashed: $fullPath"
        }
        $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    }
    finally {
        $stream.Dispose()
    }

    return [pscustomobject]@{
        Path = $relativePath
        Length = $length
        Sha256 = $hash
    }
}

function Get-OrdinalContentManifest {
    param(
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $entriesByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $caseInsensitivePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Entries) {
        $path = Assert-CanonicalContentPath -Path ([string]$entry.Path) -Label $Label
        if ($entriesByPath.ContainsKey($path)) {
            throw "$Label contains a duplicate ordinal path: $path"
        }
        if (!$caseInsensitivePaths.Add($path)) {
            throw "$Label contains a case-colliding path: $path"
        }

        $hash = ([string]$entry.Sha256).ToUpperInvariant()
        if ($hash -notmatch '^[A-F0-9]{64}$') {
            throw "$Label contains an invalid SHA-256 value: $path"
        }
        $entriesByPath.Add($path, [pscustomobject]@{
            Path = $path
            Length = [long]$entry.Length
            Sha256 = $hash
        })
    }

    $sortedPaths = [string[]]$entriesByPath.Keys
    [System.Array]::Sort($sortedPaths, [System.StringComparer]::Ordinal)
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $sortedPaths) {
        $result.Add($entriesByPath[$path])
    }
    return $result.ToArray()
}

function Get-TreeContentManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullRoot = Assert-NoReparsePointsInTree -Path $Root -Label "$Label tree"
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $fullRoot -File -Recurse -Force) {
        $entries.Add((Get-FileContentManifestEntry `
            -Root $fullRoot `
            -Path $file.FullName `
            -Label $Label))
    }
    return @(Get-OrdinalContentManifest -Entries $entries.ToArray() -Label $Label)
}

function Get-ReleaseSourceContentManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$ProjectRoots,
        [Parameter(Mandatory = $true)][string[]]$StandaloneFiles,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullRoot = Assert-NoReparseReadTraversal $Root
    $files = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($projectRoot in $ProjectRoots) {
        $fullProjectRoot = Assert-NoReparsePointsInTree -Path $projectRoot -Label $Label
        $null = Get-ReleaseRelativePath -Root $fullRoot -Path $fullProjectRoot
        foreach ($file in Get-ChildItem -LiteralPath $fullProjectRoot -Recurse -Force -File) {
            $null = $files.Add($file.FullName)
        }
    }
    foreach ($standaloneFile in $StandaloneFiles) {
        $fullFile = Assert-NoReparseReadTraversal $standaloneFile
        if (!(Test-Path -LiteralPath $fullFile -PathType Leaf)) {
            throw "$Label is missing a standalone source file: $fullFile"
        }
        $null = Get-ReleaseRelativePath -Root $fullRoot -Path $fullFile
        $null = $files.Add($fullFile)
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        $entries.Add((Get-FileContentManifestEntry `
            -Root $fullRoot `
            -Path $file `
            -Label $Label))
    }
    return @(Get-OrdinalContentManifest -Entries $entries.ToArray() -Label $Label)
}

function Assert-ContentManifestsEqual {
    param(
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expectedEntries = @(Get-OrdinalContentManifest `
        -Entries $Expected `
        -Label "$Label expected manifest")
    $actualEntries = @(Get-OrdinalContentManifest `
        -Entries $Actual `
        -Label "$Label actual manifest")
    if ($expectedEntries.Count -ne $actualEntries.Count) {
        throw "$Label manifest count differs: actual=$($actualEntries.Count) expected=$($expectedEntries.Count)"
    }

    for ($index = 0; $index -lt $expectedEntries.Count; $index++) {
        $expectedEntry = $expectedEntries[$index]
        $actualEntry = $actualEntries[$index]
        if (![string]::Equals(
                [string]$actualEntry.Path,
                [string]$expectedEntry.Path,
                [System.StringComparison]::Ordinal) -or
            [long]$actualEntry.Length -ne [long]$expectedEntry.Length -or
            ![string]::Equals(
                [string]$actualEntry.Sha256,
                [string]$expectedEntry.Sha256,
                [System.StringComparison]::Ordinal)) {
            throw (
                "$Label manifest differs at index ${index}: " +
                "actual=$($actualEntry.Path)|$($actualEntry.Length)|$($actualEntry.Sha256) " +
                "expected=$($expectedEntry.Path)|$($expectedEntry.Length)|$($expectedEntry.Sha256)")
        }
    }
}

function Assert-TreeMatchesManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object[]]$ExpectedManifest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = @(Get-TreeContentManifest -Root $Root -Label $Label)
    Assert-ContentManifestsEqual -Expected $ExpectedManifest -Actual $actual -Label $Label
}

function Get-ArchiveContentManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$ExpectedManifest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Assert-NoReparseTraversal $Path
    if (!(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Label archive is unavailable: $fullPath"
    }

    $expectedEntries = @(Get-OrdinalContentManifest `
        -Entries $ExpectedManifest `
        -Label "$Label expected manifest")
    $expectedByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($entry in $expectedEntries) {
        $entryPath = [string]$entry.Path
        $expectedByPath.Add($entryPath, $entry)
        $separator = $entryPath.LastIndexOf('/')
        while ($separator -gt 0) {
            $null = $expectedDirectories.Add($entryPath.Substring(0, $separator))
            $separator = $entryPath.LastIndexOf('/', $separator - 1)
        }
    }
    $seenArchiveNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $seenArchiveNamesIgnoreCase = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $seenEntryPathsIgnoreCase = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $seenFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $actual = [System.Collections.Generic.List[object]]::new()
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($fullPath)
    try {
        foreach ($archiveEntry in $archive.Entries) {
            $rawName = [string]$archiveEntry.FullName
            if ([string]::IsNullOrEmpty($rawName) -or
                $rawName.Contains('\') -or
                $rawName.Contains(':') -or
                $rawName.IndexOf([char]0) -ge 0 -or
                $rawName.StartsWith('/', [System.StringComparison]::Ordinal) -or
                !$seenArchiveNames.Add($rawName) -or
                !$seenArchiveNamesIgnoreCase.Add($rawName)) {
                throw "$Label contains a non-canonical or duplicate ZIP entry: $rawName"
            }

            $isDirectory = $rawName.EndsWith('/', [System.StringComparison]::Ordinal)
            $entryPath = if ($isDirectory) {
                $rawName.Substring(0, $rawName.Length - 1)
            }
            else { $rawName }
            $null = Assert-CanonicalContentPath -Path $entryPath -Label $Label
            if (!$seenEntryPathsIgnoreCase.Add($entryPath)) {
                throw "$Label contains a case-colliding ZIP entry: $rawName"
            }
            if ($isDirectory) {
                if ([long]$archiveEntry.Length -ne 0L -or
                    !$expectedDirectories.Contains($entryPath)) {
                    throw "$Label contains an unexpected directory entry: $rawName"
                }
                continue
            }
            if (!$seenFiles.Add($entryPath) -or !$expectedByPath.ContainsKey($entryPath)) {
                throw "$Label contains an unexpected file entry: $entryPath"
            }

            $expectedEntry = $expectedByPath[$entryPath]
            if ([long]$archiveEntry.Length -ne [long]$expectedEntry.Length) {
                throw "$Label archive entry length differs: $entryPath -> $($archiveEntry.Length)/$($expectedEntry.Length)"
            }

            $stream = $archiveEntry.Open()
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $buffer = New-Object byte[] 65536
                $total = 0L
                while ($true) {
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    if ($read -eq 0) {
                        break
                    }
                    $total += $read
                    if ($total -gt [long]$expectedEntry.Length) {
                        throw "$Label archive entry exceeded its expected length while hashing: $entryPath"
                    }
                    [void]$sha256.TransformBlock($buffer, 0, $read, $buffer, 0)
                }
                [void]$sha256.TransformFinalBlock((New-Object byte[] 0), 0, 0)
                if ($total -ne [long]$expectedEntry.Length) {
                    throw "$Label archive entry ended at an unexpected length: $entryPath -> $total/$($expectedEntry.Length)"
                }
                $hash = [System.BitConverter]::ToString($sha256.Hash).Replace('-', '')
            }
            finally {
                $sha256.Dispose()
                $stream.Dispose()
            }
            $actual.Add([pscustomobject]@{
                Path = $entryPath
                Length = $total
                Sha256 = $hash
            })
        }
    }
    finally {
        $archive.Dispose()
    }

    if ($seenFiles.Count -ne $expectedEntries.Count) {
        throw "$Label archive file count differs: $($seenFiles.Count)/$($expectedEntries.Count)"
    }
    return @(Get-OrdinalContentManifest -Entries $actual.ToArray() -Label $Label)
}

function Assert-ArchiveMatchesManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$ExpectedManifest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = @(Get-ArchiveContentManifest `
        -Path $Path `
        -ExpectedManifest $ExpectedManifest `
        -Label $Label)
    Assert-ContentManifestsEqual -Expected $ExpectedManifest -Actual $actual -Label $Label
}

function Assert-NoImplicitMsBuildInputs {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string[]]$Projects
    )

    $implicitFileNames = @(
        'Directory.Build.props',
        'Directory.Build.targets',
        'Directory.Packages.props',
        'MSBuild.rsp'
    )
    $visitedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($project in $Projects) {
        $current = Split-Path $project -Parent
        while (![string]::IsNullOrWhiteSpace($current)) {
            if ($visitedDirectories.Add($current)) {
                foreach ($fileName in $implicitFileNames) {
                    $candidate = Join-Path $current $fileName
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                        throw "An implicit MSBuild input is forbidden for a reproducible release: $candidate"
                    }
                }
            }

            $trimmedCurrent = $current.TrimEnd('\')
            $trimmedRoot = [System.IO.Path]::GetPathRoot($current).TrimEnd('\')
            if ([string]::Equals(
                    $trimmedCurrent,
                    $trimmedRoot,
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                break
            }
            $parent = Split-Path $current -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or
                [string]::Equals($parent, $current, [System.StringComparison]::OrdinalIgnoreCase)) {
                break
            }
            $current = $parent
        }
    }

    $customBuildFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -Force -File |
        Where-Object { $_.Extension -in @('.props', '.targets') })
    if ($customBuildFiles.Count -gt 0) {
        throw "Custom MSBuild props or targets are forbidden from the release source graph: $($customBuildFiles.FullName -join ', ')"
    }
}

function Assert-PinnedGlobalJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Assert-NoReparseReadTraversal $Path
    if (!(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "The pinned global.json is unavailable: $fullPath"
    }
    $actualHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
    if (![string]::Equals(
            $actualHash,
            $ExpectedGlobalJsonSha256,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The pinned global.json hash is unexpected: $fullPath -> $actualHash"
    }
}

function Assert-PinnedRestoreInputs {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$LockPath
    )

    $fullConfigPath = Assert-NoReparseReadTraversal $ConfigPath
    $fullLockPath = Assert-NoReparseReadTraversal $LockPath
    foreach ($restoreInput in @(
        [pscustomobject]@{
            Path = $fullConfigPath
            ExpectedSha256 = $ExpectedNuGetConfigSha256
            Label = 'NuGet.config'
        },
        [pscustomobject]@{
            Path = $fullLockPath
            ExpectedSha256 = $ExpectedControlLockFileSha256
            Label = 'Control packages.lock.json'
        }
    )) {
        if (!(Test-Path -LiteralPath $restoreInput.Path -PathType Leaf)) {
            throw "The pinned $($restoreInput.Label) is unavailable: $($restoreInput.Path)"
        }
        $actualHash = (Get-FileHash -LiteralPath $restoreInput.Path -Algorithm SHA256).Hash
        if (![string]::Equals(
                $actualHash,
                [string]$restoreInput.ExpectedSha256,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "The pinned $($restoreInput.Label) hash is unexpected: $($restoreInput.Path) -> $actualHash"
        }
    }

    [xml]$nugetConfig = Get-Content -Raw -LiteralPath $fullConfigPath
    $sourceChildren = @($nugetConfig.SelectNodes('/configuration/packageSources/*'))
    $mappingChildren = @($nugetConfig.SelectNodes('/configuration/packageSourceMapping/*'))
    $source = @($nugetConfig.SelectNodes('/configuration/packageSources/add'))
    $mappingSource = @($nugetConfig.SelectNodes('/configuration/packageSourceMapping/packageSource'))
    if ($sourceChildren.Count -ne 2 -or
        @($nugetConfig.SelectNodes('/configuration/packageSources/clear')).Count -ne 1 -or
        $source.Count -ne 1 -or
        ![string]::Equals([string]$source[0].key, 'nuget.org', [System.StringComparison]::Ordinal) -or
        ![string]::Equals(
            [string]$source[0].value,
            'https://api.nuget.org/v3/index.json',
            [System.StringComparison]::Ordinal) -or
        ![string]::Equals([string]$source[0].protocolVersion, '3', [System.StringComparison]::Ordinal) -or
        $mappingChildren.Count -ne 2 -or
        @($nugetConfig.SelectNodes('/configuration/packageSourceMapping/clear')).Count -ne 1 -or
        $mappingSource.Count -ne 1 -or
        ![string]::Equals(
            [string]$mappingSource[0].key,
            'nuget.org',
            [System.StringComparison]::Ordinal)) {
        throw 'The pinned NuGet.config does not contain one cleared official v3 source and mapping.'
    }

    $expectedPatterns = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'System.Security.Cryptography.Pkcs',
            'System.Formats.Asn1',
            'System.Buffers',
            'System.Memory',
            'System.Security.Cryptography.Cng',
            'System.Runtime.CompilerServices.Unsafe',
            'Microsoft.NETCore.App.Runtime.win-x64',
            'Microsoft.WindowsDesktop.App.Runtime.win-x64',
            'Microsoft.AspNetCore.App.Runtime.win-x64'
        ),
        [System.StringComparer]::Ordinal)
    $actualPatterns = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($mappingSource[0].SelectNodes('./package') | ForEach-Object {
            [string]$_.pattern
        }),
        [System.StringComparer]::Ordinal)
    if (!$expectedPatterns.SetEquals($actualPatterns)) {
        throw 'The pinned NuGet package-source mapping is not the exact release dependency allowlist.'
    }

    $lock = Get-Content -Raw -LiteralPath $fullLockPath | ConvertFrom-Json
    if ($null -eq $lock -or [int]$lock.version -ne 1 -or $null -eq $lock.dependencies) {
        throw 'The Control packages.lock.json has an invalid root contract.'
    }
    $frameworks = @($lock.dependencies.PSObject.Properties)
    $expectedFrameworks = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'net8.0-windows7.0',
            'net8.0-windows7.0/win-x64'
        ),
        [System.StringComparer]::Ordinal)
    $actualFrameworks = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($frameworks | ForEach-Object { [string]$_.Name }),
        [System.StringComparer]::Ordinal)
    if ($frameworks.Count -ne 2 -or !$expectedFrameworks.SetEquals($actualFrameworks)) {
        throw 'The Control packages.lock.json target framework closure is unexpected.'
    }
    foreach ($framework in $frameworks) {
        $packages = @($framework.Value.PSObject.Properties)
        if ($packages.Count -ne 1 -or
            ![string]::Equals(
                [string]$packages[0].Name,
                'System.Security.Cryptography.Pkcs',
                [System.StringComparison]::Ordinal)) {
            throw 'The Control packages.lock.json dependency closure is unexpected.'
        }
        $pkcs = $packages[0].Value
        if (@($pkcs.PSObject.Properties).Count -ne 4 -or
            ![string]::Equals([string]$pkcs.type, 'Direct', [System.StringComparison]::Ordinal) -or
            ![string]::Equals([string]$pkcs.requested, '[8.0.1, )', [System.StringComparison]::Ordinal) -or
            ![string]::Equals([string]$pkcs.resolved, '8.0.1', [System.StringComparison]::Ordinal) -or
            ![string]::Equals(
                [string]$pkcs.contentHash,
                'CoCRHFym33aUSf/NtWSVSZa99dkd0Hm7OCZUxORBjRB16LNhIEOf8THPqzIYlvKM0nNDAPTRBa1FxEECrgaxxA==',
                [System.StringComparison]::Ordinal)) {
            throw 'The Control packages.lock.json package identity is unexpected.'
        }
    }
}

function Assert-StagedProjectConditionShape {
    param(
        [Parameter(Mandatory = $true)][xml]$ProjectXml,
        [Parameter(Mandatory = $true)][string]$ProjectRelative
    )

    $productionProjects = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'CodexGuardian\CodexGuardian.csproj',
            'CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian.Trust\CodexGuardian.Trust.csproj',
            'CodexGuardian.Broker\CodexGuardian.Broker.csproj'
        ),
        [System.StringComparer]::OrdinalIgnoreCase)
    $defineConstantProjects = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian.Trust\CodexGuardian.Trust.csproj',
            'CodexGuardian.Broker\CodexGuardian.Broker.csproj'
        ),
        [System.StringComparer]::OrdinalIgnoreCase)
    $conditionAttributes = [System.Collections.Generic.List[object]]::new()
    foreach ($element in @($ProjectXml.SelectNodes('//*'))) {
        foreach ($attribute in @($element.Attributes)) {
            if ([string]::Equals(
                    [string]$attribute.LocalName,
                    'Condition',
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                if (![string]::Equals(
                        [string]$attribute.Name,
                        'Condition',
                        [System.StringComparison]::Ordinal)) {
                    throw "A release project contains a noncanonical Condition attribute: $ProjectRelative"
                }
                $conditionAttributes.Add($attribute)
            }
        }
    }

    if (!$productionProjects.Contains($ProjectRelative)) {
        if ($conditionAttributes.Count -ne 0) {
            throw "A non-production release project contains a conditional MSBuild node: $ProjectRelative"
        }
        return
    }

    $defaultCondition = "'`$(CodexGuardianTestFriend)' == ''"
    $enabledCondition = "'`$(CodexGuardianTestFriend)' == 'true'"
    $testFriendProperties = @($ProjectXml.SelectNodes('/Project/PropertyGroup/CodexGuardianTestFriend'))
    if ($testFriendProperties.Count -ne 1 -or
        $testFriendProperties[0].Attributes.Count -ne 1 -or
        ![string]::Equals(
            [string]$testFriendProperties[0].Condition,
            $defaultCondition,
            [System.StringComparison]::Ordinal) -or
        ![string]::Equals(
            [string]$testFriendProperties[0].InnerText,
            'false',
            [System.StringComparison]::Ordinal)) {
        throw "A production release project has a noncanonical TestFriend default: $ProjectRelative"
    }

    $friendGroups = @($ProjectXml.SelectNodes('/Project/ItemGroup') | Where-Object {
        [string]::Equals(
            [string]$_.Condition,
            $enabledCondition,
            [System.StringComparison]::Ordinal)
    })
    if ($friendGroups.Count -ne 1 -or $friendGroups[0].Attributes.Count -ne 1) {
        throw "A production release project has a noncanonical TestFriend item group: $ProjectRelative"
    }
    $friendElements = @($friendGroups[0].ChildNodes | Where-Object {
        $_.NodeType -eq [System.Xml.XmlNodeType]::Element
    })
    if ($friendElements.Count -ne 1 -or
        ![string]::Equals(
            [string]$friendElements[0].Name,
            'InternalsVisibleTo',
            [System.StringComparison]::Ordinal) -or
        $friendElements[0].Attributes.Count -ne 1 -or
        ![string]::Equals(
            [string]$friendElements[0].Include,
            'CodexGuardian.Tests',
            [System.StringComparison]::Ordinal)) {
        throw "A production release project has a noncanonical Tests friend declaration: $ProjectRelative"
    }

    $defineGroups = @($ProjectXml.SelectNodes('/Project/PropertyGroup') | Where-Object {
        [string]::Equals(
            [string]$_.Condition,
            $enabledCondition,
            [System.StringComparison]::Ordinal)
    })
    if ($defineConstantProjects.Contains($ProjectRelative)) {
        if ($defineGroups.Count -ne 1 -or $defineGroups[0].Attributes.Count -ne 1) {
            throw "A test-symbol release project has a noncanonical conditional property group: $ProjectRelative"
        }
        $defineElements = @($defineGroups[0].ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element
        })
        if ($defineElements.Count -ne 1 -or
            ![string]::Equals(
                [string]$defineElements[0].Name,
                'DefineConstants',
                [System.StringComparison]::Ordinal) -or
            $defineElements[0].Attributes.Count -ne 0 -or
            ![string]::Equals(
                [string]$defineElements[0].InnerText,
                '$(DefineConstants);CODEXGUARDIAN_TEST_FRIEND',
                [System.StringComparison]::Ordinal)) {
            throw "A test-symbol release project has a noncanonical DefineConstants value: $ProjectRelative"
        }
    }
    elseif ($defineGroups.Count -ne 0) {
        throw "A production release project unexpectedly defines a test compilation symbol: $ProjectRelative"
    }

    $expectedConditionCount = if ($defineConstantProjects.Contains($ProjectRelative)) { 3 } else { 2 }
    if ($conditionAttributes.Count -ne $expectedConditionCount) {
        throw "A production release project contains an unexpected conditional node: $ProjectRelative"
    }
}

function Assert-StagedProjectReferenceClosure {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$EntryProjects,
        [Parameter(Mandatory = $true)][string[]]$ExpectedProjects,
        [Parameter(Mandatory = $true)][string[]]$ExpectedEdges
    )

    $fullRoot = Assert-NoReparsePointsInTree -Path $Root -Label 'Project source tree'
    $rootPrefix = $fullRoot.TrimEnd('\') + '\'
    $expected = [System.Collections.Generic.HashSet[string]]::new(
        $ExpectedProjects,
        [System.StringComparer]::OrdinalIgnoreCase)
    $stagedProjects = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($stagedProject in Get-ChildItem -LiteralPath $fullRoot -Recurse -Force -Filter '*.csproj' -File) {
        $null = $stagedProjects.Add(
            (Get-ReleaseRelativePath -Root $fullRoot -Path $stagedProject.FullName))
    }
    if (!$expected.SetEquals($stagedProjects)) {
        throw "The source tree does not contain exactly the expected projects: $($stagedProjects -join ', ')"
    }
    $expectedPinnedProjects = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$ExpectedProjectFileHashes.Keys,
        [System.StringComparer]::OrdinalIgnoreCase)
    if (!$expected.SetEquals($expectedPinnedProjects)) {
        throw 'The expected project graph and pinned project hashes do not describe the same project set.'
    }
    foreach ($relativeProjectPath in $ExpectedProjectFileHashes.Keys) {
        $projectPath = Join-Path $fullRoot $relativeProjectPath
        $actualHash = (Get-FileHash -LiteralPath $projectPath -Algorithm SHA256).Hash
        $expectedHash = $ExpectedProjectFileHashes[$relativeProjectPath]
        if (![string]::Equals($actualHash, $expectedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "A pinned release project hash is unexpected: $relativeProjectPath -> $actualHash"
        }
    }

    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($entryProject in $EntryProjects) {
        $pending.Enqueue([System.IO.Path]::GetFullPath($entryProject))
    }
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $visitedRelative = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $visitedEdges = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    while ($pending.Count -gt 0) {
        $project = $pending.Dequeue()
        if (!$visited.Add($project)) {
            continue
        }
        if (!$project.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            !(Test-Path -LiteralPath $project -PathType Leaf)) {
            throw "A staged ProjectReference escaped or is missing from the source stage: $project"
        }
        $projectRelative = Get-ReleaseRelativePath -Root $fullRoot -Path $project
        $null = $visitedRelative.Add($projectRelative)

        [xml]$projectXml = Get-Content -Raw -LiteralPath $project
        if (![string]::Equals(
                [string]$projectXml.Project.Sdk,
                'Microsoft.NET.Sdk',
                [System.StringComparison]::Ordinal)) {
            throw "A release project uses an unexpected SDK declaration: $project"
        }
        $forbiddenNodes = @($projectXml.SelectNodes(
            "//*[local-name()='Import' or local-name()='UsingTask' or local-name()='Target' or local-name()='Choose']"))
        if ($forbiddenNodes.Count -gt 0) {
            throw "A release project contains a forbidden dynamic MSBuild node: $project -> $($forbiddenNodes[0].Name)"
        }
        Assert-StagedProjectConditionShape `
            -ProjectXml $projectXml `
            -ProjectRelative $projectRelative

        $allReferenceNodes = @($projectXml.SelectNodes('//*') | Where-Object {
            [string]::Equals(
                [string]$_.LocalName,
                'ProjectReference',
                [System.StringComparison]::OrdinalIgnoreCase)
        })
        $references = @($projectXml.SelectNodes('/Project/ItemGroup/ProjectReference'))
        if ($allReferenceNodes.Count -ne $references.Count) {
            throw "A staged ProjectReference has unexpected casing namespace or parent: $project"
        }
        foreach ($reference in $references) {
            $include = [string]$reference.Include
            if ([string]::IsNullOrWhiteSpace($include)) {
                throw "A staged ProjectReference has no Include value: $project"
            }
            $referenceCondition = [string]$reference.Condition
            $itemGroupCondition = [string]$reference.ParentNode.Condition
            if (![string]::IsNullOrWhiteSpace($referenceCondition) -or
                ![string]::IsNullOrWhiteSpace($itemGroupCondition) -or
                $include.Contains('$(') -or
                $include.Contains('@(') -or
                $include.Contains('%(') -or
                $include.IndexOfAny([char[]]@('*', '?')) -ge 0 -or
                $include.Contains(';') -or
                $include.Contains('"') -or
                $include.IndexOf([char]39) -ge 0 -or
                $include.Contains("`r") -or
                $include.Contains("`n") -or
                [System.IO.Path]::IsPathRooted($include) -or
                $include.Contains(':') -or
                ![string]::Equals(
                    [System.IO.Path]::GetExtension($include),
                    '.csproj',
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "A staged ProjectReference is not statically resolvable: $project -> $include"
            }

            $childElements = @($reference.ChildNodes | Where-Object {
                $_.NodeType -eq [System.Xml.XmlNodeType]::Element
            })
            if ($childElements.Count -ne 0) {
                throw "A staged ProjectReference contains child metadata: $project -> $include"
            }

            $resolved = [System.IO.Path]::GetFullPath(
                (Join-Path (Split-Path $project -Parent) $include))
            if (!$resolved.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "A staged ProjectReference escaped the source stage: $project -> $resolved"
            }
            $resolvedRelative = Get-ReleaseRelativePath -Root $fullRoot -Path $resolved
            if ([string]::Equals(
                    $projectRelative,
                    'CodexGuardian.Tests\CodexGuardian.Tests.csproj',
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                $expectedAttributeCount = if ([string]::Equals(
                        $resolvedRelative,
                        'CodexGuardian.Broker\CodexGuardian.Broker.csproj',
                        [System.StringComparison]::OrdinalIgnoreCase)) { 3 } else { 2 }
                if ($reference.Attributes.Count -ne $expectedAttributeCount -or
                    ![string]::Equals(
                        [string]$reference.AdditionalProperties,
                        'CodexGuardianTestFriend=true',
                        [System.StringComparison]::Ordinal) -or
                    ($expectedAttributeCount -eq 3 -and ![string]::Equals(
                        [string]$reference.ReferenceOutputAssembly,
                        'true',
                        [System.StringComparison]::Ordinal))) {
                    throw "A Tests ProjectReference has noncanonical friend metadata: $project -> $include"
                }
            }
            elseif ($reference.Attributes.Count -ne 1) {
                throw "A production ProjectReference contains unexpected metadata: $project -> $include"
            }
            if (!$visitedEdges.Add($projectRelative + '->' + $resolvedRelative)) {
                throw "The staged project graph contains a duplicate ProjectReference edge: $projectRelative -> $resolvedRelative"
            }
            $pending.Enqueue($resolved)
        }
    }

    if (!$expected.SetEquals($visitedRelative)) {
        throw "The staged ProjectReference closure is not the exact expected project graph: $($visitedRelative -join ', ')"
    }
    $expectedEdgeSet = [System.Collections.Generic.HashSet[string]]::new(
        $ExpectedEdges,
        [System.StringComparer]::OrdinalIgnoreCase)
    if (!$expectedEdgeSet.SetEquals($visitedEdges)) {
        throw "The staged ProjectReference edges are not exact: $($visitedEdges -join ', ')"
    }
}


function New-MonotonicDeadline {
    param([Parameter(Mandatory = $true)][int]$TimeoutMilliseconds)

    if ($TimeoutMilliseconds -lt 1) {
        throw "A bounded deadline must be positive: $TimeoutMilliseconds"
    }
    $delta = [long][Math]::Ceiling(
        $TimeoutMilliseconds *
        ([double][System.Diagnostics.Stopwatch]::Frequency / 1000.0))
    return [System.Diagnostics.Stopwatch]::GetTimestamp() + $delta
}

function Get-RemainingDeadlineMilliseconds {
    param([Parameter(Mandatory = $true)][long]$Deadline)

    $remainingTicks = $Deadline - [System.Diagnostics.Stopwatch]::GetTimestamp()
    if ($remainingTicks -le 0) {
        return 0
    }
    $remainingMilliseconds = [long][Math]::Ceiling(
        $remainingTicks * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency)
    return [int][Math]::Min(
        [int]::MaxValue,
        [Math]::Max(1L, $remainingMilliseconds))
}

function Invoke-BoundedGateCimQuery {
    param(
        [Parameter(Mandatory = $true)][string]$Filter,
        [Parameter(Mandatory = $true)][long]$Deadline,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $remaining = Get-RemainingDeadlineMilliseconds $Deadline
    if ($remaining -le 0) {
        throw "$Label CIM deadline expired before query."
    }
    $operationTimeoutSeconds = [uint32][Math]::Max(
        1,
        [Math]::Min(5, [Math]::Ceiling($remaining / 1000.0)))
    $result = @(Get-CimInstance `
        -ClassName Win32_Process `
        -Filter $Filter `
        -Property ProcessId,ExecutablePath,CreationDate `
        -OperationTimeoutSec $operationTimeoutSeconds `
        -ErrorAction Stop)
    if ((Get-RemainingDeadlineMilliseconds $Deadline) -le 0) {
        throw "$Label CIM query exceeded the shared cleanup deadline."
    }
    return $result
}

function Convert-CimProcessCreationTimeUtc {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime()
    }
    return [System.Management.ManagementDateTimeConverter]::ToDateTime(
        [string]$Value).ToUniversalTime()
}

function Get-ExactMarkerCount {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    $count = 0
    $reader = [System.IO.StringReader]::new($Text)
    try {
        while (($line = $reader.ReadLine()) -ne $null) {
            if ([string]::Equals($line, $Marker, [System.StringComparison]::Ordinal)) {
                $count++
                if ($count -gt 1) {
                    return 2
                }
            }
        }
    }
    finally {
        $reader.Dispose()
    }
    return $count
}

function Stop-BoundedExactArtifactProcess {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExactPid,
        [Parameter(Mandatory = $true)][long]$ExpectedStartTimeUtcTicks,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][long]$Deadline
    )

    if ($Process.Id -ne $ExactPid) {
        throw "$Label process identity changed before cleanup: expected=$ExactPid actual=$($Process.Id)"
    }
    $actualStartTimeUtcTicks = $Process.StartTime.ToUniversalTime().Ticks
    if ($actualStartTimeUtcTicks -ne $ExpectedStartTimeUtcTicks) {
        throw "$Label process start identity changed before cleanup: pid=$ExactPid"
    }

    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    $rootExited = $false
    try {
        $rootExited = $Process.HasExited
    }
    catch {
        $cleanupFailures.Add("root-state=$($_.Exception.Message)")
    }

    if (!$rootExited) {
        if ((Get-RemainingDeadlineMilliseconds $Deadline) -le 0) {
            $cleanupFailures.Add('root-kill=shared-deadline-exceeded')
        }
        else {
            try {
                $Process.Kill()
            }
            catch {
                try {
                    if (!$Process.HasExited) {
                        $cleanupFailures.Add("root-kill=$($_.Exception.Message)")
                    }
                }
                catch {
                    $cleanupFailures.Add("root-kill-state=$($_.Exception.Message)")
                }
            }
        }
    }

    try {
        $remaining = Get-RemainingDeadlineMilliseconds $Deadline
        if ($remaining -le 0 -or !$Process.WaitForExit($remaining)) {
            $cleanupFailures.Add("root-exit=deadline-exceeded pid=$ExactPid")
        }
        else {
            $Process.Refresh()
            if (!$Process.HasExited) {
                $cleanupFailures.Add("root-terminal-state-not-stable pid=$ExactPid")
            }
        }
    }
    catch {
        $cleanupFailures.Add("root-exit=$($_.Exception.Message)")
    }

    if ($cleanupFailures.Count -gt 0) {
        throw "$Label exact-handle cleanup failed after $Reason for pid=$($ExactPid): $($cleanupFailures -join '; ')"
    }
}

function Get-BoundedGateArtifactProcesses {
    param(
        [Parameter(Mandatory = $true)][long]$Deadline,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expectedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @(
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Tests\release\CodexGuardian.Tests.exe'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Tests\release\CodexGuardian.Broker.exe'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Broker.exe')
    )) {
        $null = $expectedPaths.Add([System.IO.Path]::GetFullPath($path))
    }

    $candidates = @(Invoke-BoundedGateCimQuery `
        -Filter "Name='CodexGuardian.Tests.exe' OR Name='CodexGuardian.Broker.exe'" `
        -Deadline $Deadline `
        -Label $Label)
    return @($candidates | Where-Object {
        ![string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        $expectedPaths.Contains([System.IO.Path]::GetFullPath($_.ExecutablePath))
    })
}

function Stop-BoundedGateArtifactProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][long]$Deadline
    )

    $residual = @(Get-BoundedGateArtifactProcesses -Deadline $Deadline -Label $Label)
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in $residual) {
        if ((Get-RemainingDeadlineMilliseconds $Deadline) -le 0) {
            $cleanupFailures.Add('artifact-cleanup=shared-deadline-exceeded')
            break
        }
        $exactProcess = $null
        try {
            $exactProcess = [System.Diagnostics.Process]::GetProcessById([int]$candidate.ProcessId)
            $actualPath = [System.IO.Path]::GetFullPath($exactProcess.MainModule.FileName)
            $actualStartTimeUtc = $exactProcess.StartTime.ToUniversalTime()
            $candidateStartTimeUtc = Convert-CimProcessCreationTimeUtc $candidate.CreationDate
            if (![string]::Equals(
                    $actualPath,
                    [System.IO.Path]::GetFullPath($candidate.ExecutablePath),
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                [Math]::Abs(($actualStartTimeUtc - $candidateStartTimeUtc).TotalSeconds) -gt 1) {
                $cleanupFailures.Add("artifact-identity-changed=$($candidate.ProcessId)")
                continue
            }
            Stop-BoundedExactArtifactProcess `
                -Process $exactProcess `
                -ExactPid ([int]$candidate.ProcessId) `
                -ExpectedStartTimeUtcTicks $actualStartTimeUtc.Ticks `
                -Label $Label `
                -Reason 'probe-artifact-residual' `
                -Deadline $Deadline
        }
        catch {
            $candidateFailure = $_
            try {
                $stillPresent = @(Invoke-BoundedGateCimQuery `
                    -Filter "ProcessId=$($candidate.ProcessId)" `
                    -Deadline $Deadline `
                    -Label $Label)
                if ($stillPresent.Count -gt 0) {
                    $cleanupFailures.Add(
                        "artifact=$($candidate.ProcessId):$($candidateFailure.Exception.Message)")
                }
            }
            catch {
                $cleanupFailures.Add(
                    "artifact-query=$($candidate.ProcessId):$($_.Exception.Message)")
            }
        }
        finally {
            if ($null -ne $exactProcess) {
                $exactProcess.Dispose()
            }
        }
    }

    $remaining = @(Get-BoundedGateArtifactProcesses -Deadline $Deadline -Label $Label)
    if ($remaining.Count -gt 0) {
        $cleanupFailures.Add("artifact-processes-remain=$($remaining.ProcessId -join ',')")
    }
    if ($cleanupFailures.Count -gt 0) {
        throw "$Label could not clean exact probe artifact processes: $($cleanupFailures -join '; ')"
    }
    return $residual.Count
}

function Assert-ReleaseProcessMethodsShape {
    $methodsType = 'CodexGuardian.ReleaseProcessMethodsV2' -as [type]
    $resultType = 'CodexGuardian.ReleaseBoundedProcessResultV2' -as [type]
    if ($null -eq $methodsType -or $null -eq $resultType) {
        throw 'The bounded release process helper types are unavailable.'
    }

    $runMethods = @($methodsType.GetMethods(
        [System.Reflection.BindingFlags]::Public -bor
        [System.Reflection.BindingFlags]::Static) | Where-Object {
            $_.Name -ceq 'Run'
        })
    if ($runMethods.Count -ne 1 -or
        $runMethods[0].ReturnType.FullName -cne $resultType.FullName) {
        throw 'The bounded release process helper Run method shape changed.'
    }
    $actualParameters = @($runMethods[0].GetParameters() | ForEach-Object {
        $_.ParameterType.FullName
    })
    $expectedParameters = @(
        'System.String',
        'System.String[]',
        'System.String',
        'System.String[]',
        'System.String[]',
        'System.Int32',
        'System.Int32'
    )
    if (($actualParameters -join '|') -cne ($expectedParameters -join '|')) {
        throw 'The bounded release process helper Run parameters changed.'
    }

    $actualFields = @($resultType.GetFields(
        [System.Reflection.BindingFlags]::Public -bor
        [System.Reflection.BindingFlags]::Instance) | ForEach-Object {
            $_.Name
        } | Sort-Object)
    $expectedFields = @(
        'CleanupIncomplete',
        'DrainIncomplete',
        'ExitCode',
        'FailureMessage',
        'InternalFailure',
        'OutputExceeded',
        'ProcessId',
        'ResidualBeforeCleanup',
        'ResidualProcessCount',
        'StartTimeUtcTicks',
        'Stderr',
        'Stdout',
        'TimedOut'
    ) | Sort-Object
    if (($actualFields -join '|') -cne ($expectedFields -join '|')) {
        throw 'The bounded release process result fields changed.'
    }
}

function Initialize-ReleaseProcessMethods {
    if ($script:ReleaseProcessMethodsInitialized -eq $true) {
        Assert-ReleaseProcessMethodsShape
        return
    }
    if ($null -ne ('CodexGuardian.ReleaseProcessMethodsV2' -as [type]) -or
        $null -ne ('CodexGuardian.ReleaseBoundedProcessResultV2' -as [type])) {
        throw 'A bounded release process helper type existed before this script initialized it.'
    }

    Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CodexGuardian
{
    public sealed class ReleaseBoundedProcessResultV2
    {
        public int ProcessId;
        public long StartTimeUtcTicks;
        public int ExitCode;
        public string Stdout;
        public string Stderr;
        public bool TimedOut;
        public bool OutputExceeded;
        public bool DrainIncomplete;
        public bool CleanupIncomplete;
        public bool InternalFailure;
        public int ResidualBeforeCleanup;
        public int ResidualProcessCount;
        public string FailureMessage;
    }

    public static class ReleaseProcessMethodsV2
    {
        private const uint CreateSuspended = 0x00000004;
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint ExtendedStartupInfoPresent = 0x00080000;
        private const uint CreateNoWindow = 0x08000000;
        private const uint StartfUseStdHandles = 0x00000100;
        private const uint ProcThreadAttributeHandleList = 0x00020002;
        private const uint HandleFlagInherit = 0x00000001;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const int JobObjectBasicAccountingInformationClass = 1;
        private const int JobObjectExtendedLimitInformationClass = 9;
        private const uint WaitObject0 = 0x00000000;
        private const uint WaitTimeout = 0x00000102;
        private const uint WaitFailed = 0xFFFFFFFF;
        private const uint CleanupExitCode = 0xE0434F4D;
        private const uint GenericRead = 0x80000000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x00000080;
        private const int MaximumCommandLineCharacters = 32767;
        private const int CleanupTimeoutMilliseconds = 10000;
        private const int NaturalExitAccountingGraceMilliseconds = 1000;

        private sealed class ReleaseSafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public ReleaseSafeJobHandle()
                : base(true)
            {
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        private sealed class ReleaseSafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public ReleaseSafeKernelHandle()
                : base(true)
            {
            }

            public ReleaseSafeKernelHandle(IntPtr value)
                : base(true)
            {
                SetHandle(value);
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        private sealed class CaptureState
        {
            private readonly object failureLock = new object();
            private string drainFailure;

            public int TotalBytes;
            public int OutputExceeded;
            public int ForcedDrain;

            public void RecordDrainFailure(Exception exception)
            {
                lock (failureLock)
                {
                    if (drainFailure == null)
                    {
                        drainFailure = exception.GetType().FullName;
                    }
                }
            }

            public string ReadDrainFailure()
            {
                lock (failureLock)
                {
                    return drainFailure;
                }
            }
        }

        private sealed class EnvironmentEntry
        {
            public string Name;
            public string Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public uint Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public uint Size;
            public IntPtr Reserved;
            public IntPtr Desktop;
            public IntPtr Title;
            public uint X;
            public uint Y;
            public uint XSize;
            public uint YSize;
            public uint XCountChars;
            public uint YCountChars;
            public uint FillAttribute;
            public uint Flags;
            public ushort ShowWindow;
            public ushort Reserved2Length;
            public IntPtr Reserved2;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process;
            public IntPtr Thread;
            public uint ProcessId;
            public uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern ReleaseSafeJobHandle CreateJobObject(
            IntPtr securityAttributes,
            string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            ReleaseSafeJobHandle job,
            int informationClass,
            IntPtr information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            ReleaseSafeJobHandle job,
            int informationClass,
            IntPtr information,
            uint informationLength,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(
            ReleaseSafeJobHandle job,
            SafeProcessHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(
            ReleaseSafeJobHandle job,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            IntPtr size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(ReleaseSafeKernelHandle thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            SafeProcessHandle handle,
            uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(
            SafeProcessHandle process,
            out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(
            SafeProcessHandle process,
            uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            SafeHandle handle,
            uint mask,
            uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            ref SecurityAttributes securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private static ReleaseSafeJobHandle CreateKillOnCloseJob()
        {
            ReleaseSafeJobHandle job = CreateJobObject(IntPtr.Zero, null);
            if (job == null || job.IsInvalid)
            {
                if (job != null)
                {
                    job.Dispose();
                }
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateJobObject failed.");
            }

            IntPtr buffer = IntPtr.Zero;
            try
            {
                JobObjectExtendedLimitInformation information =
                    new JobObjectExtendedLimitInformation();
                information.BasicLimitInformation.LimitFlags =
                    JobObjectLimitKillOnJobClose;
                int size = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
                buffer = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(information, buffer, false);
                if (!SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformationClass,
                        buffer,
                        (uint)size))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "SetInformationJobObject failed.");
                }
                return job;
            }
            catch
            {
                job.Dispose();
                throw;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static uint ReadActiveProcessCount(ReleaseSafeJobHandle job)
        {
            int size = Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!QueryInformationJobObject(
                        job,
                        JobObjectBasicAccountingInformationClass,
                        buffer,
                        (uint)size,
                        IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "QueryInformationJobObject failed.");
                }
                JobObjectBasicAccountingInformation information =
                    (JobObjectBasicAccountingInformation)Marshal.PtrToStructure(
                        buffer,
                        typeof(JobObjectBasicAccountingInformation));
                return information.ActiveProcesses;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static uint WaitForJobToEmpty(
            ReleaseSafeJobHandle job,
            int timeoutMilliseconds)
        {
            Stopwatch timer = Stopwatch.StartNew();
            while (true)
            {
                uint active = ReadActiveProcessCount(job);
                if (active == 0)
                {
                    return 0;
                }
                int remaining = timeoutMilliseconds - checked((int)Math.Min(
                    timeoutMilliseconds,
                    timer.ElapsedMilliseconds));
                if (remaining <= 0)
                {
                    return active;
                }
                Thread.Sleep(Math.Min(10, remaining));
            }
        }

        private static void TerminateJobChecked(ReleaseSafeJobHandle job)
        {
            if (!TerminateJobObject(job, CleanupExitCode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "TerminateJobObject failed.");
            }
        }

        private static void TerminateProcessChecked(SafeProcessHandle process)
        {
            if (!TerminateProcess(process, CleanupExitCode))
            {
                int error = Marshal.GetLastWin32Error();
                uint wait = WaitForSingleObject(process, 0);
                if (wait != WaitObject0)
                {
                    throw new Win32Exception(error, "TerminateProcess failed.");
                }
            }
        }

        private static void CreateOutputPipe(
            out NamedPipeServerStream parentRead,
            out NamedPipeClientStream childWrite)
        {
            parentRead = null;
            childWrite = null;
            string name = "CodexGuardian.Release." + Guid.NewGuid().ToString("N");
            NamedPipeServerStream server = null;
            NamedPipeClientStream client = null;
            try
            {
                server = new NamedPipeServerStream(
                    name,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096,
                    4096);
                Task connection = server.WaitForConnectionAsync();
                client = new NamedPipeClientStream(
                    ".",
                    name,
                    PipeDirection.Out,
                    PipeOptions.None);
                client.Connect(5000);
                if (!connection.Wait(5000))
                {
                    throw new TimeoutException(
                        "A bounded output pipe did not connect within five seconds.");
                }
                connection.GetAwaiter().GetResult();
                if (!SetHandleInformation(
                        client.SafePipeHandle,
                        HandleFlagInherit,
                        HandleFlagInherit))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "A bounded output pipe could not be marked inheritable.");
                }
                parentRead = server;
                childWrite = client;
                server = null;
                client = null;
            }
            finally
            {
                if (client != null)
                {
                    client.Dispose();
                }
                if (server != null)
                {
                    server.Dispose();
                }
            }
        }

        private static SafeFileHandle CreateInheritedNullInput()
        {
            SecurityAttributes attributes = new SecurityAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(SecurityAttributes));
            attributes.InheritHandle = 1;
            SafeFileHandle handle = CreateFileW(
                "NUL",
                GenericRead,
                FileShareRead | FileShareWrite,
                ref attributes,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                if (handle != null)
                {
                    handle.Dispose();
                }
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The bounded child NUL input handle could not be opened.");
            }
            if (!SetHandleInformation(
                    handle,
                    HandleFlagInherit,
                    HandleFlagInherit))
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(
                    error,
                    "The bounded child NUL input handle could not be marked inheritable.");
            }
            return handle;
        }

        private static void RejectControlCharacters(string value, string label)
        {
            if (value == null)
            {
                throw new ArgumentNullException(label);
            }
            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (character < 0x20 || character == 0x7F)
                {
                    throw new ArgumentException(
                        label + " contains a forbidden control character.");
                }
            }
        }

        private static void AppendQuotedArgument(
            StringBuilder commandLine,
            string argument)
        {
            if (argument.Length > 0 &&
                argument.IndexOfAny(new char[] { ' ', '\t', '\v', '"' }) < 0)
            {
                commandLine.Append(argument);
                return;
            }

            commandLine.Append('"');
            int backslashes = 0;
            foreach (char character in argument)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    commandLine.Append('\\', checked((backslashes * 2) + 1));
                    commandLine.Append('"');
                    backslashes = 0;
                    continue;
                }
                if (backslashes > 0)
                {
                    commandLine.Append('\\', backslashes);
                    backslashes = 0;
                }
                commandLine.Append(character);
            }
            if (backslashes > 0)
            {
                commandLine.Append('\\', checked(backslashes * 2));
            }
            commandLine.Append('"');
        }

        private static StringBuilder BuildCommandLine(
            string executable,
            string[] arguments)
        {
            RejectControlCharacters(executable, "The executable path");
            StringBuilder commandLine = new StringBuilder();
            AppendQuotedArgument(commandLine, executable);
            for (int index = 0; index < arguments.Length; index++)
            {
                RejectControlCharacters(
                    arguments[index],
                    "A bounded process argument");
                commandLine.Append(' ');
                AppendQuotedArgument(commandLine, arguments[index]);
            }
            if (commandLine.Length >= MaximumCommandLineCharacters)
            {
                throw new ArgumentException(
                    "The bounded Windows process command line is too long.");
            }
            return commandLine;
        }

        private static IntPtr BuildEnvironmentBlock(
            string[] names,
            string[] values)
        {
            if (names.Length != values.Length)
            {
                throw new ArgumentException(
                    "The bounded process environment arrays differ in length.");
            }

            HashSet<string> unique =
                new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<EnvironmentEntry> entries = new List<EnvironmentEntry>();
            for (int index = 0; index < names.Length; index++)
            {
                string name = names[index];
                string value = values[index];
                RejectControlCharacters(name, "An environment name");
                RejectControlCharacters(value, "An environment value");
                if (name.Length == 0 || name.IndexOf('=') >= 0 ||
                    !unique.Add(name))
                {
                    throw new ArgumentException(
                        "The bounded process environment is not a unique map.");
                }
                entries.Add(new EnvironmentEntry { Name = name, Value = value });
            }
            entries.Sort(delegate(EnvironmentEntry left, EnvironmentEntry right)
            {
                return StringComparer.OrdinalIgnoreCase.Compare(
                    left.Name,
                    right.Name);
            });

            StringBuilder block = new StringBuilder();
            foreach (EnvironmentEntry entry in entries)
            {
                block.Append(entry.Name);
                block.Append('=');
                block.Append(entry.Value);
                block.Append('\0');
            }
            block.Append('\0');
            byte[] bytes = Encoding.Unicode.GetBytes(block.ToString());
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static long ReadStartTimeUtcTicks(SafeProcessHandle process)
        {
            FileTime creation;
            FileTime exit;
            FileTime kernel;
            FileTime user;
            if (!GetProcessTimes(
                    process,
                    out creation,
                    out exit,
                    out kernel,
                    out user))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetProcessTimes failed.");
            }
            long fileTime =
                ((long)creation.High << 32) | (long)creation.Low;
            return DateTime.FromFileTimeUtc(fileTime).Ticks;
        }

        private static int ReadExitCode(SafeProcessHandle process)
        {
            uint exitCode;
            if (!GetExitCodeProcess(process, out exitCode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetExitCodeProcess failed.");
            }
            return unchecked((int)exitCode);
        }

        private static bool WaitForProcess(
            SafeProcessHandle process,
            int timeoutMilliseconds)
        {
            uint wait = WaitForSingleObject(
                process,
                (uint)Math.Max(0, timeoutMilliseconds));
            if (wait == WaitObject0)
            {
                return true;
            }
            if (wait == WaitTimeout)
            {
                return false;
            }
            if (wait == WaitFailed)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "WaitForSingleObject failed.");
            }
            throw new InvalidOperationException(
                "WaitForSingleObject returned an unexpected value.");
        }

        private static async Task DrainBoundedAsync(
            Stream source,
            MemoryStream destination,
            int maximumBytes,
            CaptureState state,
            CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (true)
                {
                    int read = await source.ReadAsync(
                        buffer,
                        0,
                        buffer.Length,
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        return;
                    }
                    int total = Interlocked.Add(ref state.TotalBytes, read);
                    if (total > maximumBytes)
                    {
                        Interlocked.Exchange(ref state.OutputExceeded, 1);
                        return;
                    }
                    destination.Write(buffer, 0, read);
                }
            }
            catch (OperationCanceledException exception)
            {
                if (Volatile.Read(ref state.ForcedDrain) == 0 ||
                    !cancellationToken.IsCancellationRequested)
                {
                    state.RecordDrainFailure(exception);
                }
            }
            catch (ObjectDisposedException exception)
            {
                if (Volatile.Read(ref state.ForcedDrain) == 0)
                {
                    state.RecordDrainFailure(exception);
                }
            }
            catch (Exception exception)
            {
                state.RecordDrainFailure(exception);
            }
        }

        private static bool WaitForDrains(
            Task stdoutTask,
            Task stderrTask,
            int timeoutMilliseconds)
        {
            if (stdoutTask == null && stderrTask == null)
            {
                return true;
            }
            if (stdoutTask == null || stderrTask == null ||
                timeoutMilliseconds <= 0)
            {
                return false;
            }
            try
            {
                return Task.WaitAll(
                    new Task[] { stdoutTask, stderrTask },
                    timeoutMilliseconds);
            }
            catch
            {
                return false;
            }
        }

        private static int RemainingMilliseconds(
            Stopwatch timer,
            int totalMilliseconds)
        {
            long remaining = (long)totalMilliseconds - timer.ElapsedMilliseconds;
            if (remaining <= 0)
            {
                return 0;
            }
            return (int)Math.Min(Int32.MaxValue, remaining);
        }

        private static string AppendFailure(
            string current,
            string label,
            Exception exception)
        {
            string detail = label + ":" + exception.GetType().FullName +
                ":" + exception.Message;
            detail = detail.Replace('\r', ' ').Replace('\n', ' ');
            if (detail.Length > 1024)
            {
                detail = detail.Substring(0, 1024);
            }
            string combined = String.IsNullOrEmpty(current)
                ? detail
                : current + "; " + detail;
            return combined.Length <= 2048
                ? combined
                : combined.Substring(0, 2048);
        }

        private static string AppendFailure(
            string current,
            string label,
            string detail)
        {
            string bounded = (label + ":" + detail)
                .Replace('\r', ' ')
                .Replace('\n', ' ');
            if (bounded.Length > 1024)
            {
                bounded = bounded.Substring(0, 1024);
            }
            string combined = String.IsNullOrEmpty(current)
                ? bounded
                : current + "; " + bounded;
            return combined.Length <= 2048
                ? combined
                : combined.Substring(0, 2048);
        }

        public static ReleaseBoundedProcessResultV2 Run(
            string executable,
            string[] arguments,
            string workingDirectory,
            string[] environmentNames,
            string[] environmentValues,
            int timeoutMilliseconds,
            int maximumBytes)
        {
            if (String.IsNullOrWhiteSpace(executable) ||
                !Path.IsPathRooted(executable) ||
                !File.Exists(executable))
            {
                throw new ArgumentException(
                    "The bounded process executable is not an existing absolute file.");
            }
            if (arguments == null || environmentNames == null ||
                environmentValues == null)
            {
                throw new ArgumentNullException(
                    "A bounded process input array is null.");
            }
            if (String.IsNullOrWhiteSpace(workingDirectory) ||
                !Path.IsPathRooted(workingDirectory) ||
                !Directory.Exists(workingDirectory))
            {
                throw new ArgumentException(
                    "The bounded process working directory is not an existing absolute directory.");
            }
            RejectControlCharacters(workingDirectory, "The working directory");
            if (timeoutMilliseconds < 1 || maximumBytes < 1)
            {
                throw new ArgumentOutOfRangeException(
                    "A bounded process limit is not positive.");
            }

            StringBuilder commandLine = BuildCommandLine(executable, arguments);
            IntPtr environmentBlock = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr attributeHandles = IntPtr.Zero;
            bool attributeListInitialized = false;
            ProcessInformation processInformation = new ProcessInformation();
            ReleaseSafeJobHandle job = null;
            SafeProcessHandle process = null;
            ReleaseSafeKernelHandle thread = null;
            NamedPipeServerStream stdoutParent = null;
            NamedPipeClientStream stdoutChild = null;
            NamedPipeServerStream stderrParent = null;
            NamedPipeClientStream stderrChild = null;
            SafeFileHandle nullInput = null;
            MemoryStream stdout = new MemoryStream();
            MemoryStream stderr = new MemoryStream();
            CancellationTokenSource drainCancellation =
                new CancellationTokenSource();
            CaptureState capture = new CaptureState();
            Task stdoutTask = null;
            Task stderrTask = null;
            int processId = -1;
            long startTimeUtcTicks = 0;
            int exitCode = Int32.MinValue;
            bool assignedToJob = false;
            bool rootSignaled = false;
            bool timedOut = false;
            bool drainsComplete = false;
            bool forcedDrain = false;
            bool drainIncomplete = true;
            bool cleanupIncomplete = false;
            int residualBeforeCleanup = 0;
            int residualAfterCleanup = 0;
            string failureMessage = null;
            ReleaseBoundedProcessResultV2 result = null;

            try
            {
                try
                {
                    environmentBlock = BuildEnvironmentBlock(
                        environmentNames,
                        environmentValues);
                    job = CreateKillOnCloseJob();
                    CreateOutputPipe(out stdoutParent, out stdoutChild);
                    CreateOutputPipe(out stderrParent, out stderrChild);
                    nullInput = CreateInheritedNullInput();

                    IntPtr attributeListSize = IntPtr.Zero;
                    InitializeProcThreadAttributeList(
                        IntPtr.Zero,
                        1,
                        0,
                        ref attributeListSize);
                    if (attributeListSize == IntPtr.Zero)
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Unable to size the bounded process attribute list.");
                    }
                    attributeList = Marshal.AllocHGlobal(attributeListSize);
                    if (!InitializeProcThreadAttributeList(
                            attributeList,
                            1,
                            0,
                            ref attributeListSize))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Unable to initialize the bounded process attribute list.");
                    }
                    attributeListInitialized = true;
                    attributeHandles = Marshal.AllocHGlobal(
                        checked(IntPtr.Size * 3));
                    Marshal.WriteIntPtr(
                        attributeHandles,
                        0,
                        nullInput.DangerousGetHandle());
                    Marshal.WriteIntPtr(
                        attributeHandles,
                        IntPtr.Size,
                        stdoutChild.SafePipeHandle.DangerousGetHandle());
                    Marshal.WriteIntPtr(
                        attributeHandles,
                        IntPtr.Size * 2,
                        stderrChild.SafePipeHandle.DangerousGetHandle());
                    if (!UpdateProcThreadAttribute(
                            attributeList,
                            0,
                            new IntPtr(ProcThreadAttributeHandleList),
                            attributeHandles,
                            new IntPtr(checked(IntPtr.Size * 3)),
                            IntPtr.Zero,
                            IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Unable to restrict the bounded child handle list.");
                    }

                    StartupInfoEx startupInfo = new StartupInfoEx();
                    startupInfo.StartupInfo.Size =
                        (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                    startupInfo.StartupInfo.Flags = StartfUseStdHandles;
                    startupInfo.StartupInfo.StandardInput =
                        nullInput.DangerousGetHandle();
                    startupInfo.StartupInfo.StandardOutput =
                        stdoutChild.SafePipeHandle.DangerousGetHandle();
                    startupInfo.StartupInfo.StandardError =
                        stderrChild.SafePipeHandle.DangerousGetHandle();
                    startupInfo.AttributeList = attributeList;

                    uint creationFlags =
                        CreateSuspended |
                        CreateUnicodeEnvironment |
                        ExtendedStartupInfoPresent |
                        CreateNoWindow;
                    if (!CreateProcessW(
                            executable,
                            commandLine,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            true,
                            creationFlags,
                            environmentBlock,
                            workingDirectory,
                            ref startupInfo,
                            out processInformation))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "CreateProcessW failed for the bounded release child.");
                    }

                    process = new SafeProcessHandle(
                        processInformation.Process,
                        true);
                    processInformation.Process = IntPtr.Zero;
                    thread = new ReleaseSafeKernelHandle(
                        processInformation.Thread);
                    processInformation.Thread = IntPtr.Zero;
                    if (process.IsInvalid || thread.IsInvalid)
                    {
                        throw new Win32Exception(
                            "CreateProcessW returned an invalid process or thread handle.");
                    }
                    processId = checked((int)processInformation.ProcessId);
                    startTimeUtcTicks = ReadStartTimeUtcTicks(process);

                    stdoutChild.Dispose();
                    stdoutChild = null;
                    stderrChild.Dispose();
                    stderrChild = null;
                    nullInput.Dispose();
                    nullInput = null;

                    if (!AssignProcessToJobObject(job, process))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "AssignProcessToJobObject failed.");
                    }
                    assignedToJob = true;

                    stdoutTask = DrainBoundedAsync(
                        stdoutParent,
                        stdout,
                        maximumBytes,
                        capture,
                        drainCancellation.Token);
                    stderrTask = DrainBoundedAsync(
                        stderrParent,
                        stderr,
                        maximumBytes,
                        capture,
                        drainCancellation.Token);

                    Stopwatch runTimer = Stopwatch.StartNew();
                    if (ResumeThread(thread) == UInt32.MaxValue)
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "ResumeThread failed.");
                    }
                    thread.Dispose();
                    thread = null;

                    while (true)
                    {
                        if (Volatile.Read(ref capture.OutputExceeded) != 0)
                        {
                            break;
                        }
                        string drainFailure = capture.ReadDrainFailure();
                        if (!String.IsNullOrEmpty(drainFailure))
                        {
                            throw new IOException(
                                "A bounded output drain failed: " + drainFailure);
                        }
                        int remaining = timeoutMilliseconds -
                            checked((int)Math.Min(
                                timeoutMilliseconds,
                                runTimer.ElapsedMilliseconds));
                        if (remaining <= 0)
                        {
                            timedOut = true;
                            break;
                        }
                        uint wait = WaitForSingleObject(
                            process,
                            (uint)Math.Min(20, remaining));
                        if (wait == WaitObject0)
                        {
                            rootSignaled = true;
                            break;
                        }
                        if (wait == WaitFailed)
                        {
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "WaitForSingleObject failed during bounded execution.");
                        }
                        if (wait != WaitTimeout)
                        {
                            throw new InvalidOperationException(
                                "WaitForSingleObject returned an unexpected value.");
                        }
                    }

                    if (rootSignaled)
                    {
                        exitCode = ReadExitCode(process);
                        residualBeforeCleanup = checked((int)WaitForJobToEmpty(
                            job,
                            NaturalExitAccountingGraceMilliseconds));
                    }
                    else
                    {
                        residualBeforeCleanup =
                            checked((int)ReadActiveProcessCount(job));
                    }
                }
                catch (Exception exception)
                {
                    failureMessage = AppendFailure(
                        failureMessage,
                        "run",
                        exception);
                }

                Stopwatch cleanupTimer = Stopwatch.StartNew();
                try
                {
                    bool processUsable =
                        process != null && !process.IsInvalid &&
                        !process.IsClosed;
                    bool mustTerminate =
                        processUsable &&
                        (!rootSignaled ||
                         !String.IsNullOrEmpty(failureMessage) ||
                         timedOut ||
                         Volatile.Read(ref capture.OutputExceeded) != 0 ||
                         residualBeforeCleanup != 0);
                    if (mustTerminate)
                    {
                        if (assignedToJob)
                        {
                            TerminateJobChecked(job);
                        }
                        else
                        {
                            TerminateProcessChecked(process);
                        }
                    }

                    if (processUsable)
                    {
                        rootSignaled = WaitForProcess(
                            process,
                            RemainingMilliseconds(
                                cleanupTimer,
                                CleanupTimeoutMilliseconds));
                    }
                    else
                    {
                        rootSignaled = process == null;
                    }

                    if (assignedToJob && job != null &&
                        !job.IsInvalid && !job.IsClosed)
                    {
                        residualAfterCleanup = checked((int)WaitForJobToEmpty(
                            job,
                            RemainingMilliseconds(
                                cleanupTimer,
                                CleanupTimeoutMilliseconds)));
                    }
                    else
                    {
                        residualAfterCleanup = rootSignaled ? 0 : Int32.MaxValue;
                    }
                }
                catch (Exception exception)
                {
                    cleanupIncomplete = true;
                    residualAfterCleanup = Int32.MaxValue;
                    failureMessage = AppendFailure(
                        failureMessage,
                        "cleanup",
                        exception);
                }

                int drainWait = RemainingMilliseconds(
                    cleanupTimer,
                    CleanupTimeoutMilliseconds);
                drainsComplete = WaitForDrains(
                    stdoutTask,
                    stderrTask,
                    drainWait);
                if (!drainsComplete)
                {
                    forcedDrain = true;
                    Interlocked.Exchange(ref capture.ForcedDrain, 1);
                    drainCancellation.Cancel();
                    if (stdoutParent != null)
                    {
                        stdoutParent.Dispose();
                    }
                    if (stderrParent != null)
                    {
                        stderrParent.Dispose();
                    }
                    drainsComplete = WaitForDrains(
                        stdoutTask,
                        stderrTask,
                        1000);
                }

                string drainFailureAfterCleanup = capture.ReadDrainFailure();
                drainIncomplete = forcedDrain ||
                    !drainsComplete ||
                    !String.IsNullOrEmpty(drainFailureAfterCleanup);
                if (!String.IsNullOrEmpty(drainFailureAfterCleanup))
                {
                    failureMessage = AppendFailure(
                        failureMessage,
                        "drain",
                        drainFailureAfterCleanup);
                }
                if (!rootSignaled || residualAfterCleanup != 0 ||
                    !drainsComplete)
                {
                    cleanupIncomplete = true;
                }

                byte[] stdoutBytes = !drainIncomplete
                    ? stdout.ToArray()
                    : new byte[0];
                byte[] stderrBytes = !drainIncomplete
                    ? stderr.ToArray()
                    : new byte[0];
                string stdoutText = String.Empty;
                string stderrText = String.Empty;
                try
                {
                    UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
                    stdoutText = strictUtf8.GetString(stdoutBytes);
                    stderrText = strictUtf8.GetString(stderrBytes);
                }
                catch (Exception exception)
                {
                    failureMessage = AppendFailure(
                        failureMessage,
                        "utf8",
                        exception);
                }

                if (rootSignaled && process != null &&
                    !process.IsInvalid && !process.IsClosed)
                {
                    try
                    {
                        exitCode = ReadExitCode(process);
                    }
                    catch (Exception exception)
                    {
                        failureMessage = AppendFailure(
                            failureMessage,
                            "exit",
                            exception);
                    }
                }

                result = new ReleaseBoundedProcessResultV2
                {
                    ProcessId = processId,
                    StartTimeUtcTicks = startTimeUtcTicks,
                    ExitCode = exitCode,
                    Stdout = stdoutText,
                    Stderr = stderrText,
                    TimedOut = timedOut,
                    OutputExceeded =
                        Volatile.Read(ref capture.OutputExceeded) != 0,
                    DrainIncomplete = drainIncomplete,
                    CleanupIncomplete = cleanupIncomplete,
                    InternalFailure = !String.IsNullOrEmpty(failureMessage),
                    ResidualBeforeCleanup = residualBeforeCleanup,
                    ResidualProcessCount = residualAfterCleanup,
                    FailureMessage = failureMessage
                };
            }
            finally
            {
                try
                {
                    drainCancellation.Cancel();
                }
                catch
                {
                }
                if (stdoutChild != null)
                {
                    stdoutChild.Dispose();
                }
                if (stderrChild != null)
                {
                    stderrChild.Dispose();
                }
                if (stdoutParent != null)
                {
                    stdoutParent.Dispose();
                }
                if (stderrParent != null)
                {
                    stderrParent.Dispose();
                }
                if (nullInput != null)
                {
                    nullInput.Dispose();
                }
                if (thread != null)
                {
                    thread.Dispose();
                }
                if (process != null)
                {
                    process.Dispose();
                }
                if (processInformation.Thread != IntPtr.Zero)
                {
                    CloseHandle(processInformation.Thread);
                }
                if (processInformation.Process != IntPtr.Zero)
                {
                    CloseHandle(processInformation.Process);
                }
                if (job != null)
                {
                    job.Dispose();
                }
                if (attributeListInitialized)
                {
                    DeleteProcThreadAttributeList(attributeList);
                }
                if (attributeList != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attributeList);
                }
                if (attributeHandles != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attributeHandles);
                }
                if (environmentBlock != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(environmentBlock);
                }
                drainCancellation.Dispose();
                stdout.Dispose();
                stderr.Dispose();
            }

            if (result == null)
            {
                throw new InvalidOperationException(
                    "The bounded release process did not produce a result.");
            }
            return result;
        }
    }
}
'@
    Assert-ReleaseProcessMethodsShape
    $script:ReleaseProcessMethodsInitialized = $true
}

function Invoke-BoundedReleaseProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1800)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(1024, 16777216)][long]$MaximumOutputBytes
    )

    if ($Arguments.Count -eq 0) {
        throw "$Label did not provide a dotnet command."
    }
    foreach ($argument in $Arguments) {
        if ($null -eq $argument -or
            $argument.Contains("`r") -or
            $argument.Contains("`n") -or
            $argument.IndexOf([char]0) -ge 0) {
            throw "$Label contains an invalid dotnet argument."
        }
    }
    Assert-ReleaseDotnetEnvironment
    Assert-PinnedDotnetLeases -Authority $Authority
    Initialize-ReleaseProcessMethods
    $fullWorkingDirectory = Assert-NoReparsePointsInTree `
        -Path $WorkingDirectory `
        -Label "$Label working directory"
    $childEnvironment = Get-HermeticDotnetChildEnvironment
    try {
        $result = [CodexGuardian.ReleaseProcessMethodsV2]::Run(
            [string]$Authority.ExecutablePath,
            [string[]]$Arguments,
            $fullWorkingDirectory,
            [string[]]$childEnvironment.Names,
            [string[]]$childEnvironment.Values,
            [int]($TimeoutSeconds * 1000),
            [int]$MaximumOutputBytes)
    }
    finally {
        Assert-PinnedDotnetLeases -Authority $Authority
    }
    if ($null -eq $result) {
        throw "$Label did not return a bounded process result."
    }
    if ($result.InternalFailure) {
        $failure = [string]$result.FailureMessage
        if ($failure.Length -gt 2048) {
            $failure = $failure.Substring(0, 2048)
        }
        throw "$Label bounded process helper failed: $failure"
    }
    if ($result.TimedOut -or
        $result.OutputExceeded -or
        $result.DrainIncomplete -or
        $result.CleanupIncomplete -or
        $result.ResidualBeforeCleanup -ne 0 -or
        $result.ResidualProcessCount -ne 0) {
        throw "$Label violated its process bounds: timeout=$($result.TimedOut) outputExceeded=$($result.OutputExceeded) drainIncomplete=$($result.DrainIncomplete) cleanupIncomplete=$($result.CleanupIncomplete) residualBefore=$($result.ResidualBeforeCleanup) residualAfter=$($result.ResidualProcessCount) pid=$($result.ProcessId) start=$($result.StartTimeUtcTicks)"
    }
    return $result
}

function Invoke-BoundedDotnetGate {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string]$Assembly,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$SuccessMarker,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 600) {
        throw "A bounded dotnet gate timeout is outside its allowed range: $TimeoutSeconds"
    }
    if ($Assembly.Contains('"') -or
        $Assembly.Contains("`r") -or
        $Assembly.Contains("`n") -or
        $Assembly.IndexOf([char]0) -ge 0) {
        throw 'A bounded dotnet gate assembly path contains an invalid quote or control character.'
    }
    if ($SuccessMarker -notmatch '^[A-Z0-9_]+$') {
        throw "A bounded dotnet gate marker is not a strict control identifier: $SuccessMarker"
    }
    foreach ($argument in $Arguments) {
        if ([string]::IsNullOrWhiteSpace($argument) -or
            $argument.Contains('"') -or
            $argument.Contains("`r") -or
            $argument.Contains("`n") -or
            $argument.IndexOf([char]0) -ge 0 -or
            $argument -match '\s') {
            throw "A bounded dotnet gate argument is not a single control token: $argument"
        }
    }

    $fullAssembly = Assert-NoReparseTraversal $Assembly
    $fullArtifactsRoot = [System.IO.Path]::GetFullPath($ArtifactsRoot).TrimEnd('\')
    $artifactsPrefix = $fullArtifactsRoot + '\'
    $pathWithoutRoot = $fullAssembly.Substring(
        [System.IO.Path]::GetPathRoot($fullAssembly).Length)
    if (!$fullAssembly.StartsWith(
            $artifactsPrefix,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        !(Test-Path -LiteralPath $fullAssembly -PathType Leaf) -or
        ![string]::Equals(
            [System.IO.Path]::GetExtension($fullAssembly),
            '.dll',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $pathWithoutRoot.Contains(':')) {
        throw "A bounded dotnet gate assembly is outside the isolated artifacts tree or is not a DLL: $fullAssembly"
    }

    $fullWorkingDirectory = Assert-NoReparsePointsInTree `
        -Path $WorkingDirectory `
        -Label "$Label working directory"
    $preflightDeadline = New-MonotonicDeadline 5000
    $preexistingArtifactProcesses = @(Get-BoundedGateArtifactProcesses `
        -Deadline $preflightDeadline `
        -Label $Label)
    if ($preexistingArtifactProcesses.Count -gt 0) {
        throw "$Label found pre-existing probe artifact processes: $($preexistingArtifactProcesses.ProcessId -join ',')"
    }

    try {
        $result = Invoke-BoundedReleaseProcess `
            -Authority $Authority `
            -Arguments (@($fullAssembly) + $Arguments) `
            -WorkingDirectory $fullWorkingDirectory `
            -Label $Label `
            -TimeoutSeconds $TimeoutSeconds `
            -MaximumOutputBytes (4L * 1024 * 1024)

        $cleanupDeadline = New-MonotonicDeadline 10000
        $escapedArtifactCount = Stop-BoundedGateArtifactProcesses `
            -Label $Label `
            -Deadline $cleanupDeadline
        if ($escapedArtifactCount -ne 0) {
            throw "$Label created probe artifact processes outside the bounded job: count=$escapedArtifactCount"
        }

        $stdout = [string]$result.Stdout
        $stderr = [string]$result.Stderr
        $markerCount = Get-ExactMarkerCount -Text $stdout -Marker $SuccessMarker
        $stdoutDisplay = $stdout.TrimEnd()
        if ($stdoutDisplay.Length -gt 16384) {
            $stdoutDisplay = '[stdout tail truncated]' + [Environment]::NewLine +
                $stdoutDisplay.Substring($stdoutDisplay.Length - 16384)
        }
        if (![string]::IsNullOrWhiteSpace($stdoutDisplay)) {
            Write-Host $stdoutDisplay
        }

        if ($result.ExitCode -ne 0 -or $markerCount -ne 1 -or $stderr.Length -ne 0) {
            $stderrBytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($stderr)
            $stderrSha256 = Get-ReleaseBytesSha256 -Bytes $stderrBytes
            throw "$Label failed: exit=$($result.ExitCode) marker=$SuccessMarker markerCount=$markerCount stderrLength=$($stderrBytes.Length) stderrSha256=$stderrSha256 pid=$($result.ProcessId) start=$($result.StartTimeUtcTicks)"
        }
    }
    catch {
        $primaryFailure = $_
        $cleanupFailures = [System.Collections.Generic.List[string]]::new()
        $cleanupDeadline = New-MonotonicDeadline 10000
        try {
            [void](Stop-BoundedGateArtifactProcesses `
                -Label $Label `
                -Deadline $cleanupDeadline)
        }
        catch {
            $cleanupFailures.Add($_.Exception.Message)
        }
        if ($cleanupFailures.Count -gt 0) {
            throw "$($primaryFailure.Exception.Message) Cleanup failure: $($cleanupFailures -join '; ')"
        }
        throw $primaryFailure
    }
}

function Assert-GuardianStopped {
    $runningGuardian = Get-Process -Name CodexGuardian -ErrorAction SilentlyContinue
    if (!$runningGuardian) {
        return
    }

    $details = ($runningGuardian | ForEach-Object {
        try { "$($_.Id):$($_.Path)" } catch { "$($_.Id)" }
    }) -join ', '
    throw "Close Codex Guardian before release build or packaging. Running: $details"
}

function Enter-GuardianReleaseLease {
    $mutex = [System.Threading.Mutex]::new($false, $GuardianReleaseMutexName)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (!$acquired) {
            throw 'CodexGuardian is running or another release exchange owns the Guardian release lease.'
        }
        return $mutex
    }
    catch {
        if (!$acquired) {
            $mutex.Dispose()
        }
        throw
    }
}

function Exit-GuardianReleaseLease {
    param([Parameter(Mandatory = $true)][System.Threading.Mutex]$Mutex)

    try {
        $Mutex.ReleaseMutex()
    }
    finally {
        $Mutex.Dispose()
    }
}

function Assert-ExistingDesktopShortcut {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $expectedTarget = [System.IO.Path]::GetFullPath((Join-Path $RuntimeOutput 'CodexGuardian.exe'))
    $expectedWorkingDirectory = [System.IO.Path]::GetFullPath($RuntimeOutput)
    $shell = New-Object -ComObject WScript.Shell
    $matchingShortcut = $null
    try {
        foreach ($candidate in Get-ChildItem -LiteralPath $desktopPath -Filter '*.lnk' -File) {
            $candidateShortcut = $null
            try {
                $candidateShortcut = $shell.CreateShortcut($candidate.FullName)
                if ([string]::IsNullOrWhiteSpace($candidateShortcut.TargetPath)) {
                    continue
                }

                $candidateTarget = [System.IO.Path]::GetFullPath($candidateShortcut.TargetPath)
                if ([string]::Equals($candidateTarget, $expectedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $matchingShortcut = $candidateShortcut
                    $candidateShortcut = $null
                    break
                }
            }
            catch {
                continue
            }
            finally {
                if ($null -ne $candidateShortcut) {
                    [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($candidateShortcut)
                }
            }
        }

        if ($null -eq $matchingShortcut) {
            throw 'No desktop shortcut targets the packaged CodexGuardian executable.'
        }

        $actualWorkingDirectory = [System.IO.Path]::GetFullPath($matchingShortcut.WorkingDirectory)
        if (![string]::Equals($actualWorkingDirectory, $expectedWorkingDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Desktop shortcut uses an unexpected working directory: $($matchingShortcut.WorkingDirectory)"
        }

        $actualIcon = ($matchingShortcut.IconLocation -split ',', 2)[0].Trim('"')
        if ([string]::IsNullOrWhiteSpace($actualIcon) -or
            ![string]::Equals([System.IO.Path]::GetFullPath($actualIcon), $expectedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Desktop shortcut uses an unexpected icon: $($matchingShortcut.IconLocation)"
        }
    }
    finally {
        if ($null -ne $matchingShortcut) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($matchingShortcut)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
}

function Remove-ManagedArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (!(Test-Path -LiteralPath $Path)) {
        return
    }

    if (Test-Path -LiteralPath $Path -PathType Container) {
        Remove-ManagedDirectoryTree $Path
    }
    else {
        Remove-ManagedFile $Path
    }
}

function New-ManagedOutputDirectory {
    param([Parameter(Mandatory = $true)][string]$Destination)

    $managedDestination = Assert-OutputPath $Destination
    if (Test-Path -LiteralPath $managedDestination) {
        throw "A managed output directory already exists: $managedDestination"
    }
    New-Item -ItemType Directory -Path $managedDestination | Out-Null
}

function Copy-ManagedOutputTree {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullSource = Assert-NoReparsePointsInTree -Path $Source -Label "$Label source"
    $managedDestination = Assert-OutputPath $Destination
    if (!(Test-Path -LiteralPath $managedDestination -PathType Container)) {
        throw "$Label destination is not an existing managed directory: $managedDestination"
    }
    foreach ($entry in Get-ChildItem -LiteralPath $fullSource -Force) {
        Copy-Item `
            -LiteralPath $entry.FullName `
            -Destination $managedDestination `
            -Recurse `
            -Force
    }
}

function Compress-CanonicalArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][object[]]$ExpectedManifest,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateSet('scratch', 'output')][string]$DestinationScope
    )

    $fullSource = Assert-NoReparsePointsInTree -Path $Source -Label "$Label source"
    $fullDestination = if ($DestinationScope -eq 'output') {
        Assert-OutputPath $Destination
    }
    else {
        $scratchDestination = Assert-ScratchPath $Destination
        $null = Assert-NoReparseTraversal $scratchDestination
        $scratchDestination
    }
    if (Test-Path -LiteralPath $fullDestination) {
        throw "$Label destination already exists: $fullDestination"
    }
    $destinationParent = Split-Path $fullDestination -Parent
    $null = Assert-NoReparsePointsInTree -Path $destinationParent -Label "$Label destination parent"
    $manifest = @(Get-OrdinalContentManifest `
        -Entries $ExpectedManifest `
        -Label "$Label archive producer manifest")

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveStream = $null
    $archive = $null
    $completed = $false
    try {
        $archiveStream = [System.IO.FileStream]::new(
            $fullDestination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            65536,
            [System.IO.FileOptions]::WriteThrough)
        $archive = [System.IO.Compression.ZipArchive]::new(
            $archiveStream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $true)
        foreach ($manifestEntry in $manifest) {
            $entryPath = Assert-CanonicalContentPath `
                -Path ([string]$manifestEntry.Path) `
                -Label $Label
            $sourcePath = Assert-NoReparseReadTraversal (
                Join-Path $fullSource ($entryPath.Replace('/', '\')))
            $actualRelativePath = (Get-ReleaseRelativePath `
                -Root $fullSource `
                -Path $sourcePath).Replace('\', '/')
            if (![string]::Equals(
                    $actualRelativePath,
                    $entryPath,
                    [System.StringComparison]::Ordinal)) {
                throw "$Label source path changed before compression: $entryPath"
            }

            $sourceStream = [System.IO.File]::Open(
                $sourcePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            try {
                if ([long]$sourceStream.Length -ne [long]$manifestEntry.Length) {
                    throw "$Label source length changed before compression: $entryPath"
                }
                $zipEntry = $archive.CreateEntry(
                    $entryPath,
                    [System.IO.Compression.CompressionLevel]::Optimal)
                $zipEntry.LastWriteTime = [DateTimeOffset]::new(
                    1980,
                    1,
                    1,
                    0,
                    0,
                    0,
                    [TimeSpan]::Zero)
                $zipStream = $zipEntry.Open()
                try {
                    $sourceStream.CopyTo($zipStream, 65536)
                }
                finally {
                    $zipStream.Dispose()
                }
            }
            finally {
                $sourceStream.Dispose()
            }
        }
        $archive.Dispose()
        $archive = $null
        $archiveStream.Flush($true)
        $completed = $true
    }
    finally {
        if ($null -ne $archive) {
            $archive.Dispose()
        }
        if ($null -ne $archiveStream) {
            $archiveStream.Dispose()
        }
        if (!$completed -and (Test-Path -LiteralPath $fullDestination)) {
            if ($DestinationScope -eq 'output') {
                Remove-ManagedFile $fullDestination
            }
            else {
                Remove-Item -LiteralPath $fullDestination -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Compress-ManagedOutputArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][object[]]$ExpectedManifest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Compress-CanonicalArchive `
        -Source $Source `
        -Destination $Destination `
        -ExpectedManifest $ExpectedManifest `
        -Label $Label `
        -DestinationScope output
}

function Write-ManagedOutputLines {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string[]]$Lines
    )

    $managedDestination = Assert-OutputPath $Destination
    [System.IO.File]::WriteAllLines(
        $managedDestination,
        $Lines,
        [System.Text.UTF8Encoding]::new($false))
}

function Sync-ManagedArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $managedPath = Assert-OutputPath $Path
    $files = if ($Kind -eq 'tree') {
        $fullTree = Assert-NoReparsePointsInTree -Path $managedPath -Label $Label
        @(Get-ChildItem -LiteralPath $fullTree -File -Recurse -Force)
    }
    else {
        if (!(Test-Path -LiteralPath $managedPath -PathType Leaf)) {
            throw "$Label file is unavailable before its durable barrier: $managedPath"
        }
        @((Get-Item -LiteralPath $managedPath -Force))
    }

    foreach ($file in $files) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point before its durable barrier: $($file.FullName)"
        }
        $stream = [System.IO.FileStream]::new(
            $file.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read,
            65536,
            [System.IO.FileOptions]::WriteThrough)
        try {
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }

    if ($Kind -eq 'tree') {
        $null = Assert-NoReparsePointsInTree -Path $managedPath -Label "$Label after durable barrier"
    }
}

function Move-ManagedArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [switch]$ReplaceExisting
    )

    $managedSource = Assert-OutputPath $Source
    $managedDestination = Assert-OutputPath $Destination
    if (!(Test-Path -LiteralPath $managedSource)) {
        throw "Release artifact does not exist: $managedSource"
    }
    if (!$ReplaceExisting -and (Test-Path -LiteralPath $managedDestination)) {
        throw "Release artifact destination already exists: $managedDestination"
    }
    if ($ReplaceExisting -and (Test-Path -LiteralPath $managedDestination -PathType Container)) {
        throw "A durable release file replacement cannot target a directory: $managedDestination"
    }

    $sourceRoot = [System.IO.Path]::GetPathRoot($managedSource)
    $destinationRoot = [System.IO.Path]::GetPathRoot($managedDestination)
    if (![string]::Equals($sourceRoot, $destinationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Release artifact exchange must remain on one volume: $managedSource -> $managedDestination"
    }

    Initialize-ReleaseNativeMethods
    $moveFlags = [uint32]8 # MOVEFILE_WRITE_THROUGH
    if ($ReplaceExisting) {
        $moveFlags = $moveFlags -bor [uint32]1 # MOVEFILE_REPLACE_EXISTING
    }
    if (![CodexGuardian.ReleaseNativeMethodsV2]::MoveFileEx(
            $managedSource,
            $managedDestination,
            $moveFlags)) {
        $nativeError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new(
            $nativeError,
            "Durable release rename failed: $managedSource -> $managedDestination")
    }
    if ((Test-Path -LiteralPath $managedSource) -or
        !(Test-Path -LiteralPath $managedDestination)) {
        throw "Durable release rename did not settle at the expected path: $managedSource -> $managedDestination"
    }
}

function Assert-ReleaseNativeMethodsShape {
    $type = 'CodexGuardian.ReleaseNativeMethodsV2' -as [type]
    if ($null -eq $type) {
        throw 'The release native helper type is unavailable.'
    }
    $bindingFlags = [System.Reflection.BindingFlags]::Public -bor
        [System.Reflection.BindingFlags]::Static -bor
        [System.Reflection.BindingFlags]::DeclaredOnly
    $methods = @($type.GetMethods($bindingFlags))
    if ($methods.Count -ne 1 -or
        $methods[0].Name -cne 'MoveFileEx' -or
        $methods[0].ReturnType -ne [bool]) {
        throw 'The release native helper method shape changed.'
    }
    $parameters = @($methods[0].GetParameters())
    $parameterTypes = @($parameters | ForEach-Object { $_.ParameterType.FullName })
    if (($parameterTypes -join '|') -cne 'System.String|System.String|System.UInt32') {
        throw 'The release native helper parameter shape changed.'
    }
    $imports = @($methods[0].GetCustomAttributes(
        [System.Runtime.InteropServices.DllImportAttribute],
        $false))
    $marshalReturns = @($methods[0].ReturnParameter.GetCustomAttributes(
        [System.Runtime.InteropServices.MarshalAsAttribute],
        $false))
    if ($imports.Count -ne 1 -or
        $imports[0].Value -cne 'kernel32.dll' -or
        $imports[0].EntryPoint -cne 'MoveFileExW' -or
        !$imports[0].SetLastError -or
        $imports[0].CharSet -ne [System.Runtime.InteropServices.CharSet]::Unicode -or
        $marshalReturns.Count -ne 1 -or
        $marshalReturns[0].Value -ne [System.Runtime.InteropServices.UnmanagedType]::Bool) {
        throw 'The release native helper interop contract changed.'
    }
}

function Initialize-ReleaseNativeMethods {
    if ($script:ReleaseNativeMethodsInitialized -eq $true) {
        Assert-ReleaseNativeMethodsShape
        return
    }
    if ($null -ne ('CodexGuardian.ReleaseNativeMethodsV2' -as [type])) {
        throw 'A release native helper type existed before this script initialized it.'
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace CodexGuardian
{
    public static class ReleaseNativeMethodsV2
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "MoveFileExW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existingPath, string destinationPath, uint flags);
    }
}
'@
    Assert-ReleaseNativeMethodsShape
    $script:ReleaseNativeMethodsInitialized = $true
}

function Assert-ExactReleaseProperties {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($null -eq $Value) {
        throw "$Label is null."
    }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Label has an unexpected property count."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (![string]::Equals(
                [string]$actual[$index],
                [string]$Expected[$index],
                [System.StringComparison]::Ordinal)) {
            throw "$Label has an unexpected property at index ${index}: $($actual[$index])"
        }
    }
}

function Assert-ReleaseIdentifier {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[a-f0-9]{32}$') {
        throw "$Label is not a canonical release identifier."
    }
    return $Value
}

function Assert-ReleaseSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[A-F0-9]{64}$') {
        throw "$Label is not a canonical SHA-256 value."
    }
    return $Value
}

function Get-ReleaseNonnegativeInt64 {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -isnot [byte] -and $Value -isnot [sbyte] -and
        $Value -isnot [int16] -and $Value -isnot [uint16] -and
        $Value -isnot [int32] -and $Value -isnot [uint32] -and
        $Value -isnot [int64]) {
        throw "$Label is not an integer."
    }
    $result = [long]$Value
    if ($result -lt 0) {
        throw "$Label cannot be negative."
    }
    return $result
}

function Assert-CanonicalReleaseTimestamp {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        $parsed = [DateTimeOffset]::ParseExact(
            $Value,
            'O',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind)
    }
    catch {
        throw "$Label is not a round-trip timestamp."
    }
    $canonical = $parsed.ToUniversalTime().ToString(
        'O',
        [System.Globalization.CultureInfo]::InvariantCulture)
    if (![string]::Equals($Value, $canonical, [System.StringComparison]::Ordinal)) {
        throw "$Label must be canonical UTC."
    }
    return $Value
}

function Convert-HexStringToBytes {
    param([Parameter(Mandatory = $true)][string]$Value)

    $null = Assert-ReleaseSha256 -Value $Value -Label 'A manifest entry hash'
    $bytes = New-Object byte[] 32
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Get-ReleaseBytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-ManifestIdentity {
    param(
        [Parameter(Mandatory = $true)][object[]]$Manifest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $entries = @(Get-OrdinalContentManifest -Entries $Manifest -Label $Label)
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $buffer = [System.IO.MemoryStream]::new()
    $totalBytes = 0L
    try {
        foreach ($entry in $entries) {
            $pathBytes = $utf8.GetBytes([string]$entry.Path)
            $pathLength = [System.Net.IPAddress]::HostToNetworkOrder([int]$pathBytes.Length)
            $pathLengthBytes = [System.BitConverter]::GetBytes($pathLength)
            $fileLength = [System.Net.IPAddress]::HostToNetworkOrder([long]$entry.Length)
            $fileLengthBytes = [System.BitConverter]::GetBytes($fileLength)
            [byte[]]$hashBytes = Convert-HexStringToBytes ([string]$entry.Sha256)
            $buffer.Write($pathLengthBytes, 0, $pathLengthBytes.Length)
            $buffer.Write($pathBytes, 0, $pathBytes.Length)
            $buffer.Write($fileLengthBytes, 0, $fileLengthBytes.Length)
            $buffer.Write($hashBytes, 0, $hashBytes.Length)
            $nextTotalBytes = $totalBytes + [long]$entry.Length
            if ($nextTotalBytes -lt $totalBytes) {
                throw "$Label total length overflowed."
            }
            $totalBytes = $nextTotalBytes
        }
        $digest = Get-ReleaseBytesSha256 -Bytes $buffer.ToArray()
    }
    finally {
        $buffer.Dispose()
    }

    return [pscustomobject][ordered]@{
        kind = 'tree'
        manifestSha256 = $digest
        fileCount = [long]$entries.Count
        totalBytes = $totalBytes
    }
}

function Get-ManagedArtifactIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $managedPath = Assert-OutputPath $Path
    if ($Kind -eq 'tree') {
        if (!(Test-Path -LiteralPath $managedPath -PathType Container)) {
            throw "$Label directory is unavailable: $managedPath"
        }
        $manifest = @(Get-TreeContentManifest -Root $managedPath -Label $Label)
        return Get-ManifestIdentity -Manifest $manifest -Label "$Label manifest"
    }

    if (!(Test-Path -LiteralPath $managedPath -PathType Leaf)) {
        throw "$Label file is unavailable: $managedPath"
    }
    $entry = Get-FileContentManifestEntry `
        -Root (Split-Path $managedPath -Parent) `
        -Path $managedPath `
        -Label $Label
    return [pscustomobject][ordered]@{
        kind = 'file'
        sha256 = [string]$entry.Sha256
        length = [long]$entry.Length
    }
}

function ConvertTo-CanonicalReleaseArtifactIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Identity,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Kind -eq 'tree') {
        Assert-ExactReleaseProperties `
            -Value $Identity `
            -Expected @('kind', 'manifestSha256', 'fileCount', 'totalBytes') `
            -Label $Label
        if (![string]::Equals([string]$Identity.kind, 'tree', [System.StringComparison]::Ordinal)) {
            throw "$Label kind is not tree."
        }
        return [pscustomobject][ordered]@{
            kind = 'tree'
            manifestSha256 = Assert-ReleaseSha256 `
                -Value ([string]$Identity.manifestSha256) `
                -Label "$Label manifest hash"
            fileCount = Get-ReleaseNonnegativeInt64 `
                -Value $Identity.fileCount `
                -Label "$Label file count"
            totalBytes = Get-ReleaseNonnegativeInt64 `
                -Value $Identity.totalBytes `
                -Label "$Label total bytes"
        }
    }

    Assert-ExactReleaseProperties `
        -Value $Identity `
        -Expected @('kind', 'sha256', 'length') `
        -Label $Label
    if (![string]::Equals([string]$Identity.kind, 'file', [System.StringComparison]::Ordinal)) {
        throw "$Label kind is not file."
    }
    return [pscustomobject][ordered]@{
        kind = 'file'
        sha256 = Assert-ReleaseSha256 -Value ([string]$Identity.sha256) -Label "$Label hash"
        length = Get-ReleaseNonnegativeInt64 -Value $Identity.length -Label "$Label length"
    }
}

function Test-ReleaseArtifactIdentityEqual {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind
    )

    $expectedCanonical = ConvertTo-CanonicalReleaseArtifactIdentity `
        -Identity $Expected `
        -Kind $Kind `
        -Label 'Expected release artifact identity'
    $actualCanonical = ConvertTo-CanonicalReleaseArtifactIdentity `
        -Identity $Actual `
        -Kind $Kind `
        -Label 'Actual release artifact identity'
    if ($Kind -eq 'tree') {
        return [string]::Equals(
                [string]$expectedCanonical.manifestSha256,
                [string]$actualCanonical.manifestSha256,
                [System.StringComparison]::Ordinal) -and
            [long]$expectedCanonical.fileCount -eq [long]$actualCanonical.fileCount -and
            [long]$expectedCanonical.totalBytes -eq [long]$actualCanonical.totalBytes
    }
    return [string]::Equals(
            [string]$expectedCanonical.sha256,
            [string]$actualCanonical.sha256,
            [System.StringComparison]::Ordinal) -and
        [long]$expectedCanonical.length -eq [long]$actualCanonical.length
}

function Get-OptionalManagedArtifactIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $managedPath = Assert-OutputPath $Path
    if (!(Test-Path -LiteralPath $managedPath)) {
        return $null
    }
    return Get-ManagedArtifactIdentity -Path $managedPath -Kind $Kind -Label $Label
}

function Assert-ManagedArtifactIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('tree', 'file')][string]$Kind,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = Get-ManagedArtifactIdentity -Path $Path -Kind $Kind -Label $Label
    if (!(Test-ReleaseArtifactIdentityEqual -Expected $Expected -Actual $actual -Kind $Kind)) {
        throw "$Label identity does not match the durable release transaction."
    }
}

function ConvertTo-CanonicalReleaseCommit {
    param(
        [Parameter(Mandatory = $true)][object]$Commit,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    Assert-ExactReleaseProperties `
        -Value $Commit `
        -Expected @('marker', 'schemaVersion', 'generationId', 'transactionId', 'committedUtc', 'projectVersion', 'artifacts') `
        -Label 'Release commit manifest'
    if (![string]::Equals(
            [string]$Commit.marker,
            'CODEXGUARDIAN_RELEASE_COMMIT_V1',
            [System.StringComparison]::Ordinal) -or
        [long](Get-ReleaseNonnegativeInt64 -Value $Commit.schemaVersion -Label 'Release commit schema') -ne 1L) {
        throw 'The release commit manifest marker or schema is unsupported.'
    }
    $generationId = Assert-ReleaseIdentifier -Value ([string]$Commit.generationId) -Label 'Release generation id'
    $transactionId = Assert-ReleaseIdentifier -Value ([string]$Commit.transactionId) -Label 'Release commit transaction id'
    if (![string]::Equals($generationId, $transactionId, [System.StringComparison]::Ordinal)) {
        throw 'The release commit generation and transaction ids differ.'
    }
    $timestamp = Assert-CanonicalReleaseTimestamp -Value ([string]$Commit.committedUtc) -Label 'Release commit timestamp'
    if (![string]::Equals(
            [string]$Commit.projectVersion,
            $ExpectedProjectVersion,
            [System.StringComparison]::Ordinal)) {
        throw 'The release commit project version is unexpected.'
    }
    $commitArtifacts = @($Commit.artifacts)
    if ($commitArtifacts.Count -ne $Artifacts.Count) {
        throw 'The release commit artifact count is unexpected.'
    }
    $canonicalArtifacts = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $descriptor = $Artifacts[$index]
        $entry = $commitArtifacts[$index]
        Assert-ExactReleaseProperties `
            -Value $entry `
            -Expected @('id', 'leaf', 'kind', 'identity') `
            -Label "Release commit artifact $index"
        if (![string]::Equals([string]$entry.id, [string]$descriptor.Id, [System.StringComparison]::Ordinal) -or
            ![string]::Equals([string]$entry.leaf, [string]$descriptor.Leaf, [System.StringComparison]::Ordinal) -or
            ![string]::Equals([string]$entry.kind, [string]$descriptor.Kind, [System.StringComparison]::Ordinal)) {
            throw "Release commit artifact $index does not match the fixed artifact plan."
        }
        $canonicalArtifacts.Add([pscustomobject][ordered]@{
            id = [string]$descriptor.Id
            leaf = [string]$descriptor.Leaf
            kind = [string]$descriptor.Kind
            identity = ConvertTo-CanonicalReleaseArtifactIdentity `
                -Identity $entry.identity `
                -Kind ([string]$descriptor.Kind) `
                -Label "Release commit artifact $($descriptor.Id)"
        })
    }
    return [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_COMMIT_V1'
        schemaVersion = 1
        generationId = $generationId
        transactionId = $transactionId
        committedUtc = $timestamp
        projectVersion = $ExpectedProjectVersion
        artifacts = $canonicalArtifacts.ToArray()
    }
}

function ConvertTo-CanonicalReleaseJournal {
    param(
        [Parameter(Mandatory = $true)][object]$Journal,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    Assert-ExactReleaseProperties `
        -Value $Journal `
        -Expected @('marker', 'schemaVersion', 'transactionId', 'createdUtc', 'protocol', 'oldCommit', 'newCommit', 'artifacts') `
        -Label 'Release exchange journal'
    if (![string]::Equals(
            [string]$Journal.marker,
            'CODEXGUARDIAN_RELEASE_TRANSACTION_V1',
            [System.StringComparison]::Ordinal) -or
        [long](Get-ReleaseNonnegativeInt64 -Value $Journal.schemaVersion -Label 'Release journal schema') -ne 1L -or
        ![string]::Equals(
            [string]$Journal.protocol,
            'rollback-before-commit',
            [System.StringComparison]::Ordinal)) {
        throw 'The release exchange journal marker schema or protocol is unsupported.'
    }
    $transactionId = Assert-ReleaseIdentifier `
        -Value ([string]$Journal.transactionId) `
        -Label 'Release journal transaction id'
    $createdUtc = Assert-CanonicalReleaseTimestamp `
        -Value ([string]$Journal.createdUtc) `
        -Label 'Release journal timestamp'

    Assert-ExactReleaseProperties `
        -Value $Journal.oldCommit `
        -Expected @('present', 'sha256', 'generationId') `
        -Label 'Release journal old commit'
    if ($Journal.oldCommit.present -isnot [bool]) {
        throw 'The release journal old commit presence flag is not Boolean.'
    }
    $oldCommitPresent = [bool]$Journal.oldCommit.present
    if ($oldCommitPresent) {
        $oldCommitSha256 = Assert-ReleaseSha256 `
            -Value ([string]$Journal.oldCommit.sha256) `
            -Label 'Release journal old commit hash'
        $oldGenerationId = Assert-ReleaseIdentifier `
            -Value ([string]$Journal.oldCommit.generationId) `
            -Label 'Release journal old generation id'
    }
    else {
        if ($null -ne $Journal.oldCommit.sha256 -or $null -ne $Journal.oldCommit.generationId) {
            throw 'An absent old commit cannot carry an identity.'
        }
        $oldCommitSha256 = $null
        $oldGenerationId = $null
    }

    Assert-ExactReleaseProperties `
        -Value $Journal.newCommit `
        -Expected @('generationId', 'sha256') `
        -Label 'Release journal new commit'
    $newGenerationId = Assert-ReleaseIdentifier `
        -Value ([string]$Journal.newCommit.generationId) `
        -Label 'Release journal new generation id'
    if (![string]::Equals($newGenerationId, $transactionId, [System.StringComparison]::Ordinal)) {
        throw 'The release journal new generation id differs from the transaction id.'
    }
    $newCommitSha256 = Assert-ReleaseSha256 `
        -Value ([string]$Journal.newCommit.sha256) `
        -Label 'Release journal new commit hash'

    $journalArtifacts = @($Journal.artifacts)
    if ($journalArtifacts.Count -ne $Artifacts.Count) {
        throw 'The release journal artifact count is unexpected.'
    }
    $canonicalArtifacts = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $descriptor = $Artifacts[$index]
        $entry = $journalArtifacts[$index]
        Assert-ExactReleaseProperties `
            -Value $entry `
            -Expected @('id', 'kind', 'hadCurrent', 'old', 'new') `
            -Label "Release journal artifact $index"
        if (![string]::Equals([string]$entry.id, [string]$descriptor.Id, [System.StringComparison]::Ordinal) -or
            ![string]::Equals([string]$entry.kind, [string]$descriptor.Kind, [System.StringComparison]::Ordinal)) {
            throw "Release journal artifact $index does not match the fixed artifact plan."
        }
        if ($entry.hadCurrent -isnot [bool]) {
            throw "Release journal artifact $index has a non-Boolean current flag."
        }
        $hadCurrent = [bool]$entry.hadCurrent
        if ($hadCurrent) {
            if ($null -eq $entry.old) {
                throw "Release journal artifact $index is missing its old identity."
            }
            $oldIdentity = ConvertTo-CanonicalReleaseArtifactIdentity `
                -Identity $entry.old `
                -Kind ([string]$descriptor.Kind) `
                -Label "Release journal old artifact $($descriptor.Id)"
        }
        else {
            if ($null -ne $entry.old) {
                throw "Release journal artifact $index unexpectedly carries an old identity."
            }
            $oldIdentity = $null
        }
        $newIdentity = ConvertTo-CanonicalReleaseArtifactIdentity `
            -Identity $entry.new `
            -Kind ([string]$descriptor.Kind) `
            -Label "Release journal new artifact $($descriptor.Id)"
        $canonicalArtifacts.Add([pscustomobject][ordered]@{
            id = [string]$descriptor.Id
            kind = [string]$descriptor.Kind
            hadCurrent = $hadCurrent
            old = $oldIdentity
            new = $newIdentity
        })
    }

    return [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_TRANSACTION_V1'
        schemaVersion = 1
        transactionId = $transactionId
        createdUtc = $createdUtc
        protocol = 'rollback-before-commit'
        oldCommit = [pscustomobject][ordered]@{
            present = $oldCommitPresent
            sha256 = $oldCommitSha256
            generationId = $oldGenerationId
        }
        newCommit = [pscustomobject][ordered]@{
            generationId = $newGenerationId
            sha256 = $newCommitSha256
        }
        artifacts = $canonicalArtifacts.ToArray()
    }
}

function ConvertTo-CanonicalReleaseJsonText {
    param([Parameter(Mandatory = $true)][object]$Value)

    return ($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine
}

function Write-CanonicalRuntimeConfigDev {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $managedPath = Assert-OutputPath $Path
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $canonicalBytes = $encoding.GetBytes('{"runtimeOptions":{}}' + "`r`n")
    if ($canonicalBytes.Length -ne 23 -or
        (Get-ReleaseBytesSha256 -Bytes $canonicalBytes) -cne
            '65F2DFF132AEC14731F86C569B5EC96691CACA7D822D02A18B79ACAEB5DC96D7') {
        throw 'The canonical runtimeconfig.dev.json bytes are internally inconsistent.'
    }

    if (!(Test-Path -LiteralPath $managedPath)) {
        $parent = Split-Path $managedPath -Parent
        $null = Assert-NoReparseTraversal $parent
        if (!(Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $null = Assert-NoReparsePointsInTree -Path $parent -Label "$Label parent"
        $stream = [System.IO.FileStream]::new(
            $managedPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough)
        try {
            $stream.Write($canonicalBytes, 0, $canonicalBytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }

    $item = Get-Item -LiteralPath $managedPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw "$Label is not an ordinary file."
    }
    $actualBytes = [System.IO.File]::ReadAllBytes($managedPath)
    if ($actualBytes.Length -ne $canonicalBytes.Length) {
        throw "$Label length is not canonical."
    }
    for ($index = 0; $index -lt $canonicalBytes.Length; $index++) {
        if ($actualBytes[$index] -ne $canonicalBytes[$index]) {
            throw "$Label bytes are not canonical."
        }
    }
}

function Read-StrictReleaseJsonText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $managedPath = Assert-OutputPath $Path
    if (!(Test-Path -LiteralPath $managedPath -PathType Leaf)) {
        return $null
    }
    $item = Get-Item -LiteralPath $managedPath -Force
    if ($item.Length -le 0 -or $item.Length -gt 65536) {
        throw "$Label size is outside the durable 64 KiB bound."
    }
    $bytes = [System.IO.File]::ReadAllBytes($managedPath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw "$Label must be UTF-8 without BOM."
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $text = $encoding.GetString($bytes)
    }
    catch {
        throw "$Label is not strict UTF-8."
    }
    try {
        $document = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "$Label is not valid JSON."
    }
    return [pscustomobject]@{
        Path = $managedPath
        Text = $text
        Sha256 = Get-ReleaseBytesSha256 -Bytes $bytes
        Document = $document
    }
}

function Read-StrictReleaseCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    $raw = Read-StrictReleaseJsonText -Path $Path -Label 'Release commit manifest'
    if ($null -eq $raw) {
        return $null
    }
    $canonical = ConvertTo-CanonicalReleaseCommit -Commit $raw.Document -Artifacts $Artifacts
    $canonicalText = ConvertTo-CanonicalReleaseJsonText -Value $canonical
    if (![string]::Equals($raw.Text, $canonicalText, [System.StringComparison]::Ordinal)) {
        throw 'The release commit manifest is not canonical or contains unsupported JSON data.'
    }
    return [pscustomobject]@{
        Path = $raw.Path
        Text = $raw.Text
        Sha256 = $raw.Sha256
        Document = $canonical
    }
}

function Read-StrictReleaseJournal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    $raw = Read-StrictReleaseJsonText -Path $Path -Label 'Release exchange journal'
    if ($null -eq $raw) {
        return $null
    }
    $canonical = ConvertTo-CanonicalReleaseJournal -Journal $raw.Document -Artifacts $Artifacts
    $canonicalText = ConvertTo-CanonicalReleaseJsonText -Value $canonical
    if (![string]::Equals($raw.Text, $canonicalText, [System.StringComparison]::Ordinal)) {
        throw 'The release exchange journal is not canonical or contains unsupported JSON data.'
    }
    return [pscustomobject]@{
        Path = $raw.Path
        Text = $raw.Text
        Sha256 = $raw.Sha256
        Document = $canonical
    }
}

function Invoke-ReleaseTransactionFaultCallback {
    param(
        [AllowNull()][scriptblock]$Callback,
        [Parameter(Mandatory = $true)][string]$Point,
        [Parameter(Mandatory = $true)][string]$TransactionId,
        [AllowNull()][object]$ArtifactId,
        [int]$ArtifactIndex = -1
    )

    if ($null -eq $Callback) {
        return
    }
    $null = Assert-ReleaseIdentifier -Value $TransactionId -Label 'Fault callback transaction id'
    if ($Point.Length -gt 128 -or
        $Point -cnotmatch '^(?:(?:pending-commit|journal)\.(?:temp-flushed|published)|commit\.published|promotion\.[0-4]\.[a-z-]+\.(?:backup|current)-published)$') {
        throw "A release transaction fault point is invalid: $Point"
    }
    $isPromotion = $Point.StartsWith('promotion.', [System.StringComparison]::Ordinal)
    if ($isPromotion) {
        if ($ArtifactId -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$ArtifactId) -or
            [string]$ArtifactId -cnotmatch '^[a-z-]+$' -or
            $ArtifactIndex -lt 0 -or
            $ArtifactIndex -gt 4) {
            throw 'A promotion fault callback lacks its fixed artifact identity.'
        }
    }
    elseif ($null -ne $ArtifactId -or $ArtifactIndex -ne -1) {
        throw 'A non-promotion fault callback unexpectedly contains artifact identity.'
    }

    $context = [pscustomobject][ordered]@{
        point = $Point
        transactionId = $TransactionId
        artifactId = if ($isPromotion) { [string]$ArtifactId } else { $null }
        artifactIndex = if ($isPromotion) { $ArtifactIndex } else { -1 }
    }
    $null = & $Callback $context
}

function Write-DurableManagedText {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$TransactionId,
        [switch]$ReplaceExisting,
        [AllowNull()][scriptblock]$FaultCallback,
        [AllowNull()][string]$FaultScope
    )

    $null = Assert-ReleaseIdentifier -Value $TransactionId -Label 'Durable write transaction id'
    if ($null -ne $FaultCallback -and
        $FaultScope -cnotin @('pending-commit', 'journal')) {
        throw 'A durable release state fault callback has an invalid scope.'
    }
    $managedDestination = Assert-OutputPath $Destination
    $temporary = Assert-OutputPath ($managedDestination + '.tmp-' + $TransactionId)
    if (Test-Path -LiteralPath $temporary) {
        throw "A durable release temporary file already exists: $temporary"
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($Text)
    if ($bytes.Length -le 0 -or $bytes.Length -gt 65536) {
        throw 'A durable release state file exceeded the 64 KiB bound.'
    }
    $stream = [System.IO.FileStream]::new(
        $temporary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        65536,
        [System.IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $written = [System.IO.File]::ReadAllBytes($temporary)
    if ($written.Length -ne $bytes.Length -or
        !(Get-ReleaseBytesSha256 -Bytes $written).Equals(
            (Get-ReleaseBytesSha256 -Bytes $bytes),
            [System.StringComparison]::Ordinal)) {
        Remove-ManagedFile $temporary
        throw 'A durable release state file failed its write verification.'
    }
    if ($null -ne $FaultCallback) {
        Invoke-ReleaseTransactionFaultCallback `
            -Callback $FaultCallback `
            -Point ($FaultScope + '.temp-flushed') `
            -TransactionId $TransactionId `
            -ArtifactId $null
    }
    try {
        Move-ManagedArtifact `
            -Source $temporary `
            -Destination $managedDestination `
            -ReplaceExisting:$ReplaceExisting
    }
    catch {
        try {
            Remove-ManagedFile $temporary
        }
        catch {
        }
        throw
    }
    if ($null -ne $FaultCallback) {
        Invoke-ReleaseTransactionFaultCallback `
            -Callback $FaultCallback `
            -Point ($FaultScope + '.published') `
            -TransactionId $TransactionId `
            -ArtifactId $null
    }
    return Get-ReleaseBytesSha256 -Bytes $bytes
}

function Enter-ReleaseExchangeLock {
    param([Parameter(Mandatory = $true)][string]$Path)

    $managedPath = Assert-OutputPath $Path
    $null = Assert-NoReparseTraversal $managedPath
    try {
        return [System.IO.FileStream]::new(
            $managedPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None,
            1,
            [System.IO.FileOptions]::WriteThrough)
    }
    catch {
        throw "Another release exchange owns the formal outputs lock: $managedPath"
    }
}

function Get-ReleasePendingStateFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $fullRoot = Assert-NoReparsePointsInTree -Path $Root -Label 'Formal release outputs'
    return @(Get-ChildItem -LiteralPath $fullRoot -Force | Where-Object {
        $_.Name -cmatch '^(?:\.CodexGuardian-release-(?:manifest\.pending\.[a-f0-9]{32}\.json(?:\.tmp-[a-f0-9]{32})?|transaction\.json\.tmp-[a-f0-9]{32})|(?:CodexGuardian-win-x64(?:\.zip)?|CodexGuardian-source(?:\.zip)?|SHA256SUMS\.txt)\.discard\.[a-f0-9]{32})$'
    })
}

function Get-ReleaseArtifactDiscardPath {
    param(
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][string]$TransactionId
    )

    $null = Assert-ReleaseIdentifier -Value $TransactionId -Label 'Discard transaction id'
    $parent = Split-Path $Artifact.Current -Parent
    $leaf = Split-Path $Artifact.Current -Leaf
    return Assert-OutputPath (Join-Path $parent ($leaf + '.discard.' + $TransactionId))
}

function Move-ReleaseArtifactToDiscard {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Discard
    )

    if (!(Test-Path -LiteralPath $Source)) {
        return
    }
    if (Test-Path -LiteralPath $Discard) {
        throw "A durable release discard path already exists: $Discard"
    }
    Move-ManagedArtifact -Source $Source -Destination $Discard
}

function Remove-ReleaseDiscardArtifacts {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$TransactionId
    )

    foreach ($artifact in $Artifacts) {
        $discard = Get-ReleaseArtifactDiscardPath `
            -Artifact $artifact `
            -TransactionId $TransactionId
        Remove-ManagedArtifact $discard
    }
}

function Assert-ReleaseExchangeWorkspaceSettled {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$OutputsPath
    )

    if (Test-Path -LiteralPath (Assert-OutputPath $JournalPath)) {
        throw 'The release exchange journal remains after recovery.'
    }
    foreach ($artifact in $Artifacts) {
        if ((Test-Path -LiteralPath $artifact.Next) -or
            (Test-Path -LiteralPath $artifact.Previous)) {
            throw "Release exchange workspace is not settled for $($artifact.Id)."
        }
    }
    if (@(Get-ReleasePendingStateFiles -Root $OutputsPath).Count -ne 0) {
        throw 'Durable release pending state remains after recovery.'
    }
}

function Assert-CurrentReleaseCoherent {
    param([Parameter(Mandatory = $true)][object[]]$Artifacts)

    $runtimeDirectory = @($Artifacts | Where-Object { $_.Id -ceq 'runtime-directory' })[0]
    $sourceDirectory = @($Artifacts | Where-Object { $_.Id -ceq 'source-directory' })[0]
    $runtimeArchive = @($Artifacts | Where-Object { $_.Id -ceq 'runtime-zip' })[0]
    $sourceArchive = @($Artifacts | Where-Object { $_.Id -ceq 'source-zip' })[0]
    $checksum = @($Artifacts | Where-Object { $_.Id -ceq 'checksum' })[0]
    $runtimeManifest = @(Get-TreeContentManifest `
        -Root $runtimeDirectory.Current `
        -Label 'Committed runtime directory')
    $sourceManifest = @(Get-TreeContentManifest `
        -Root $sourceDirectory.Current `
        -Label 'Committed source directory')
    Assert-NoDesktopModificationPayload -Root $runtimeDirectory.Current -Label 'Committed runtime package'
    Assert-NoDesktopModificationPayload -Root $sourceDirectory.Current -Label 'Committed source package'
    Assert-NoRuntimeTestPayload -Root $runtimeDirectory.Current -Label 'Committed runtime package'
    Assert-NoDesktopModificationArchiveEntries -Path $runtimeArchive.Current -Label 'Committed runtime ZIP'
    Assert-NoDesktopModificationArchiveEntries -Path $sourceArchive.Current -Label 'Committed source ZIP'
    Assert-NoRuntimeTestArchiveEntries -Path $runtimeArchive.Current -Label 'Committed runtime ZIP'
    Assert-ArchiveMatchesManifest `
        -Path $runtimeArchive.Current `
        -ExpectedManifest $runtimeManifest `
        -Label 'Committed runtime ZIP'
    Assert-ArchiveMatchesManifest `
        -Path $sourceArchive.Current `
        -ExpectedManifest $sourceManifest `
        -Label 'Committed source ZIP'
    $expectedChecksumLines = @(
        "$((Get-FileHash -LiteralPath $runtimeArchive.Current -Algorithm SHA256).Hash.ToLowerInvariant())  $($runtimeArchive.Leaf)"
        "$((Get-FileHash -LiteralPath $sourceArchive.Current -Algorithm SHA256).Hash.ToLowerInvariant())  $($sourceArchive.Leaf)"
    )
    $actualChecksumLines = @(Get-Content -LiteralPath $checksum.Current)
    if ($actualChecksumLines.Count -ne $expectedChecksumLines.Count -or
        @(Compare-Object -ReferenceObject $expectedChecksumLines -DifferenceObject $actualChecksumLines -SyncWindow 0).Count -ne 0) {
        throw 'The committed release checksum file does not match its ZIP files.'
    }
}

function Assert-CurrentReleaseMatchesCommit {
    param(
        [Parameter(Mandatory = $true)][object]$Commit,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    $commitEntries = @($Commit.Document.artifacts)
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $artifact = $Artifacts[$index]
        Assert-ManagedArtifactIdentity `
            -Path $artifact.Current `
            -Kind $artifact.Kind `
            -Expected $commitEntries[$index].identity `
            -Label "Committed $($artifact.Label)"
    }
    Assert-CurrentReleaseCoherent -Artifacts $Artifacts
}

function Get-CurrentReleaseBaseline {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$CommitPath
    )

    $commit = Read-StrictReleaseCommit -Path $CommitPath -Artifacts $Artifacts
    $present = @($Artifacts | Where-Object { Test-Path -LiteralPath $_.Current })
    if ($present.Count -eq 0) {
        if ($null -ne $commit) {
            throw 'A release commit manifest exists without its complete current artifact set.'
        }
        $entries = @($Artifacts | ForEach-Object {
            [pscustomobject][ordered]@{
                id = [string]$_.Id
                kind = [string]$_.Kind
                hadCurrent = $false
                old = $null
            }
        })
        return [pscustomobject]@{
            Commit = $null
            OldCommit = [pscustomobject][ordered]@{
                present = $false
                sha256 = $null
                generationId = $null
            }
            Artifacts = $entries
        }
    }
    if ($present.Count -ne $Artifacts.Count -or $null -eq $commit) {
        throw 'The current formal release is partial or lacks a verified commit manifest.'
    }
    Assert-CurrentReleaseMatchesCommit -Commit $commit -Artifacts $Artifacts
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in $Artifacts) {
        $entries.Add([pscustomobject][ordered]@{
            id = [string]$artifact.Id
            kind = [string]$artifact.Kind
            hadCurrent = $true
            old = Get-ManagedArtifactIdentity `
                -Path $artifact.Current `
                -Kind $artifact.Kind `
                -Label "Existing $($artifact.Label)"
        })
    }
    return [pscustomobject]@{
        Commit = $commit
        OldCommit = [pscustomobject][ordered]@{
            present = $true
            sha256 = [string]$commit.Sha256
            generationId = [string]$commit.Document.generationId
        }
        Artifacts = $entries.ToArray()
    }
}

function Get-ReleaseCandidateEntries {
    param([Parameter(Mandatory = $true)][object[]]$Artifacts)

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in $Artifacts) {
        $entries.Add([pscustomobject][ordered]@{
            id = [string]$artifact.Id
            kind = [string]$artifact.Kind
            new = Get-ManagedArtifactIdentity `
                -Path $artifact.Next `
                -Kind $artifact.Kind `
                -Label "Candidate $($artifact.Label)"
        })
    }
    return $entries.ToArray()
}

function Assert-ReleaseTransactionSnapshot {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][object[]]$JournalArtifacts
    )

    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $artifact = $Artifacts[$index]
        $entry = $JournalArtifacts[$index]
        if ([bool]$entry.hadCurrent) {
            Assert-ManagedArtifactIdentity `
                -Path $artifact.Current `
                -Kind $artifact.Kind `
                -Expected $entry.old `
                -Label "Current $($artifact.Label) before transaction"
        }
        elseif (Test-Path -LiteralPath $artifact.Current) {
            throw "A first-release current artifact appeared before transaction: $($artifact.Current)"
        }
        Assert-ManagedArtifactIdentity `
            -Path $artifact.Next `
            -Kind $artifact.Kind `
            -Expected $entry.new `
            -Label "Next $($artifact.Label) before transaction"
        if (Test-Path -LiteralPath $artifact.Previous) {
            throw "A previous artifact appeared before transaction: $($artifact.Previous)"
        }
    }
}

function New-ReleaseCommitDocument {
    param(
        [Parameter(Mandatory = $true)][string]$TransactionId,
        [Parameter(Mandatory = $true)][string]$CommittedUtc,
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][object[]]$CandidateEntries
    )

    $commitArtifacts = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $artifact = $Artifacts[$index]
        $commitArtifacts.Add([pscustomobject][ordered]@{
            id = [string]$artifact.Id
            leaf = [string]$artifact.Leaf
            kind = [string]$artifact.Kind
            identity = $CandidateEntries[$index].new
        })
    }
    return [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_COMMIT_V1'
        schemaVersion = 1
        generationId = $TransactionId
        transactionId = $TransactionId
        committedUtc = $CommittedUtc
        projectVersion = $ExpectedProjectVersion
        artifacts = $commitArtifacts.ToArray()
    }
}

function New-ReleaseJournalDocument {
    param(
        [Parameter(Mandatory = $true)][string]$TransactionId,
        [Parameter(Mandatory = $true)][string]$CreatedUtc,
        [Parameter(Mandatory = $true)][object]$Baseline,
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][object[]]$CandidateEntries,
        [Parameter(Mandatory = $true)][string]$NewCommitSha256
    )

    $journalArtifacts = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $oldEntry = $Baseline.Artifacts[$index]
        $newEntry = $CandidateEntries[$index]
        $journalArtifacts.Add([pscustomobject][ordered]@{
            id = [string]$Artifacts[$index].Id
            kind = [string]$Artifacts[$index].Kind
            hadCurrent = [bool]$oldEntry.hadCurrent
            old = $oldEntry.old
            new = $newEntry.new
        })
    }
    return [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_TRANSACTION_V1'
        schemaVersion = 1
        transactionId = $TransactionId
        createdUtc = $CreatedUtc
        protocol = 'rollback-before-commit'
        oldCommit = $Baseline.OldCommit
        newCommit = [pscustomobject][ordered]@{
            generationId = $TransactionId
            sha256 = $NewCommitSha256
        }
        artifacts = $journalArtifacts.ToArray()
    }
}

function Get-ReleaseCommitPendingPath {
    param(
        [Parameter(Mandatory = $true)][string]$OutputsPath,
        [Parameter(Mandatory = $true)][string]$TransactionId
    )

    $null = Assert-ReleaseIdentifier -Value $TransactionId -Label 'Pending commit transaction id'
    return Assert-OutputPath (Join-Path $OutputsPath (
        '.CodexGuardian-release-manifest.pending.' + $TransactionId + '.json'))
}

function Remove-ReleasePendingCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][object[]]$Artifacts
    )

    if (!(Test-Path -LiteralPath $Path)) {
        return
    }
    $pending = Read-StrictReleaseCommit -Path $Path -Artifacts $Artifacts
    if ($null -eq $pending -or
        ![string]::Equals($pending.Sha256, $ExpectedSha256, [System.StringComparison]::Ordinal)) {
        throw 'The pending release commit does not match the durable journal.'
    }
    Remove-ManagedFile $Path
}

function Assert-RollbackReleaseArtifactState {
    param(
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][object]$JournalEntry,
        [Parameter(Mandatory = $true)][string]$DiscardPath
    )

    $currentExists = Test-Path -LiteralPath $Artifact.Current
    $nextExists = Test-Path -LiteralPath $Artifact.Next
    $previousExists = Test-Path -LiteralPath $Artifact.Previous
    $discardExists = Test-Path -LiteralPath $DiscardPath
    if ($discardExists) {
        Assert-ManagedArtifactIdentity `
            -Path $DiscardPath `
            -Kind $Artifact.Kind `
            -Expected $JournalEntry.new `
            -Label "Rollback discard $($Artifact.Label)"
    }
    if ([bool]$JournalEntry.hadCurrent) {
        $validShape = if ($discardExists) {
            (!$currentExists -and !$nextExists -and $previousExists) -or
                ($currentExists -and !$nextExists -and !$previousExists)
        }
        else {
            ($currentExists -and $nextExists -and !$previousExists) -or
                (!$currentExists -and $nextExists -and $previousExists) -or
                ($currentExists -and !$nextExists -and $previousExists) -or
                (!$currentExists -and !$nextExists -and $previousExists) -or
                ($currentExists -and !$nextExists -and !$previousExists)
        }
        if (!$validShape) {
            throw "Uncommitted release artifact state is ambiguous: $($Artifact.Id)"
        }
        if ($currentExists) {
            $expectedCurrent = if ($previousExists) { $JournalEntry.new } else { $JournalEntry.old }
            Assert-ManagedArtifactIdentity `
                -Path $Artifact.Current `
                -Kind $Artifact.Kind `
                -Expected $expectedCurrent `
                -Label "Rollback current $($Artifact.Label)"
        }
        if ($nextExists) {
            Assert-ManagedArtifactIdentity `
                -Path $Artifact.Next `
                -Kind $Artifact.Kind `
                -Expected $JournalEntry.new `
                -Label "Rollback next $($Artifact.Label)"
        }
        if ($previousExists) {
            Assert-ManagedArtifactIdentity `
                -Path $Artifact.Previous `
                -Kind $Artifact.Kind `
                -Expected $JournalEntry.old `
                -Label "Rollback previous $($Artifact.Label)"
        }
        return
    }

    $validFirstReleaseShape = if ($discardExists) {
        !$currentExists -and !$nextExists -and !$previousExists
    }
    else {
        (!$currentExists -and $nextExists -and !$previousExists) -or
            ($currentExists -and !$nextExists -and !$previousExists) -or
            (!$currentExists -and !$nextExists -and !$previousExists)
    }
    if (!$validFirstReleaseShape) {
        throw "Uncommitted first-release artifact state is ambiguous: $($Artifact.Id)"
    }
    if ($currentExists) {
        Assert-ManagedArtifactIdentity `
            -Path $Artifact.Current `
            -Kind $Artifact.Kind `
            -Expected $JournalEntry.new `
            -Label "Rollback current $($Artifact.Label)"
    }
    if ($nextExists) {
        Assert-ManagedArtifactIdentity `
            -Path $Artifact.Next `
            -Kind $Artifact.Kind `
            -Expected $JournalEntry.new `
            -Label "Rollback next $($Artifact.Label)"
    }
}

function Restore-UncommittedReleaseTransaction {
    param(
        [Parameter(Mandatory = $true)][object]$Journal,
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$CommitPath,
        [Parameter(Mandatory = $true)][string]$OutputsPath
    )

    Assert-GuardianStopped
    $entries = @($Journal.Document.artifacts)
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $discard = Get-ReleaseArtifactDiscardPath `
            -Artifact $Artifacts[$index] `
            -TransactionId ([string]$Journal.Document.transactionId)
        Assert-RollbackReleaseArtifactState `
            -Artifact $Artifacts[$index] `
            -JournalEntry $entries[$index] `
            -DiscardPath $discard
    }
    for ($index = $Artifacts.Count - 1; $index -ge 0; $index--) {
        $artifact = $Artifacts[$index]
        $entry = $entries[$index]
        $discard = Get-ReleaseArtifactDiscardPath `
            -Artifact $artifact `
            -TransactionId ([string]$Journal.Document.transactionId)
        $currentExists = Test-Path -LiteralPath $artifact.Current
        $nextExists = Test-Path -LiteralPath $artifact.Next
        $previousExists = Test-Path -LiteralPath $artifact.Previous
        if ([bool]$entry.hadCurrent) {
            if ($previousExists) {
                if ($currentExists) {
                    Move-ReleaseArtifactToDiscard `
                        -Source $artifact.Current `
                        -Discard $discard
                }
                Move-ManagedArtifact -Source $artifact.Previous -Destination $artifact.Current
            }
            if ($nextExists) {
                Move-ReleaseArtifactToDiscard `
                    -Source $artifact.Next `
                    -Discard $discard
            }
            Assert-ManagedArtifactIdentity `
                -Path $artifact.Current `
                -Kind $artifact.Kind `
                -Expected $entry.old `
                -Label "Restored $($artifact.Label)"
        }
        else {
            if ($currentExists) {
                Move-ReleaseArtifactToDiscard `
                    -Source $artifact.Current `
                    -Discard $discard
            }
            if ($nextExists) {
                Move-ReleaseArtifactToDiscard `
                    -Source $artifact.Next `
                    -Discard $discard
            }
            if (Test-Path -LiteralPath $artifact.Previous) {
                throw "A first-release previous artifact survived rollback: $($artifact.Previous)"
            }
        }
    }
    if ([bool]$Journal.Document.oldCommit.present) {
        $restoredCommit = Read-StrictReleaseCommit -Path $CommitPath -Artifacts $Artifacts
        if ($null -eq $restoredCommit -or
            ![string]::Equals(
                [string]$restoredCommit.Sha256,
                [string]$Journal.Document.oldCommit.sha256,
                [System.StringComparison]::Ordinal) -or
            ![string]::Equals(
                [string]$restoredCommit.Document.generationId,
                [string]$Journal.Document.oldCommit.generationId,
                [System.StringComparison]::Ordinal)) {
            throw 'The restored stable commit does not match the journal old generation.'
        }
        Assert-CurrentReleaseMatchesCommit -Commit $restoredCommit -Artifacts $Artifacts
    }
    elseif (Test-Path -LiteralPath $CommitPath) {
        throw 'A first-release rollback unexpectedly retained a stable commit.'
    }
    $pendingPath = Get-ReleaseCommitPendingPath `
        -OutputsPath $OutputsPath `
        -TransactionId ([string]$Journal.Document.transactionId)
    Remove-ReleasePendingCommit `
        -Path $pendingPath `
        -ExpectedSha256 ([string]$Journal.Document.newCommit.sha256) `
        -Artifacts $Artifacts
    Remove-ManagedFile $JournalPath
    Remove-ReleaseDiscardArtifacts `
        -Artifacts $Artifacts `
        -TransactionId ([string]$Journal.Document.transactionId)
}

function Complete-CommittedReleaseTransaction {
    param(
        [Parameter(Mandatory = $true)][object]$Journal,
        [Parameter(Mandatory = $true)][object]$Commit,
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$OutputsPath
    )

    Assert-GuardianStopped
    $entries = @($Journal.Document.artifacts)
    for ($index = 0; $index -lt $Artifacts.Count; $index++) {
        $artifact = $Artifacts[$index]
        $entry = $entries[$index]
        $discard = Get-ReleaseArtifactDiscardPath `
            -Artifact $artifact `
            -TransactionId ([string]$Journal.Document.transactionId)
        Assert-ManagedArtifactIdentity `
            -Path $artifact.Current `
            -Kind $artifact.Kind `
            -Expected $entry.new `
            -Label "Committed $($artifact.Label)"
        if (Test-Path -LiteralPath $artifact.Next) {
            throw "A committed release unexpectedly retains a next artifact: $($artifact.Next)"
        }
        if (Test-Path -LiteralPath $discard) {
            if (![bool]$entry.hadCurrent -or (Test-Path -LiteralPath $artifact.Previous)) {
                throw "A committed release discard state is ambiguous: $($artifact.Id)"
            }
            Assert-ManagedArtifactIdentity `
                -Path $discard `
                -Kind $artifact.Kind `
                -Expected $entry.old `
                -Label "Committed discard $($artifact.Label)"
        }
        if (Test-Path -LiteralPath $artifact.Previous) {
            if (![bool]$entry.hadCurrent) {
                throw "A first release unexpectedly retains a previous artifact: $($artifact.Previous)"
            }
            Assert-ManagedArtifactIdentity `
                -Path $artifact.Previous `
                -Kind $artifact.Kind `
                -Expected $entry.old `
                -Label "Committed previous $($artifact.Label)"
        }
    }
    Assert-CurrentReleaseMatchesCommit -Commit $Commit -Artifacts $Artifacts
    foreach ($artifact in $Artifacts) {
        if (Test-Path -LiteralPath $artifact.Previous) {
            $discard = Get-ReleaseArtifactDiscardPath `
                -Artifact $artifact `
                -TransactionId ([string]$Journal.Document.transactionId)
            Move-ReleaseArtifactToDiscard `
                -Source $artifact.Previous `
                -Discard $discard
        }
    }
    $pendingPath = Get-ReleaseCommitPendingPath `
        -OutputsPath $OutputsPath `
        -TransactionId ([string]$Journal.Document.transactionId)
    Remove-ReleasePendingCommit `
        -Path $pendingPath `
        -ExpectedSha256 ([string]$Journal.Document.newCommit.sha256) `
        -Artifacts $Artifacts
    Remove-ManagedFile $JournalPath
    Remove-ReleaseDiscardArtifacts `
        -Artifacts $Artifacts `
        -TransactionId ([string]$Journal.Document.transactionId)
}

function Resolve-ReleaseExchangeTransaction {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$CommitPath,
        [Parameter(Mandatory = $true)][string]$OutputsPath
    )

    $null = Assert-NoReparsePointsInTree -Path $OutputsPath -Label 'Formal release outputs'
    $journal = Read-StrictReleaseJournal -Path $JournalPath -Artifacts $Artifacts
    $commit = Read-StrictReleaseCommit -Path $CommitPath -Artifacts $Artifacts
    if ($null -eq $journal) {
        $present = @($Artifacts | Where-Object { Test-Path -LiteralPath $_.Current })
        if ($null -eq $commit) {
            if ($present.Count -ne 0) {
                throw 'An unanchored current release requires manual recovery.'
            }
        }
        else {
            if ($present.Count -ne $Artifacts.Count) {
                throw 'The committed current release is partial.'
            }
            Assert-CurrentReleaseMatchesCommit -Commit $commit -Artifacts $Artifacts
        }
        $transient = @($Artifacts | Where-Object {
            (Test-Path -LiteralPath $_.Next) -or (Test-Path -LiteralPath $_.Previous)
        })
        $pendingFiles = @(Get-ReleasePendingStateFiles -Root $OutputsPath)
        if ($transient.Count -gt 0 -or $pendingFiles.Count -gt 0) {
            Assert-GuardianStopped
            foreach ($artifact in $Artifacts) {
                Remove-ManagedArtifact $artifact.Next
                Remove-ManagedArtifact $artifact.Previous
            }
            foreach ($pendingFile in $pendingFiles) {
                Remove-ManagedArtifact $pendingFile.FullName
            }
        }
        return
    }

    $newCommitHash = [string]$journal.Document.newCommit.sha256
    if ($null -ne $commit -and
        [string]::Equals($commit.Sha256, $newCommitHash, [System.StringComparison]::Ordinal) -and
        [string]::Equals(
            [string]$commit.Document.generationId,
            [string]$journal.Document.transactionId,
            [System.StringComparison]::Ordinal)) {
        Complete-CommittedReleaseTransaction `
            -Journal $journal `
            -Commit $commit `
            -Artifacts $Artifacts `
            -JournalPath $JournalPath `
            -OutputsPath $OutputsPath
        return
    }

    if ([bool]$journal.Document.oldCommit.present) {
        if ($null -eq $commit -or
            ![string]::Equals(
                [string]$commit.Sha256,
                [string]$journal.Document.oldCommit.sha256,
                [System.StringComparison]::Ordinal) -or
            ![string]::Equals(
                [string]$commit.Document.generationId,
                [string]$journal.Document.oldCommit.generationId,
                [System.StringComparison]::Ordinal)) {
            throw 'The stable release commit matches neither side of the durable transaction.'
        }
    }
    elseif ($null -ne $commit) {
        throw 'A first-release transaction found an unexpected stable commit.'
    }

    Restore-UncommittedReleaseTransaction `
        -Journal $journal `
        -Artifacts $Artifacts `
        -JournalPath $JournalPath `
        -CommitPath $CommitPath `
        -OutputsPath $OutputsPath
}

function Invoke-DurableReleaseExchangeTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$ReleaseArtifacts,
        [Parameter(Mandatory = $true)][object]$ReleaseBaseline,
        [Parameter(Mandatory = $true)][string]$ReleaseTransactionId,
        [Parameter(Mandatory = $true)][string]$ReleaseCommitPendingPath,
        [Parameter(Mandatory = $true)][string]$ReleaseCommitPath,
        [Parameter(Mandatory = $true)][string]$ReleaseJournalPath,
        [Parameter(Mandatory = $true)][string]$OutputsRoot,
        [Parameter(Mandatory = $true)][string]$RuntimeOutput,
        [Parameter(Mandatory = $true)][string]$SourceOutput,
        [Parameter(Mandatory = $true)][string]$RuntimeZip,
        [Parameter(Mandatory = $true)][string]$SourceZip,
        [Parameter(Mandatory = $true)][string]$ChecksumPath,
        [Parameter(Mandatory = $true)][object[]]$RuntimeStageManifest,
        [Parameter(Mandatory = $true)][object[]]$SourceStageManifest,
        [Parameter(Mandatory = $true)][int]$RuntimeEntryCount,
        [Parameter(Mandatory = $true)][int]$SourceEntryCount,
        [AllowNull()][scriptblock]$FaultCallback
    )

    foreach ($artifact in $releaseArtifacts) {
        Sync-ManagedArtifact `
            -Path $artifact.Next `
            -Kind $artifact.Kind `
            -Label "Sealed candidate $($artifact.Label)"
    }

    $candidateEntries = @(Get-ReleaseCandidateEntries -Artifacts $releaseArtifacts)
    $transactionTimestamp = [DateTimeOffset]::UtcNow.ToString(
        'O',
        [System.Globalization.CultureInfo]::InvariantCulture)
    $releaseCommit = New-ReleaseCommitDocument `
        -TransactionId $ReleaseTransactionId `
        -CommittedUtc $transactionTimestamp `
        -Artifacts $releaseArtifacts `
        -CandidateEntries $candidateEntries
    $canonicalCommit = ConvertTo-CanonicalReleaseCommit `
        -Commit $releaseCommit `
        -Artifacts $releaseArtifacts
    $commitText = ConvertTo-CanonicalReleaseJsonText -Value $canonicalCommit
    $newCommitSha256 = Write-DurableManagedText `
        -Destination $ReleaseCommitPendingPath `
        -Text $commitText `
        -TransactionId $ReleaseTransactionId `
        -FaultCallback $FaultCallback `
        -FaultScope 'pending-commit'
    $pendingCommit = Read-StrictReleaseCommit `
        -Path $ReleaseCommitPendingPath `
        -Artifacts $releaseArtifacts
    if ($null -eq $pendingCommit -or
        ![string]::Equals($pendingCommit.Sha256, $newCommitSha256, [System.StringComparison]::Ordinal)) {
        throw 'The durable pending release commit failed its identity gate.'
    }

    Assert-GuardianStopped

    if ([bool]$releaseBaseline.OldCommit.present) {
        $currentCommit = Read-StrictReleaseCommit `
            -Path $ReleaseCommitPath `
            -Artifacts $releaseArtifacts
        if ($null -eq $currentCommit -or
            ![string]::Equals(
                $currentCommit.Sha256,
                [string]$releaseBaseline.OldCommit.sha256,
                [System.StringComparison]::Ordinal)) {
            throw 'The old stable commit changed before the write-ahead journal.'
        }
    }
    elseif (Test-Path -LiteralPath $ReleaseCommitPath) {
        throw 'A stable commit appeared before the first-release journal.'
    }

    $releaseJournal = New-ReleaseJournalDocument `
        -TransactionId $ReleaseTransactionId `
        -CreatedUtc $transactionTimestamp `
        -Baseline $releaseBaseline `
        -Artifacts $releaseArtifacts `
        -CandidateEntries $candidateEntries `
        -NewCommitSha256 $newCommitSha256
    $canonicalJournal = ConvertTo-CanonicalReleaseJournal `
        -Journal $releaseJournal `
        -Artifacts $releaseArtifacts
    Assert-ReleaseTransactionSnapshot `
        -Artifacts $releaseArtifacts `
        -JournalArtifacts @($canonicalJournal.artifacts)
    $journalText = ConvertTo-CanonicalReleaseJsonText -Value $canonicalJournal
    $journalSha256 = Write-DurableManagedText `
        -Destination $ReleaseJournalPath `
        -Text $journalText `
        -TransactionId $ReleaseTransactionId `
        -FaultCallback $FaultCallback `
        -FaultScope 'journal'
    $durableJournal = Read-StrictReleaseJournal `
        -Path $ReleaseJournalPath `
        -Artifacts $releaseArtifacts
    if ($null -eq $durableJournal -or
        ![string]::Equals($durableJournal.Sha256, $journalSha256, [System.StringComparison]::Ordinal)) {
        throw 'The durable release journal failed its identity gate.'
    }

    $journalEntries = @($durableJournal.Document.artifacts)
    for ($index = 0; $index -lt $releaseArtifacts.Count; $index++) {
        Assert-GuardianStopped
        if (!(Get-FileHash -LiteralPath $ReleaseJournalPath -Algorithm SHA256).Hash.Equals(
                $journalSha256,
                [System.StringComparison]::Ordinal)) {
            throw 'The durable release journal changed during promotion.'
        }
        $artifact = $releaseArtifacts[$index]
        $journalEntry = $journalEntries[$index]
        if ([bool]$journalEntry.hadCurrent) {
            Assert-ManagedArtifactIdentity `
                -Path $artifact.Current `
                -Kind $artifact.Kind `
                -Expected $journalEntry.old `
                -Label "Pre-promotion current $($artifact.Label)"
            Move-ManagedArtifact -Source $artifact.Current -Destination $artifact.Previous
            Invoke-ReleaseTransactionFaultCallback `
                -Callback $FaultCallback `
                -Point ("promotion.{0}.{1}.backup-published" -f $index, $artifact.Id) `
                -TransactionId $ReleaseTransactionId `
                -ArtifactId $artifact.Id `
                -ArtifactIndex $index
        }
        elseif (Test-Path -LiteralPath $artifact.Current) {
            throw "A first-release current artifact appeared during promotion: $($artifact.Current)"
        }
        Assert-ManagedArtifactIdentity `
            -Path $artifact.Next `
            -Kind $artifact.Kind `
            -Expected $journalEntry.new `
            -Label "Pre-promotion next $($artifact.Label)"
        Move-ManagedArtifact -Source $artifact.Next -Destination $artifact.Current
        Invoke-ReleaseTransactionFaultCallback `
            -Callback $FaultCallback `
            -Point ("promotion.{0}.{1}.current-published" -f $index, $artifact.Id) `
            -TransactionId $ReleaseTransactionId `
            -ArtifactId $artifact.Id `
            -ArtifactIndex $index
    }

    foreach ($requiredFile in @(
        (Join-Path $RuntimeOutput 'CodexGuardian.exe'),
        (Join-Path $RuntimeOutput 'CodexGuardian.dll'),
        (Join-Path $RuntimeOutput 'CodexGuardian.Control.dll'),
        (Join-Path $RuntimeOutput 'CodexGuardian.Trust.dll'),
        (Join-Path $RuntimeOutput 'System.Security.Cryptography.Pkcs.dll'),
        (Join-Path $RuntimeOutput 'CodexGuardian.deps.json'),
        (Join-Path $RuntimeOutput 'CodexGuardian.runtimeconfig.json'),
        (Join-Path $RuntimeOutput 'CodexGuardian.runtimeconfig.dev.json'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Broker.exe'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Broker.dll'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Control.dll'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Trust.dll'),
        (Join-Path $RuntimeOutput 'Broker\System.Security.Cryptography.Pkcs.dll'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Broker.deps.json'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Broker.runtimeconfig.json'),
        (Join-Path $RuntimeOutput 'Broker\CodexGuardian.Broker.runtimeconfig.dev.json'),
        (Join-Path $RuntimeOutput 'README.md'),
        (Join-Path $SourceOutput 'CodexGuardian\App.xaml'),
        (Join-Path $SourceOutput 'CodexGuardian\App.xaml.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\MainWindow.xaml.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Program.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Services\SettingsService.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Services\DataDirectorySafety.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\ViewModels\MainViewModel.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Services\AppServerClient.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Services\RecoveryOperationJournal.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\GuardianBrokerManagedBootstrap.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\GuardianBrokerBootstrapLifetime.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\ICdpCommandTransport.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CdpPipeTransport.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\WindowsCrtPipeProcess.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexCdpRuntimeResources.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexCdpObservationProtocol.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\Services\CodexDeepObservationService.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexPackageBaselineVerifier.cs'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\cdp-runtime-profile.json'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\cdp-observation-profile.json'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\codex-guardian-cdp-hook.js'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\codex-guardian-cdp-runtime-hook.js'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\codex-guardian-cdp-observer-poc.mjs'),
        (Join-Path $SourceOutput 'CodexGuardian\HookPayload\run-cdp-observation-poc.ps1'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexGuardian.Control.csproj'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\packages.lock.json'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\GlobalUsings.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexCdpBrokerProtocol.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexCdpBrokerStateMachine.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexCdpRuntimeOwnership.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexPackageCompatibility.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexAsarCapabilityInspector.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexPackageGeneration.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\CodexAppxBlockMapVerifier.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\PublishedRuntimeDependencyClosureVerifier.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\GuardianManagedEntryProof.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\GuardianBrokerAdmissionProtocol.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerConsentLedgerContract.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerConsentLedgerStore.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerConsentGrantDraft.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerWebAuthnClientData.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerWebAuthnCoseKey.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerWebAuthnProof.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerWebAuthnReceiptVerifier.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerFreshPresenceSession.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerCapabilityLease.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerRuntimeOwner.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\WindowsCodexCdpRuntimeControlHost.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerControlSession.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\VerifiedGuardianManagedEntryConnection.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerSingleInstanceLease.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerGuardianAcceptLoop.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerProductionHost.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerProductionComposition.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\WindowsGuardianProductionAdmission.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\WindowsGuardianCleanLauncher.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\WindowsGuardianProcessSettlement.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerWebAuthnPlatform.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\BrokerOwnedWindow.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\CodexAsarCapabilityOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerConsentLedgerContractOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerConsentLedgerStoreOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerWebAuthnReceiptOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerControlSessionOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\CodexCdpRuntimeOwnershipOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\WindowsCrtPipeProcessLifecycleOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\WindowsCodexCdpRuntimeControlHostOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\PublishedRuntimeDependencyClosureOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Control\GuardianBrokerBootstrapProtocol.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\GuardianBrokerBootstrapOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\Program.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\GuardianBrokerAdmissionProtocolOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\WindowsGuardianCleanLauncherOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\GuardianManagedEntryProofOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\WindowsGuardianProductionAdmissionOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\GuardianBrokerManagedBootstrapOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\FollowUpOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\VerifiedLocalReleaseManifestOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerProductionHostOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\BrokerWebAuthnNativeProbeTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\CodexPackageBaselineVerifierOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\CodexCdpObservationSessionOfflineTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Tests\WindowsConnectedClientPeerTrustNativeTests.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Trust\CodexGuardian.Trust.csproj'),
        (Join-Path $SourceOutput 'CodexGuardian.Trust\BrokerPeerTrust.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Trust\AuthenticatedPipePeerConnection.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Trust\Windows\WindowsConnectedClientPeerTrustPlatform.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Trust\Windows\WindowsVerifiedLocalReleaseManifestFactory.cs'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\CodexGuardian.Broker.csproj'),
        (Join-Path $SourceOutput 'CodexGuardian.Broker\Program.cs'),
        (Join-Path $SourceOutput 'package-release.ps1'),
        (Join-Path $SourceOutput 'global.json'),
        (Join-Path $SourceOutput 'NuGet.config'),
        $RuntimeZip,
        $SourceZip,
        $ChecksumPath
    )) {
        if (!(Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Exchanged release is incomplete: $requiredFile"
        }
    }

    Assert-NoDesktopModificationPayload -Root $RuntimeOutput -Label 'Exchanged runtime package'
    Assert-NoDesktopModificationPayload -Root $SourceOutput -Label 'Exchanged source package'
    Assert-NoRuntimeTestPayload -Root $RuntimeOutput -Label 'Exchanged runtime package'
    Assert-NoDesktopModificationArchiveEntries -Path $RuntimeZip -Label 'Exchanged runtime ZIP'
    Assert-NoDesktopModificationArchiveEntries -Path $SourceZip -Label 'Exchanged source ZIP'
    Assert-NoRuntimeTestArchiveEntries -Path $RuntimeZip -Label 'Exchanged runtime ZIP'
    Assert-TreeMatchesManifest `
        -Root $RuntimeOutput `
        -ExpectedManifest $RuntimeStageManifest `
        -Label 'Exchanged runtime directory'
    Assert-TreeMatchesManifest `
        -Root $SourceOutput `
        -ExpectedManifest $SourceStageManifest `
        -Label 'Exchanged source directory'
    Assert-ArchiveMatchesManifest `
        -Path $RuntimeZip `
        -ExpectedManifest $RuntimeStageManifest `
        -Label 'Exchanged runtime ZIP'
    Assert-ArchiveMatchesManifest `
        -Path $SourceZip `
        -ExpectedManifest $SourceStageManifest `
        -Label 'Exchanged source ZIP'
    if ((Get-ArchiveEntryCount $RuntimeZip) -ne $runtimeEntryCount -or
        (Get-ArchiveEntryCount $SourceZip) -ne $sourceEntryCount) {
        throw 'Exchanged release archive entry counts changed.'
    }

    $formalChecksumLines = @(
        "$((Get-FileHash -LiteralPath $RuntimeZip -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $RuntimeZip -Leaf)"
        "$((Get-FileHash -LiteralPath $SourceZip -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $SourceZip -Leaf)"
    )
    $storedChecksumLines = @(Get-Content -LiteralPath $ChecksumPath)
    if ($storedChecksumLines.Count -ne $formalChecksumLines.Count -or
        @(Compare-Object -ReferenceObject $formalChecksumLines -DifferenceObject $storedChecksumLines -SyncWindow 0).Count -ne 0) {
        throw 'Exchanged release checksums do not match the formal ZIP files.'
    }

    Move-ManagedArtifact `
        -Source $ReleaseCommitPendingPath `
        -Destination $ReleaseCommitPath `
        -ReplaceExisting
    Invoke-ReleaseTransactionFaultCallback `
        -Callback $FaultCallback `
        -Point 'commit.published' `
        -TransactionId $ReleaseTransactionId `
        -ArtifactId $null
    Resolve-ReleaseExchangeTransaction `
        -Artifacts $releaseArtifacts `
        -JournalPath $ReleaseJournalPath `
        -CommitPath $ReleaseCommitPath `
        -OutputsPath $OutputsRoot
    Assert-ReleaseExchangeWorkspaceSettled `
        -Artifacts $releaseArtifacts `
        -JournalPath $ReleaseJournalPath `
        -OutputsPath $OutputsRoot
    $committedRelease = Read-StrictReleaseCommit `
        -Path $ReleaseCommitPath `
        -Artifacts $releaseArtifacts
    if ($null -eq $committedRelease -or
        ![string]::Equals(
            [string]$committedRelease.Sha256,
            [string]$newCommitSha256,
            [System.StringComparison]::Ordinal) -or
        ![string]::Equals(
            [string]$committedRelease.Document.generationId,
            [string]$ReleaseTransactionId,
            [System.StringComparison]::Ordinal)) {
        throw 'The stable release commit does not identify the completed transaction.'
    }
    Assert-CurrentReleaseMatchesCommit `
        -Commit $committedRelease `
        -Artifacts $releaseArtifacts

    return $true
}

function Get-InternalReleaseTransactionContext {
    param([Parameter(Mandatory = $true)][string]$RequestPath)

    $fullRequestPath = [System.IO.Path]::GetFullPath($RequestPath)
    if (![string]::Equals(
            (Split-Path $fullRequestPath -Leaf),
            'request.json',
            [System.StringComparison]::Ordinal)) {
        throw 'The internal release transaction request must be named request.json.'
    }
    $fixtureRoot = [System.IO.Path]::GetFullPath((Split-Path $fullRequestPath -Parent)).TrimEnd('\')
    $fixtureParent = [System.IO.Path]::GetFullPath((Split-Path $fixtureRoot -Parent)).TrimEnd('\')
    $expectedParent = [System.IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
    $fixtureLeaf = Split-Path $fixtureRoot -Leaf
    if (![string]::Equals(
            $fixtureParent,
            $expectedParent,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $fixtureLeaf -cnotmatch '^r13-release-transaction-fault-[a-f0-9]{32}$') {
        throw 'The internal release transaction fixture root is outside the fixed D-drive namespace.'
    }
    $null = Assert-DDrivePath $fixtureRoot
    Assert-NoPathOverlap `
        -Candidate $fixtureRoot `
        -ProtectedRoots @(
            $RepositoryRoot,
            $script:OutputsRoot,
            $ProtectedR13EvidenceRoot,
            $DotnetCliHome,
            $ScratchRoot,
            $TempRoot
        ) `
        -Label 'Internal release transaction fixture'
    $fixtureRoot = Assert-NoReparsePointsInTree `
        -Path $fixtureRoot `
        -Label 'Internal release transaction fixture'
    $expectedRequestPath = Join-Path $fixtureRoot 'request.json'
    if (![string]::Equals(
            $fullRequestPath,
            $expectedRequestPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The internal release transaction request path is not the fixture request leaf.'
    }
    if (!(Test-Path -LiteralPath $fullRequestPath -PathType Leaf)) {
        throw 'The internal release transaction request file is unavailable.'
    }
    $requestItem = Get-Item -LiteralPath $fullRequestPath -Force
    if (($requestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $requestItem.Length -le 0 -or
        $requestItem.Length -gt 16384) {
        throw 'The internal release transaction request file failed its bounded regular-file gate.'
    }

    $tempBase = 'D:\CodexTemp\CodexGuardian'
    $null = Assert-DDrivePath $tempBase
    $null = Assert-NoReparseTraversal $tempBase
    $fixtureTempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase $fixtureLeaf))
    Assert-NoPathOverlap `
        -Candidate $fixtureTempRoot `
        -ProtectedRoots @(
            $RepositoryRoot,
            $script:OutputsRoot,
            $ProtectedR13EvidenceRoot,
            $DotnetCliHome,
            $ScratchRoot,
            $TempRoot,
            $fixtureRoot
        ) `
        -Label 'Internal release transaction TEMP root'
    $null = Assert-NoReparseTraversal $fixtureTempRoot

    return [pscustomobject]@{
        RequestPath = $fullRequestPath
        FixtureRoot = $fixtureRoot
        TempRoot = $fixtureTempRoot
    }
}

function Get-InternalReleaseTransactionFaultPoints {
    param([Parameter(Mandatory = $true)][ValidateSet('first', 'upgrade')][string]$Generation)

    $points = [System.Collections.Generic.List[string]]::new()
    foreach ($point in @(
        'pending-commit.temp-flushed',
        'pending-commit.published',
        'journal.temp-flushed',
        'journal.published'
    )) {
        $points.Add($point)
    }
    $artifactIds = @(
        'runtime-directory',
        'source-directory',
        'runtime-zip',
        'source-zip',
        'checksum'
    )
    for ($index = 0; $index -lt $artifactIds.Count; $index++) {
        if ($Generation -ceq 'upgrade') {
            $points.Add(("promotion.{0}.{1}.backup-published" -f $index, $artifactIds[$index]))
        }
        $points.Add(("promotion.{0}.{1}.current-published" -f $index, $artifactIds[$index]))
    }
    $points.Add('commit.published')
    return $points.ToArray()
}

function Read-InternalReleaseTransactionRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$FixtureRoot
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -le 0 -or $bytes.Length -gt 16384 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
        throw 'The internal release transaction request encoding or size is invalid.'
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $text = $encoding.GetString($bytes)
        $document = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "The internal release transaction request is not strict UTF-8 JSON: $($_.Exception.Message)"
    }
    Assert-ExactReleaseProperties `
        -Value $document `
        -Expected @('marker', 'schemaVersion', 'operation', 'fixtureRoot', 'generation', 'faultPoint') `
        -Label 'Internal release transaction request'
    if ($document.marker -isnot [string] -or
        ![string]::Equals(
            [string]$document.marker,
            'CODEXGUARDIAN_RELEASE_FAULT_REQUEST_V1',
            [System.StringComparison]::Ordinal) -or
        $null -eq $document.schemaVersion -or
        $document.schemaVersion.GetType().FullName -cne 'System.Int32' -or
        [int]$document.schemaVersion -ne 1 -or
        $document.operation -isnot [string] -or
        [string]$document.operation -cnotin @('exchange', 'resolve', 'snapshot') -or
        $document.fixtureRoot -isnot [string] -or
        ![string]::Equals(
            [string]$document.fixtureRoot,
            $FixtureRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $document.generation -isnot [string] -or
        [string]$document.generation -cnotin @('first', 'upgrade') -or
        ($null -ne $document.faultPoint -and $document.faultPoint -isnot [string])) {
        throw 'The internal release transaction request fields are invalid.'
    }
    $faultPoint = if ($null -eq $document.faultPoint) { $null } else { [string]$document.faultPoint }
    if ($null -ne $faultPoint -and $faultPoint.Length -gt 128) {
        throw 'The internal release transaction fault point exceeds its bound.'
    }
    if ([string]$document.operation -ceq 'exchange') {
        if ($null -ne $faultPoint -and
            @(Get-InternalReleaseTransactionFaultPoints -Generation ([string]$document.generation)) -cnotcontains $faultPoint) {
            throw "The requested release transaction fault point is not allowed: $faultPoint"
        }
    }
    elseif ($null -ne $faultPoint) {
        throw 'Resolve and snapshot requests cannot contain a fault point.'
    }

    $canonical = [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_FAULT_REQUEST_V1'
        schemaVersion = 1
        operation = [string]$document.operation
        fixtureRoot = $FixtureRoot
        generation = [string]$document.generation
        faultPoint = $faultPoint
    }
    $canonicalText = ConvertTo-CanonicalReleaseJsonText -Value $canonical
    if (![string]::Equals($text, $canonicalText, [System.StringComparison]::Ordinal)) {
        throw 'The internal release transaction request is not canonical JSON.'
    }
    return $canonical
}

function Write-InternalReleaseTransactionJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [switch]$ReplaceExisting
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullFixtureRoot = [System.IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
    if (![string]::Equals(
            [System.IO.Path]::GetFullPath((Split-Path $fullPath -Parent)).TrimEnd('\'),
            $fullFixtureRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path $fullPath -Leaf) -cnotin @('fault-reached.json', 'result.json')) {
        throw 'An internal release transaction JSON write escaped its fixed fixture leaves.'
    }
    $null = Assert-NoReparseTraversal $fullPath
    if ((Test-Path -LiteralPath $fullPath) -and !$ReplaceExisting) {
        throw "An internal release transaction JSON file already exists: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath -PathType Container) {
        throw 'An internal release transaction JSON target is a directory.'
    }
    $text = ConvertTo-CanonicalReleaseJsonText -Value $Value
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($text)
    if ($bytes.Length -le 0 -or $bytes.Length -gt 65536) {
        throw 'An internal release transaction JSON file exceeded its bound.'
    }
    $temporary = $fullPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
    $null = Assert-NoReparseTraversal $temporary
    $stream = [System.IO.FileStream]::new(
        $temporary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $written = [System.IO.File]::ReadAllBytes($temporary)
    if ($written.Length -ne $bytes.Length -or
        !(Get-ReleaseBytesSha256 -Bytes $written).Equals(
            (Get-ReleaseBytesSha256 -Bytes $bytes),
            [System.StringComparison]::Ordinal)) {
        [System.IO.File]::Delete($temporary)
        throw 'An internal release transaction JSON file failed write verification.'
    }
    Initialize-ReleaseNativeMethods
    $moveFlags = [uint32]8
    if ($ReplaceExisting) {
        $moveFlags = $moveFlags -bor [uint32]1
    }
    if (![CodexGuardian.ReleaseNativeMethodsV2]::MoveFileEx($temporary, $fullPath, $moveFlags)) {
        $nativeError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [System.IO.File]::Delete($temporary)
        throw [System.ComponentModel.Win32Exception]::new(
            $nativeError,
            "Internal release transaction JSON rename failed: $fullPath")
    }
    if ((Test-Path -LiteralPath $temporary) -or !(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'An internal release transaction JSON rename did not settle.'
    }
}

function Read-InternalReleaseTransactionFaultMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$FixtureRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (![string]::Equals(
            [System.IO.Path]::GetFullPath((Split-Path $fullPath -Parent)).TrimEnd('\'),
            [System.IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase) -or
        ![string]::Equals(
            (Split-Path $fullPath -Leaf),
            'fault-reached.json',
            [System.StringComparison]::Ordinal)) {
        throw 'The internal release transaction fault marker path is invalid.'
    }
    $null = Assert-NoReparseTraversal $fullPath
    if (!(Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        return $null
    }
    $markerItem = Get-Item -LiteralPath $fullPath -Force
    if (($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The internal release transaction fault marker is a reparse point.'
    }
    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if ($bytes.Length -le 0 -or $bytes.Length -gt 4096 -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
        throw 'The internal release transaction fault marker is invalid.'
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $encoding.GetString($bytes)
    $document = $text | ConvertFrom-Json -ErrorAction Stop
    Assert-ExactReleaseProperties `
        -Value $document `
        -Expected @('marker', 'schemaVersion', 'point', 'transactionId', 'artifactId', 'artifactIndex') `
        -Label 'Internal release transaction fault marker'
    $null = Assert-ReleaseIdentifier -Value ([string]$document.transactionId) -Label 'Fault marker transaction id'
    $canonical = [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_FAULT_REACHED_V1'
        schemaVersion = 1
        point = [string]$document.point
        transactionId = [string]$document.transactionId
        artifactId = if ($null -eq $document.artifactId) { $null } else { [string]$document.artifactId }
        artifactIndex = [int]$document.artifactIndex
    }
    if (![string]::Equals(
            [string]$document.marker,
            [string]$canonical.marker,
            [System.StringComparison]::Ordinal) -or
        $document.schemaVersion.GetType().FullName -cne 'System.Int32' -or
        [int]$document.schemaVersion -ne 1 -or
        $document.artifactIndex.GetType().FullName -cne 'System.Int32' -or
        ![string]::Equals(
            $text,
            (ConvertTo-CanonicalReleaseJsonText -Value $canonical),
            [System.StringComparison]::Ordinal)) {
        throw 'The internal release transaction fault marker is not canonical.'
    }
    return $canonical
}

function New-InternalReleaseArtifactPlan {
    param([Parameter(Mandatory = $true)][string]$OutputsPath)

    $runtimeOutputPath = Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-win-x64')
    $sourceOutputPath = Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-source')
    return @(
        [pscustomobject]@{ Id = 'runtime-directory'; Label = 'runtime directory'; Kind = 'tree'; Leaf = 'CodexGuardian-win-x64'; Current = $runtimeOutputPath; Next = (Assert-OutputPath ($runtimeOutputPath + '.next')); Previous = (Assert-OutputPath ($runtimeOutputPath + '.previous')) },
        [pscustomobject]@{ Id = 'source-directory'; Label = 'source directory'; Kind = 'tree'; Leaf = 'CodexGuardian-source'; Current = $sourceOutputPath; Next = (Assert-OutputPath ($sourceOutputPath + '.next')); Previous = (Assert-OutputPath ($sourceOutputPath + '.previous')) },
        [pscustomobject]@{ Id = 'runtime-zip'; Label = 'runtime ZIP'; Kind = 'file'; Leaf = 'CodexGuardian-win-x64.zip'; Current = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-win-x64.zip')); Next = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-win-x64.next.zip')); Previous = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-win-x64.previous.zip')) },
        [pscustomobject]@{ Id = 'source-zip'; Label = 'source ZIP'; Kind = 'file'; Leaf = 'CodexGuardian-source.zip'; Current = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-source.zip')); Next = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-source.next.zip')); Previous = (Assert-OutputPath (Join-Path $OutputsPath 'CodexGuardian-source.previous.zip')) },
        [pscustomobject]@{ Id = 'checksum'; Label = 'checksum file'; Kind = 'file'; Leaf = 'SHA256SUMS.txt'; Current = (Assert-OutputPath (Join-Path $OutputsPath 'SHA256SUMS.txt')); Next = (Assert-OutputPath (Join-Path $OutputsPath 'SHA256SUMS.next.txt')); Previous = (Assert-OutputPath (Join-Path $OutputsPath 'SHA256SUMS.previous.txt')) }
    )
}

function Get-InternalReleaseArtifact {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$Id
    )

    $matches = @($Artifacts | Where-Object { [string]$_.Id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "The internal release artifact plan lacks exactly one $Id descriptor."
    }
    return $matches[0]
}

function Write-InternalReleaseFixtureText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $managedPath = Assert-OutputPath $Path
    if (Test-Path -LiteralPath $managedPath) {
        throw "An internal release fixture file already exists: $managedPath"
    }
    $parent = Split-Path $managedPath -Parent
    $null = Assert-NoReparseTraversal $parent
    if (!(Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $null = Assert-NoReparsePointsInTree -Path $parent -Label 'Internal release fixture parent'
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $encoding.GetBytes($Text + [Environment]::NewLine)
    if ($bytes.Length -gt 4096) {
        throw 'An internal release fixture file exceeded its bound.'
    }
    $stream = [System.IO.FileStream]::new(
        $managedPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function New-InternalReleaseFixtureGeneration {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][ValidateSet('Current', 'Next')][string]$Slot,
        [Parameter(Mandatory = $true)][ValidateSet('old', 'new')][string]$Generation
    )

    $runtimeDirectory = Get-InternalReleaseArtifact -Artifacts $Artifacts -Id 'runtime-directory'
    $sourceDirectory = Get-InternalReleaseArtifact -Artifacts $Artifacts -Id 'source-directory'
    $runtimeArchive = Get-InternalReleaseArtifact -Artifacts $Artifacts -Id 'runtime-zip'
    $sourceArchive = Get-InternalReleaseArtifact -Artifacts $Artifacts -Id 'source-zip'
    $checksumArtifact = Get-InternalReleaseArtifact -Artifacts $Artifacts -Id 'checksum'
    $runtimeDirectoryPath = [string]$runtimeDirectory.PSObject.Properties[$Slot].Value
    $sourceDirectoryPath = [string]$sourceDirectory.PSObject.Properties[$Slot].Value
    $runtimeArchivePath = [string]$runtimeArchive.PSObject.Properties[$Slot].Value
    $sourceArchivePath = [string]$sourceArchive.PSObject.Properties[$Slot].Value
    $checksumPath = [string]$checksumArtifact.PSObject.Properties[$Slot].Value

    New-ManagedOutputDirectory -Destination $runtimeDirectoryPath
    New-ManagedOutputDirectory -Destination $sourceDirectoryPath
    foreach ($relativePath in @(
        'CodexGuardian.exe',
        'CodexGuardian.dll',
        'CodexGuardian.Control.dll',
        'CodexGuardian.Trust.dll',
        'CodexGuardian.deps.json',
        'CodexGuardian.runtimeconfig.json',
        'System.Security.Cryptography.Pkcs.dll',
        'Broker\CodexGuardian.Broker.exe',
        'Broker\CodexGuardian.Broker.dll',
        'Broker\CodexGuardian.Control.dll',
        'Broker\CodexGuardian.Trust.dll',
        'Broker\CodexGuardian.Broker.deps.json',
        'Broker\CodexGuardian.Broker.runtimeconfig.json',
        'Broker\System.Security.Cryptography.Pkcs.dll',
        'README.md'
    )) {
        Write-InternalReleaseFixtureText `
            -Path (Join-Path $runtimeDirectoryPath $relativePath) `
            -Text ("CodexGuardian internal runtime fixture {0} {1}" -f $Generation, $relativePath)
    }
    Write-CanonicalRuntimeConfigDev `
        -Path (Join-Path $runtimeDirectoryPath 'CodexGuardian.runtimeconfig.dev.json') `
        -Label 'Internal Guardian runtimeconfig.dev.json'
    Write-CanonicalRuntimeConfigDev `
        -Path (Join-Path $runtimeDirectoryPath 'Broker\CodexGuardian.Broker.runtimeconfig.dev.json') `
        -Label 'Internal Broker runtimeconfig.dev.json'
    foreach ($relativePath in @(
        'CodexGuardian\App.xaml',
        'CodexGuardian\App.xaml.cs',
        'CodexGuardian\MainWindow.xaml.cs',
        'CodexGuardian\Program.cs',
        'CodexGuardian\Services\SettingsService.cs',
        'CodexGuardian\Services\DataDirectorySafety.cs',
        'CodexGuardian\ViewModels\MainViewModel.cs',
        'CodexGuardian\Services\AppServerClient.cs',
        'CodexGuardian\Services\RecoveryOperationJournal.cs',
        'CodexGuardian\GuardianBrokerManagedBootstrap.cs',
        'CodexGuardian\GuardianBrokerBootstrapLifetime.cs',
        'CodexGuardian.Control\ICdpCommandTransport.cs',
        'CodexGuardian.Control\CdpPipeTransport.cs',
        'CodexGuardian.Control\WindowsCrtPipeProcess.cs',
        'CodexGuardian.Control\CodexCdpRuntimeResources.cs',
        'CodexGuardian.Control\CodexCdpObservationProtocol.cs',
        'CodexGuardian\Services\CodexDeepObservationService.cs',
        'CodexGuardian.Control\CodexPackageBaselineVerifier.cs',
        'CodexGuardian\HookPayload\cdp-runtime-profile.json',
        'CodexGuardian\HookPayload\cdp-observation-profile.json',
        'CodexGuardian\HookPayload\codex-guardian-cdp-hook.js',
        'CodexGuardian\HookPayload\codex-guardian-cdp-runtime-hook.js',
        'CodexGuardian\HookPayload\codex-guardian-cdp-observer-poc.mjs',
        'CodexGuardian\HookPayload\run-cdp-observation-poc.ps1',
        'CodexGuardian.Control\CodexGuardian.Control.csproj',
        'CodexGuardian.Control\packages.lock.json',
        'CodexGuardian.Control\GlobalUsings.cs',
        'CodexGuardian.Control\CodexCdpBrokerProtocol.cs',
        'CodexGuardian.Control\CodexCdpBrokerStateMachine.cs',
        'CodexGuardian.Control\CodexCdpRuntimeOwnership.cs',
        'CodexGuardian.Control\CodexPackageCompatibility.cs',
        'CodexGuardian.Control\CodexAsarCapabilityInspector.cs',
        'CodexGuardian.Control\CodexPackageGeneration.cs',
        'CodexGuardian.Control\CodexAppxBlockMapVerifier.cs',
        'CodexGuardian.Control\PublishedRuntimeDependencyClosureVerifier.cs',
        'CodexGuardian.Control\GuardianManagedEntryProof.cs',
        'CodexGuardian.Control\GuardianBrokerAdmissionProtocol.cs',
        'CodexGuardian.Broker\BrokerConsentLedgerContract.cs',
        'CodexGuardian.Broker\BrokerConsentLedgerStore.cs',
        'CodexGuardian.Broker\BrokerConsentGrantDraft.cs',
        'CodexGuardian.Broker\BrokerWebAuthnClientData.cs',
        'CodexGuardian.Broker\BrokerWebAuthnCoseKey.cs',
        'CodexGuardian.Broker\BrokerWebAuthnProof.cs',
        'CodexGuardian.Broker\BrokerWebAuthnReceiptVerifier.cs',
        'CodexGuardian.Broker\BrokerFreshPresenceSession.cs',
        'CodexGuardian.Broker\BrokerCapabilityLease.cs',
        'CodexGuardian.Broker\BrokerRuntimeOwner.cs',
        'CodexGuardian.Broker\WindowsCodexCdpRuntimeControlHost.cs',
        'CodexGuardian.Broker\BrokerControlSession.cs',
        'CodexGuardian.Broker\VerifiedGuardianManagedEntryConnection.cs',
        'CodexGuardian.Broker\BrokerSingleInstanceLease.cs',
        'CodexGuardian.Broker\BrokerGuardianAcceptLoop.cs',
        'CodexGuardian.Broker\BrokerProductionHost.cs',
        'CodexGuardian.Broker\BrokerProductionComposition.cs',
        'CodexGuardian.Broker\WindowsGuardianProductionAdmission.cs',
        'CodexGuardian.Broker\WindowsGuardianCleanLauncher.cs',
        'CodexGuardian.Broker\WindowsGuardianProcessSettlement.cs',
        'CodexGuardian.Broker\BrokerWebAuthnPlatform.cs',
        'CodexGuardian.Broker\BrokerOwnedWindow.cs',
        'CodexGuardian.Tests\CodexAsarCapabilityOfflineTests.cs',
        'CodexGuardian.Tests\BrokerConsentLedgerContractOfflineTests.cs',
        'CodexGuardian.Tests\BrokerConsentLedgerStoreOfflineTests.cs',
        'CodexGuardian.Tests\BrokerWebAuthnReceiptOfflineTests.cs',
        'CodexGuardian.Tests\BrokerControlSessionOfflineTests.cs',
        'CodexGuardian.Tests\CodexCdpRuntimeOwnershipOfflineTests.cs',
        'CodexGuardian.Tests\WindowsCrtPipeProcessLifecycleOfflineTests.cs',
        'CodexGuardian.Tests\WindowsCodexCdpRuntimeControlHostOfflineTests.cs',
        'CodexGuardian.Tests\PublishedRuntimeDependencyClosureOfflineTests.cs',
        'CodexGuardian.Control\GuardianBrokerBootstrapProtocol.cs',
        'CodexGuardian.Tests\GuardianBrokerBootstrapOfflineTests.cs',
        'CodexGuardian.Tests\Program.cs',
        'CodexGuardian.Tests\GuardianBrokerAdmissionProtocolOfflineTests.cs',
        'CodexGuardian.Tests\WindowsGuardianCleanLauncherOfflineTests.cs',
        'CodexGuardian.Tests\GuardianManagedEntryProofOfflineTests.cs',
        'CodexGuardian.Tests\WindowsGuardianProductionAdmissionOfflineTests.cs',
        'CodexGuardian.Tests\GuardianBrokerManagedBootstrapOfflineTests.cs',
        'CodexGuardian.Tests\FollowUpOfflineTests.cs',
        'CodexGuardian.Tests\VerifiedLocalReleaseManifestOfflineTests.cs',
        'CodexGuardian.Tests\BrokerProductionHostOfflineTests.cs',
        'CodexGuardian.Tests\BrokerWebAuthnNativeProbeTests.cs',
        'CodexGuardian.Tests\CodexPackageBaselineVerifierOfflineTests.cs',
        'CodexGuardian.Tests\CodexCdpObservationSessionOfflineTests.cs',
        'CodexGuardian.Tests\WindowsConnectedClientPeerTrustNativeTests.cs',
        'CodexGuardian.Trust\CodexGuardian.Trust.csproj',
        'CodexGuardian.Trust\BrokerPeerTrust.cs',
        'CodexGuardian.Trust\AuthenticatedPipePeerConnection.cs',
        'CodexGuardian.Trust\Windows\WindowsConnectedClientPeerTrustPlatform.cs',
        'CodexGuardian.Trust\Windows\WindowsVerifiedLocalReleaseManifestFactory.cs',
        'CodexGuardian.Broker\CodexGuardian.Broker.csproj',
        'CodexGuardian.Broker\Program.cs',
        'package-release.ps1',
        'global.json',
        'NuGet.config'
    )) {
        Write-InternalReleaseFixtureText `
            -Path (Join-Path $sourceDirectoryPath $relativePath) `
            -Text ("CodexGuardian internal source fixture {0} {1}" -f $Generation, $relativePath)
    }

    $runtimeManifest = @(Get-TreeContentManifest `
        -Root $runtimeDirectoryPath `
        -Label "Internal $Generation runtime fixture")
    $sourceManifest = @(Get-TreeContentManifest `
        -Root $sourceDirectoryPath `
        -Label "Internal $Generation source fixture")
    Compress-ManagedOutputArchive `
        -Source $runtimeDirectoryPath `
        -Destination $runtimeArchivePath `
        -ExpectedManifest $runtimeManifest `
        -Label "Internal $Generation runtime ZIP"
    Compress-ManagedOutputArchive `
        -Source $sourceDirectoryPath `
        -Destination $sourceArchivePath `
        -ExpectedManifest $sourceManifest `
        -Label "Internal $Generation source ZIP"
    $checksumLines = @(
        "$((Get-FileHash -LiteralPath $runtimeArchivePath -Algorithm SHA256).Hash.ToLowerInvariant())  $($runtimeArchive.Leaf)"
        "$((Get-FileHash -LiteralPath $sourceArchivePath -Algorithm SHA256).Hash.ToLowerInvariant())  $($sourceArchive.Leaf)"
    )
    Write-ManagedOutputLines -Destination $checksumPath -Lines $checksumLines
    foreach ($artifact in $Artifacts) {
        Sync-ManagedArtifact `
            -Path ([string]$artifact.PSObject.Properties[$Slot].Value) `
            -Kind ([string]$artifact.Kind) `
            -Label "Internal $Generation $($artifact.Label)"
    }
    return [pscustomobject]@{
        RuntimeManifest = $runtimeManifest
        SourceManifest = $sourceManifest
        RuntimeEntryCount = $runtimeManifest.Count
        SourceEntryCount = $sourceManifest.Count
    }
}

function New-InternalReleaseFixtureCommit {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$CommitPath,
        [Parameter(Mandatory = $true)][string]$TransactionId
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in $Artifacts) {
        $entries.Add([pscustomobject][ordered]@{
            id = [string]$artifact.Id
            kind = [string]$artifact.Kind
            new = Get-ManagedArtifactIdentity `
                -Path ([string]$artifact.Current) `
                -Kind ([string]$artifact.Kind) `
                -Label "Internal old $($artifact.Label)"
        })
    }
    $timestamp = [DateTimeOffset]::UtcNow.ToString(
        'O',
        [System.Globalization.CultureInfo]::InvariantCulture)
    $commit = New-ReleaseCommitDocument `
        -TransactionId $TransactionId `
        -CommittedUtc $timestamp `
        -Artifacts $Artifacts `
        -CandidateEntries $entries.ToArray()
    $canonical = ConvertTo-CanonicalReleaseCommit -Commit $commit -Artifacts $Artifacts
    $text = ConvertTo-CanonicalReleaseJsonText -Value $canonical
    $sha256 = Write-DurableManagedText `
        -Destination $CommitPath `
        -Text $text `
        -TransactionId $TransactionId
    $verified = Read-StrictReleaseCommit -Path $CommitPath -Artifacts $Artifacts
    if ($null -eq $verified -or
        ![string]::Equals($verified.Sha256, $sha256, [System.StringComparison]::Ordinal)) {
        throw 'The internal old release commit failed verification.'
    }
    Assert-CurrentReleaseMatchesCommit -Commit $verified -Artifacts $Artifacts
}

function Get-InternalReleaseTransactionSnapshot {
    param(
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$CommitPath,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)][string]$OutputsPath,
        [AllowNull()][string]$NewTransactionId
    )

    if (![string]::IsNullOrWhiteSpace($NewTransactionId)) {
        $null = Assert-ReleaseIdentifier -Value $NewTransactionId -Label 'Snapshot new transaction id'
    }
    $commit = Read-StrictReleaseCommit -Path $CommitPath -Artifacts $Artifacts
    $current = @($Artifacts | Where-Object { Test-Path -LiteralPath $_.Current })
    $result = $null
    if ($current.Count -eq 0 -and $null -eq $commit) {
        $result = 'empty'
    }
    elseif ($current.Count -eq $Artifacts.Count -and $null -ne $commit) {
        Assert-CurrentReleaseMatchesCommit -Commit $commit -Artifacts $Artifacts
        $result = if (![string]::IsNullOrWhiteSpace($NewTransactionId) -and
            [string]::Equals(
                [string]$commit.Document.generationId,
                $NewTransactionId,
                [System.StringComparison]::Ordinal)) {
            'new'
        }
        else {
            'old'
        }
    }
    else {
        throw 'The internal release transaction snapshot found a partial current release.'
    }

    $artifactSnapshots = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in $Artifacts) {
        $hasCurrent = Test-Path -LiteralPath $artifact.Current
        $artifactSnapshots.Add([pscustomobject][ordered]@{
            id = [string]$artifact.Id
            current = [bool]$hasCurrent
            next = [bool](Test-Path -LiteralPath $artifact.Next)
            previous = [bool](Test-Path -LiteralPath $artifact.Previous)
            identity = if ($hasCurrent) {
                Get-ManagedArtifactIdentity `
                    -Path ([string]$artifact.Current) `
                    -Kind ([string]$artifact.Kind) `
                    -Label "Internal snapshot $($artifact.Label)"
            }
            else {
                $null
            }
        })
    }
    $pending = @(Get-ReleasePendingStateFiles -Root $OutputsPath)
    $transientCount = $pending.Count + @($Artifacts | Where-Object {
        (Test-Path -LiteralPath $_.Next) -or (Test-Path -LiteralPath $_.Previous)
    }).Count
    return [pscustomobject][ordered]@{
        marker = 'CODEXGUARDIAN_RELEASE_FAULT_RESULT_V1'
        schemaVersion = 1
        result = $result
        generationId = if ($null -eq $commit) { $null } else { [string]$commit.Document.generationId }
        commitSha256 = if ($null -eq $commit) { $null } else { [string]$commit.Sha256 }
        artifacts = $artifactSnapshots.ToArray()
        journalPresent = [bool](Test-Path -LiteralPath $JournalPath)
        pendingCount = [int]$pending.Count
        transientCount = [int]$transientCount
    }
}

function Invoke-InternalReleaseTransactionHarness {
    param([Parameter(Mandatory = $true)][string]$RequestPath)

    if ($ValidateOnly -or $ScratchRootWasProvided) {
        throw 'The internal release transaction harness cannot be combined with package modes.'
    }
    $context = Get-InternalReleaseTransactionContext -RequestPath $RequestPath
    $request = Read-InternalReleaseTransactionRequest `
        -Path $context.RequestPath `
        -FixtureRoot $context.FixtureRoot
    $outputsPath = [System.IO.Path]::GetFullPath((Join-Path $context.FixtureRoot 'outputs'))
    $resultPath = Join-Path $context.FixtureRoot 'result.json'
    $faultMarkerPath = Join-Path $context.FixtureRoot 'fault-reached.json'
    $operation = [string]$request.operation
    if ($operation -ceq 'exchange') {
        if (Test-Path -LiteralPath $outputsPath) {
            throw 'A new internal release exchange requires an absent outputs fixture.'
        }
        New-Item -ItemType Directory -Path $outputsPath -Force | Out-Null
    }
    elseif (!(Test-Path -LiteralPath $outputsPath -PathType Container)) {
        throw 'The internal release resolve or snapshot requires an existing outputs fixture.'
    }
    $null = Assert-NoReparsePointsInTree -Path $outputsPath -Label 'Internal release outputs fixture'
    if (!(Test-Path -LiteralPath $context.TempRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $context.TempRoot -Force | Out-Null
    }
    $null = Assert-NoReparsePointsInTree -Path $context.TempRoot -Label 'Internal release TEMP fixture'
    $runTempRoot = Join-Path $context.TempRoot (
        'run-' + $PID + '-' + [Guid]::NewGuid().ToString('N'))
    $null = Assert-NoReparseTraversal $runTempRoot
    New-Item -ItemType Directory -Path $runTempRoot -Force | Out-Null
    $null = Assert-NoReparsePointsInTree -Path $runTempRoot -Label 'Internal release child TEMP fixture'
    $env:TEMP = $runTempRoot
    $env:TMP = $runTempRoot
    $script:OutputsRoot = $outputsPath

    $artifacts = @(New-InternalReleaseArtifactPlan -OutputsPath $outputsPath)
    $commitPath = Assert-OutputPath (Join-Path $outputsPath 'CodexGuardian-release-manifest.json')
    $journalPath = Assert-OutputPath (Join-Path $outputsPath '.CodexGuardian-release-transaction.json')
    $lockPath = Assert-OutputPath (Join-Path $outputsPath '.CodexGuardian-release-exchange.lock')
    $newTransactionId = $null
    $snapshot = $null

    if ($operation -ceq 'exchange') {
        if ([string]$request.generation -ceq 'upgrade') {
            $null = New-InternalReleaseFixtureGeneration `
                -Artifacts $artifacts `
                -Slot Current `
                -Generation old
            $oldTransactionId = [Guid]::NewGuid().ToString('N')
            New-InternalReleaseFixtureCommit `
                -Artifacts $artifacts `
                -CommitPath $commitPath `
                -TransactionId $oldTransactionId
        }
        $candidate = New-InternalReleaseFixtureGeneration `
            -Artifacts $artifacts `
            -Slot Next `
            -Generation new
        $baseline = Get-CurrentReleaseBaseline -Artifacts $artifacts -CommitPath $commitPath
        $newTransactionId = [Guid]::NewGuid().ToString('N')
        $pendingCommitPath = Get-ReleaseCommitPendingPath `
            -OutputsPath $outputsPath `
            -TransactionId $newTransactionId
        $faultCallback = if ($null -eq $request.faultPoint) {
            $null
        }
        else {
            $requestedFaultPoint = [string]$request.faultPoint
            $faultJsonWriterCommand = Get-Command `
                -Name Write-InternalReleaseTransactionJson `
                -CommandType Function `
                -ErrorAction Stop
            {
                param($faultContext)

                if (![string]::Equals(
                        [string]$faultContext.point,
                        $requestedFaultPoint,
                        [System.StringComparison]::Ordinal)) {
                    return
                }
                $faultDocument = [pscustomobject][ordered]@{
                    marker = 'CODEXGUARDIAN_RELEASE_FAULT_REACHED_V1'
                    schemaVersion = 1
                    point = [string]$faultContext.point
                    transactionId = [string]$faultContext.transactionId
                    artifactId = if ($null -eq $faultContext.artifactId) { $null } else { [string]$faultContext.artifactId }
                    artifactIndex = [int]$faultContext.artifactIndex
                }
                & $faultJsonWriterCommand `
                    -Path $faultMarkerPath `
                    -Value $faultDocument `
                    -FixtureRoot $context.FixtureRoot
                [Console]::Out.WriteLine('TRANSACTION_FAULT_REACHED point=' + [string]$faultContext.point)
                [Console]::Out.Flush()
                Stop-Process -Id $PID -Force
                throw 'The internal release transaction fault callback failed to terminate its process.'
            }.GetNewClosure()
        }

        $guardianLease = Enter-GuardianReleaseLease
        $exchangeLock = $null
        try {
            Assert-GuardianStopped
            $exchangeLock = Enter-ReleaseExchangeLock -Path $lockPath
            $succeeded = Invoke-DurableReleaseExchangeTransaction `
                -ReleaseArtifacts $artifacts `
                -ReleaseBaseline $baseline `
                -ReleaseTransactionId $newTransactionId `
                -ReleaseCommitPendingPath $pendingCommitPath `
                -ReleaseCommitPath $commitPath `
                -ReleaseJournalPath $journalPath `
                -OutputsRoot $outputsPath `
                -RuntimeOutput ([string](Get-InternalReleaseArtifact -Artifacts $artifacts -Id 'runtime-directory').Current) `
                -SourceOutput ([string](Get-InternalReleaseArtifact -Artifacts $artifacts -Id 'source-directory').Current) `
                -RuntimeZip ([string](Get-InternalReleaseArtifact -Artifacts $artifacts -Id 'runtime-zip').Current) `
                -SourceZip ([string](Get-InternalReleaseArtifact -Artifacts $artifacts -Id 'source-zip').Current) `
                -ChecksumPath ([string](Get-InternalReleaseArtifact -Artifacts $artifacts -Id 'checksum').Current) `
                -RuntimeStageManifest @($candidate.RuntimeManifest) `
                -SourceStageManifest @($candidate.SourceManifest) `
                -RuntimeEntryCount ([int]$candidate.RuntimeEntryCount) `
                -SourceEntryCount ([int]$candidate.SourceEntryCount) `
                -FaultCallback $faultCallback
            if (!$succeeded) {
                throw 'The internal release transaction returned false.'
            }
            if ($null -ne $request.faultPoint) {
                throw 'The requested internal release transaction fault point was not reached.'
            }
            $snapshot = Get-InternalReleaseTransactionSnapshot `
                -Artifacts $artifacts `
                -CommitPath $commitPath `
                -JournalPath $journalPath `
                -OutputsPath $outputsPath `
                -NewTransactionId $newTransactionId
        }
        finally {
            if ($null -ne $exchangeLock) {
                $exchangeLock.Dispose()
            }
            Exit-GuardianReleaseLease -Mutex $guardianLease
        }
    }
    else {
        $faultMarker = Read-InternalReleaseTransactionFaultMarker `
            -Path $faultMarkerPath `
            -FixtureRoot $context.FixtureRoot
        if ($null -ne $faultMarker) {
            $newTransactionId = [string]$faultMarker.transactionId
        }
        $guardianLease = Enter-GuardianReleaseLease
        $exchangeLock = $null
        try {
            Assert-GuardianStopped
            $exchangeLock = Enter-ReleaseExchangeLock -Path $lockPath
            if ($operation -ceq 'resolve') {
                Resolve-ReleaseExchangeTransaction `
                    -Artifacts $artifacts `
                    -JournalPath $journalPath `
                    -CommitPath $commitPath `
                    -OutputsPath $outputsPath
                Assert-ReleaseExchangeWorkspaceSettled `
                    -Artifacts $artifacts `
                    -JournalPath $journalPath `
                    -OutputsPath $outputsPath
            }
            $snapshot = Get-InternalReleaseTransactionSnapshot `
                -Artifacts $artifacts `
                -CommitPath $commitPath `
                -JournalPath $journalPath `
                -OutputsPath $outputsPath `
                -NewTransactionId $newTransactionId
        }
        finally {
            if ($null -ne $exchangeLock) {
                $exchangeLock.Dispose()
            }
            Exit-GuardianReleaseLease -Mutex $guardianLease
        }
    }

    Write-InternalReleaseTransactionJson `
        -Path $resultPath `
        -Value $snapshot `
        -FixtureRoot $context.FixtureRoot `
        -ReplaceExisting
    [Console]::Out.WriteLine(
        'INTERNAL_RELEASE_TRANSACTION_COMPLETE operation=' + $operation + ' result=' + [string]$snapshot.result)
    [Console]::Out.Flush()
}

if (![string]::IsNullOrWhiteSpace($InternalReleaseTransactionRequestPath)) {
    Invoke-InternalReleaseTransactionHarness `
        -RequestPath $InternalReleaseTransactionRequestPath
    return
}

throw (
    'broker-production-bootstrap-unavailable: package validation and formal exchange remain disabled ' +
    'until the production Broker bootstrap, clean launcher, closed runtime namespace, and manifest-bound ' +
    'semantic receipts are implemented and accepted.')

Assert-GuardianStopped
Assert-NoSourceBuildResidue
Assert-DDriveCapacity
$null = Assert-NoReparseTraversal $RepositoryRoot
foreach ($sourceProjectRoot in $SourceProjectRoots) {
    $null = Assert-NoReparsePointsInTree -Path $sourceProjectRoot -Label 'Authoritative source project'
}
Write-Host "Release source: $RepositoryRoot"
Write-Host "Release outputs: $OutputsRoot"
Write-Host "Release scratch workspace: $ScratchWorkspace"
Write-Host "Release temporary workspace: $TempWorkspace"
Write-Host "Release test data: $TestDataRoot"
Write-Host "Release Broker ledger test data: $BrokerConsentLedgerTestData"
Write-Host "DOTNET_CLI_HOME: $DotnetCliHome"
Write-Host "NUGET_PACKAGES: $NugetPackages"
$releaseArtifacts = $null
$releaseExchangeLock = $null
$guardianReleaseLease = $null
$brokerConsentLedgerTestDataOwned = $false
try {
    $null = Initialize-DDriveDirectory -Path $DataRoot -Label 'The CodexGuardian data root'
    $null = Initialize-DDriveDirectory -Path $DotnetCliHome -Label 'The .NET CLI home'
    Initialize-ScratchWorkspace
    Initialize-TempWorkspace
    $null = Initialize-DDriveDirectory -Path $NugetPackages -Label 'The NuGet package root'
    $null = Initialize-DDriveDirectory -Path $NugetHttpCache -Label 'The NuGet HTTP cache root'
    $null = Initialize-DDriveDirectory -Path $NugetPluginsCache -Label 'The NuGet plugin cache root'
    $null = Assert-TempPath $BrokerConsentLedgerTestData
    Assert-NoPathOverlap `
        -Candidate $BrokerConsentLedgerTestData `
        -ProtectedRoots @(
            $RepositoryRoot,
            $OutputsRoot,
            $ScratchRoot,
            $TempWorkspace,
            $DotnetCliHome,
            $ProtectedR13EvidenceRoot
        ) `
        -Label 'The Broker consent-ledger test-data workspace'
    if ($BrokerConsentLedgerTestData.Length -gt 72) {
        throw "The Broker consent-ledger test-data workspace is too long: $BrokerConsentLedgerTestData"
    }
    if (Test-Path -LiteralPath $BrokerConsentLedgerTestData) {
        throw "The unique Broker consent-ledger test-data workspace already exists: $BrokerConsentLedgerTestData"
    }
    New-Item -ItemType Directory -Path $BrokerConsentLedgerTestData -ErrorAction Stop | Out-Null
    $brokerConsentLedgerTestDataOwned = $true
    $null = Assert-NoReparsePointsInTree `
        -Path $BrokerConsentLedgerTestData `
        -Label 'The Broker consent-ledger test-data workspace'
    $null = Initialize-DDriveDirectory -Path $NugetScratch -Label 'The isolated NuGet scratch root'
    $null = Initialize-DDriveDirectory -Path $DotnetBundleExtractRoot -Label 'The isolated dotnet bundle extraction root'
    $null = Initialize-DDriveDirectory -Path $ToolUserProfile -Label 'The isolated tool user profile'
    $null = Initialize-DDriveDirectory -Path $ToolAppData -Label 'The isolated tool roaming profile'
    $null = Initialize-DDriveDirectory -Path $ToolLocalAppData -Label 'The isolated tool local profile'
    $null = Initialize-DDriveDirectory `
        -Path $MSBuildUserExtensionsPath `
        -Label 'The isolated MSBuild user extensions root'
    New-Item -ItemType Directory `
        -Path $RuntimeStage,$SourceStage,$ArtifactsRoot,$FormalArtifactsRoot,$TestDataRoot `
        -Force | Out-Null
    $DotnetExecutable = Resolve-PinnedDotnetExecutable
    $DotnetAuthority = Open-PinnedDotnetLeases
    if (![string]::Equals(
            [string]$DotnetAuthority.ExecutablePath,
            $DotnetExecutable,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The pinned .NET executable and authority disagree.'
    }
    Assert-PinnedGlobalJson -Path $GlobalJsonPath
    Assert-PinnedRestoreInputs `
        -ConfigPath $NuGetConfigPath `
        -LockPath $ControlLockFilePath

    $sourceStandaloneFiles = @($PSCommandPath, $GlobalJsonPath, $NuGetConfigPath)
    $activeSourceBefore = @(Get-ReleaseSourceContentManifest `
        -Root $WorkRoot `
        -ProjectRoots $SourceProjectRoots `
        -StandaloneFiles $sourceStandaloneFiles `
        -Label 'Authoritative source before staging')

    Invoke-Robocopy $ProjectRoot $StagedProjectRoot
    Invoke-Robocopy $TestsRoot $StagedTestsRoot
    Invoke-Robocopy $ControlRoot $StagedControlRoot
    Invoke-Robocopy $TrustRoot $StagedTrustRoot
    Invoke-Robocopy $BrokerProbeRoot $StagedBrokerRoot
    Copy-Item -LiteralPath $PSCommandPath -Destination $SourceStage -Force
    Copy-Item -LiteralPath $GlobalJsonPath -Destination $SourceStage -Force
    Copy-Item -LiteralPath $NuGetConfigPath -Destination $SourceStage -Force

    $SourceStageManifest = @(Get-TreeContentManifest `
        -Root $SourceStage `
        -Label 'Staged source snapshot')
    $activeSourceAfter = @(Get-ReleaseSourceContentManifest `
        -Root $WorkRoot `
        -ProjectRoots $SourceProjectRoots `
        -StandaloneFiles $sourceStandaloneFiles `
        -Label 'Authoritative source after staging')
    Assert-ContentManifestsEqual `
        -Expected $activeSourceBefore `
        -Actual $SourceStageManifest `
        -Label 'Authoritative source to staged source'
    Assert-ContentManifestsEqual `
        -Expected $activeSourceBefore `
        -Actual $activeSourceAfter `
        -Label 'Authoritative source staging stability'

    $null = Assert-NoReparsePointsInTree -Path $SourceStage -Label 'Staged source package'
    Assert-PinnedGlobalJson -Path $StagedGlobalJsonPath
    Assert-PinnedRestoreInputs `
        -ConfigPath $StagedNuGetConfigPath `
        -LockPath $StagedControlLockFilePath
    Assert-NoImplicitMsBuildInputs -SourceRoot $SourceStage -Projects $StagedProjects
    Assert-StagedProjectReferenceClosure `
        -Root $SourceStage `
        -EntryProjects @($StagedTestsProject) `
        -ExpectedProjects @(
            'CodexGuardian.Tests\CodexGuardian.Tests.csproj',
            'CodexGuardian\CodexGuardian.csproj',
            'CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian.Trust\CodexGuardian.Trust.csproj',
            'CodexGuardian.Broker\CodexGuardian.Broker.csproj'
        ) `
        -ExpectedEdges @(
            'CodexGuardian.Tests\CodexGuardian.Tests.csproj->CodexGuardian.Broker\CodexGuardian.Broker.csproj',
            'CodexGuardian.Tests\CodexGuardian.Tests.csproj->CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian.Tests\CodexGuardian.Tests.csproj->CodexGuardian\CodexGuardian.csproj',
            'CodexGuardian.Tests\CodexGuardian.Tests.csproj->CodexGuardian.Trust\CodexGuardian.Trust.csproj',
            'CodexGuardian\CodexGuardian.csproj->CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian\CodexGuardian.csproj->CodexGuardian.Trust\CodexGuardian.Trust.csproj',
            'CodexGuardian.Broker\CodexGuardian.Broker.csproj->CodexGuardian.Control\CodexGuardian.Control.csproj',
            'CodexGuardian.Broker\CodexGuardian.Broker.csproj->CodexGuardian.Trust\CodexGuardian.Trust.csproj'
        )

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'restore',
            $StagedTestsProject,
            '--disable-build-servers',
            '--configfile', $StagedNuGetConfigPath,
            '--packages', $NugetPackages,
            '--locked-mode',
            '-r', 'win-x64',
            '--artifacts-path', $ArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Locked release restore' `
        -TimeoutSeconds 300

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'build',
            $StagedTestsProject,
            '--disable-build-servers',
            '--no-restore',
            '-c', 'Release',
            '--no-incremental',
            '--artifacts-path', $ArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            '-p:UseSharedCompilation=false',
            '-p:RestoreLockedMode=true',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Release build' `
        -TimeoutSeconds 900
    Assert-NoSourceBuildResidue

    $TestsAssembly = Join-Path $ArtifactsRoot 'bin\CodexGuardian.Tests\release\CodexGuardian.Tests.dll'
    if (!(Test-Path -LiteralPath $TestsAssembly -PathType Leaf)) {
        throw "Release test assembly was not produced in the isolated artifacts directory: $TestsAssembly"
    }
    foreach ($freshBuildFile in @(
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian\release\CodexGuardian.exe'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian\release\CodexGuardian.dll'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian\release\CodexGuardian.Control.dll'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian\release\CodexGuardian.deps.json'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian\release\CodexGuardian.runtimeconfig.json'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Broker.exe'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Broker.dll'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Broker.deps.json'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Broker.runtimeconfig.json'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Control.dll'),
        (Join-Path $ArtifactsRoot 'bin\CodexGuardian.Broker\release\CodexGuardian.Trust.dll')
    )) {
        if (!(Test-Path -LiteralPath $freshBuildFile -PathType Leaf)) {
            throw "The isolated release build graph is incomplete: $freshBuildFile"
        }
    }

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--broker-guardian-admission-offline-only'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Broker Guardian admission offline tests' `
        -TimeoutSeconds 300 `
        -ExpectedSuccessMarker 'BROKER_GUARDIAN_ADMISSION_OFFLINE_TESTS_COMPLETE' `
        -RequireEmptyStderr

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--safe-drill-only',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Safe-drill tests' `
        -TimeoutSeconds 300 `
        -ExpectedSuccessMarker 'ALL TESTS PASSED' `
        -RequireEmptyStderr

    if (Test-Path -LiteralPath $NativeUserPresenceEvidenceRoot) {
        throw 'The native user-presence evidence root must not preexist the capability probe.'
    }
    New-Item -ItemType Directory -Path $NativeUserPresenceEvidenceRoot -ErrorAction Stop | Out-Null
    if (@(Get-ChildItem -LiteralPath $NativeUserPresenceEvidenceRoot -Force -ErrorAction Stop).Count -ne 0) {
        throw 'The native user-presence evidence root must be empty before the capability probe.'
    }
    Invoke-BoundedDotnetGate -Authority $DotnetAuthority -Assembly $TestsAssembly `
        -Arguments @(
            '--native-user-presence-capability-probe',
            '--native-user-presence-evidence-root', $NativeUserPresenceEvidenceRoot
        ) `
        -TimeoutSeconds $NativeUserPresenceCapabilityProbeTimeoutSeconds `
        -SuccessMarker $NativeUserPresenceCapabilityProbeMarker `
        -WorkingDirectory $SourceStage `
        -Label 'Native user-presence capability probe'

    Invoke-BoundedDotnetGate -Authority $DotnetAuthority -Assembly $TestsAssembly `
        -Arguments @(
            '--native-peer-child-probe',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData
        ) `
        -TimeoutSeconds $NativePeerProbeTimeoutSeconds `
        -SuccessMarker $NativePeerProbeMarker `
        -WorkingDirectory $SourceStage `
        -Label 'Native peer authentication probe'

    Invoke-BoundedDotnetGate -Authority $DotnetAuthority -Assembly $TestsAssembly `
        -Arguments @(
            '--native-connected-client-probe',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData
        ) `
        -TimeoutSeconds $ConnectedClientProbeTimeoutSeconds `
        -SuccessMarker $ConnectedClientProbeMarker `
        -WorkingDirectory $SourceStage `
        -Label 'Synthetic Tests-apphost Guardian-role reverse authentication probe'

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--watcher-only',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Real-time watcher tests' `
        -TimeoutSeconds 300 `
        -ExpectedSuccessMarker 'ALL TESTS PASSED' `
        -RequireEmptyStderr

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--package-baseline-live-readonly',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Read-only installed-package verification' `
        -TimeoutSeconds 180

    Assert-NoSourceBuildResidue

    $IdleResourceData = Join-Path $TestDataRoot 'idle-resource'
    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--idle-resource-host',
            '--duration-seconds', '65',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData,
            '--data-dir', $IdleResourceData
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Event-driven idle resource acceptance' `
        -TimeoutSeconds 180

    $TargetedRefreshData = Join-Path $TestDataRoot 'targeted-refresh'
    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--idle-resource-host',
            '--targeted-refresh-probe',
            '--broker-consent-ledger-store-test-data-root', $BrokerConsentLedgerTestData,
            '--data-dir', $TargetedRefreshData
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Targeted event refresh acceptance' `
        -TimeoutSeconds 180

    [xml]$projectXml = Get-Content -Raw -LiteralPath $StagedProjectFile
    $declaredVersion = [string]$projectXml.Project.PropertyGroup.Version
    if ($declaredVersion -ne $ExpectedProjectVersion) {
        throw "CodexGuardian project version must be $ExpectedProjectVersion; found $declaredVersion."
    }

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'restore',
            $StagedProjectFile,
            '--disable-build-servers',
            '--configfile', $StagedNuGetConfigPath,
            '--packages', $NugetPackages,
            '--locked-mode',
            '-r', 'win-x64',
            '-p:SelfContained=true',
            '-p:CodexGuardianTestFriend=false',
            '--artifacts-path', $FormalArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Locked self-contained publish restore' `
        -TimeoutSeconds 300

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'restore',
            $StagedBrokerProject,
            '--disable-build-servers',
            '--configfile', $StagedNuGetConfigPath,
            '--packages', $NugetPackages,
            '--locked-mode',
            '-r', 'win-x64',
            '-p:SelfContained=true',
            '-p:CodexGuardianTestFriend=false',
            '--artifacts-path', $FormalArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Locked Broker self-contained publish restore' `
        -TimeoutSeconds 300

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'publish',
            $StagedProjectFile,
            '--disable-build-servers',
            '--no-restore',
            '-c', 'Release',
            '-r', 'win-x64',
            '--self-contained', 'true',
            '--artifacts-path', $FormalArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            '-p:UseSharedCompilation=false',
            '-p:RestoreLockedMode=true',
            '-p:CodexGuardianTestFriend=false',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '-o', $RuntimeStage,
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Runtime publish' `
        -TimeoutSeconds 900
    Assert-NoSourceBuildResidue

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            'publish',
            $StagedBrokerProject,
            '--disable-build-servers',
            '--no-restore',
            '-c', 'Release',
            '-r', 'win-x64',
            '--self-contained', 'true',
            '--artifacts-path', $FormalArtifactsRoot,
            '-p:ImportDirectoryBuildProps=false',
            '-p:ImportDirectoryBuildTargets=false',
            '-p:UseSharedCompilation=false',
            '-p:RestoreLockedMode=true',
            '-p:CodexGuardianTestFriend=false',
            "-p:MSBuildUserExtensionsPath=$MSBuildUserExtensionsPath",
            '-o', $BrokerRuntimeStage,
            '--nologo'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Broker runtime publish' `
        -TimeoutSeconds 900
    Assert-NoSourceBuildResidue

    Write-CanonicalRuntimeConfigDev `
        -Path (Join-Path $RuntimeStage 'CodexGuardian.runtimeconfig.dev.json') `
        -Label 'Published Guardian runtimeconfig.dev.json'
    Write-CanonicalRuntimeConfigDev `
        -Path (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.runtimeconfig.dev.json') `
        -Label 'Published Broker runtimeconfig.dev.json'

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--verify-published-runtime-closure',
            '--published-runtime-root', $RuntimeStage,
            '--published-runtime-nuget-packages-root', $NugetPackages,
            '--published-runtime-root-assembly', 'CodexGuardian',
            '--require-production-runtime-surface'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Published runtime dependency closure' `
        -TimeoutSeconds 180 `
        -ExpectedSuccessMarker 'PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED' `
        -RequireEmptyStderr
    Assert-NoSourceBuildResidue

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--verify-published-runtime-closure',
            '--published-runtime-root', $BrokerRuntimeStage,
            '--published-runtime-nuget-packages-root', $NugetPackages,
            '--published-runtime-root-assembly', 'CodexGuardian.Broker',
            '--require-production-runtime-surface'
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Published Broker runtime dependency closure' `
        -TimeoutSeconds 180 `
        -ExpectedSuccessMarker 'PUBLISHED_RUNTIME_DEPENDENCY_CLOSURE_VERIFIED' `
        -RequireEmptyStderr
    Assert-NoSourceBuildResidue

    Invoke-PinnedDotnetCommand `
        -Authority $DotnetAuthority `
        -Arguments @(
            $TestsAssembly,
            '--guardian-managed-entry-apphost-probe',
            '--guardian-managed-entry-runtime-root', $RuntimeStage
        ) `
        -WorkingDirectory $SourceStage `
        -Label 'Published Guardian managed-entry apphost proof' `
        -TimeoutSeconds 180 `
        -ExpectedSuccessMarker 'GUARDIAN_MANAGED_ENTRY_APPHOST_PROOF_VERIFIED' `
        -RequireEmptyStderr
    Assert-NoSourceBuildResidue
    Close-PinnedDotnetLeases -Authority $DotnetAuthority
    $DotnetAuthority = $null

    Copy-Item -LiteralPath (Join-Path $StagedProjectRoot 'README.md') -Destination $RuntimeStage -Force
    Assert-TreeMatchesManifest `
        -Root $SourceStage `
        -ExpectedManifest $SourceStageManifest `
        -Label 'Staged source after build test and publish'

    $publishedExecutable = Join-Path $RuntimeStage 'CodexGuardian.exe'
    foreach ($requiredFile in @(
        $publishedExecutable,
        (Join-Path $RuntimeStage 'CodexGuardian.dll'),
        (Join-Path $RuntimeStage 'CodexGuardian.Control.dll'),
        (Join-Path $RuntimeStage 'CodexGuardian.Trust.dll'),
        (Join-Path $RuntimeStage 'System.Security.Cryptography.Pkcs.dll'),
        (Join-Path $RuntimeStage 'CodexGuardian.deps.json'),
        (Join-Path $RuntimeStage 'CodexGuardian.runtimeconfig.json'),
        (Join-Path $RuntimeStage 'CodexGuardian.runtimeconfig.dev.json'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.exe'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.dll'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Control.dll'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Trust.dll'),
        (Join-Path $BrokerRuntimeStage 'System.Security.Cryptography.Pkcs.dll'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.deps.json'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.runtimeconfig.json'),
        (Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.runtimeconfig.dev.json'),
        (Join-Path $RuntimeStage 'README.md'),
        (Join-Path $SourceStage 'CodexGuardian\App.xaml'),
        (Join-Path $SourceStage 'CodexGuardian\App.xaml.cs'),
        (Join-Path $SourceStage 'CodexGuardian\MainWindow.xaml.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Program.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Services\SettingsService.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Services\DataDirectorySafety.cs'),
        (Join-Path $SourceStage 'CodexGuardian\ViewModels\MainViewModel.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Services\AppServerClient.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Services\RecoveryOperationJournal.cs'),
        (Join-Path $SourceStage 'CodexGuardian\GuardianBrokerManagedBootstrap.cs'),
        (Join-Path $SourceStage 'CodexGuardian\GuardianBrokerBootstrapLifetime.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\ICdpCommandTransport.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CdpPipeTransport.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\WindowsCrtPipeProcess.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexCdpRuntimeResources.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexCdpObservationProtocol.cs'),
        (Join-Path $SourceStage 'CodexGuardian\Services\CodexDeepObservationService.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexPackageBaselineVerifier.cs'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\cdp-runtime-profile.json'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\cdp-observation-profile.json'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\codex-guardian-cdp-hook.js'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\codex-guardian-cdp-runtime-hook.js'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\codex-guardian-cdp-observer-poc.mjs'),
        (Join-Path $SourceStage 'CodexGuardian\HookPayload\run-cdp-observation-poc.ps1'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexGuardian.Control.csproj'),
        (Join-Path $SourceStage 'CodexGuardian.Control\packages.lock.json'),
        (Join-Path $SourceStage 'CodexGuardian.Control\GlobalUsings.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexCdpBrokerProtocol.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexCdpBrokerStateMachine.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexCdpRuntimeOwnership.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexPackageCompatibility.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexAsarCapabilityInspector.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexPackageGeneration.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\CodexAppxBlockMapVerifier.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\PublishedRuntimeDependencyClosureVerifier.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\GuardianManagedEntryProof.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\GuardianBrokerAdmissionProtocol.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerConsentLedgerContract.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerConsentLedgerStore.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerConsentGrantDraft.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerWebAuthnClientData.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerWebAuthnCoseKey.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerWebAuthnProof.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerWebAuthnReceiptVerifier.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerFreshPresenceSession.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerCapabilityLease.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerRuntimeOwner.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\WindowsCodexCdpRuntimeControlHost.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerControlSession.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\VerifiedGuardianManagedEntryConnection.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerSingleInstanceLease.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerGuardianAcceptLoop.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerProductionHost.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerProductionComposition.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\WindowsGuardianProductionAdmission.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\WindowsGuardianCleanLauncher.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\WindowsGuardianProcessSettlement.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerWebAuthnPlatform.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\BrokerOwnedWindow.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\CodexAsarCapabilityOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerConsentLedgerContractOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerConsentLedgerStoreOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerWebAuthnReceiptOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerControlSessionOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\CodexCdpRuntimeOwnershipOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsCrtPipeProcessLifecycleOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsCodexCdpRuntimeControlHostOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\PublishedRuntimeDependencyClosureOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Control\GuardianBrokerBootstrapProtocol.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\GuardianBrokerBootstrapOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\Program.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\GuardianBrokerAdmissionProtocolOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsGuardianCleanLauncherOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\GuardianManagedEntryProofOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsGuardianProductionAdmissionOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\GuardianBrokerManagedBootstrapOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\FollowUpOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\VerifiedLocalReleaseManifestOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerProductionHostOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\BrokerWebAuthnNativeProbeTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\CodexPackageBaselineVerifierOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\CodexCdpObservationSessionOfflineTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsNamedPipePeerTrustNativeProbeTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Tests\WindowsConnectedClientPeerTrustNativeTests.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\CodexGuardian.Trust.csproj'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\BrokerPeerTrust.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\AuthenticatedPipePeerConnection.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\Windows\WindowsNativePeerIdentity.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\Windows\WindowsSameLogonNamedPipe.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\Windows\WindowsNamedPipePeerTrustPlatform.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\Windows\WindowsConnectedClientPeerTrustPlatform.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Trust\Windows\WindowsVerifiedLocalReleaseManifestFactory.cs'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\CodexGuardian.Broker.csproj'),
        (Join-Path $SourceStage 'CodexGuardian.Broker\Program.cs'),
        (Join-Path $SourceStage 'package-release.ps1'),
        (Join-Path $SourceStage 'global.json'),
        (Join-Path $SourceStage 'NuGet.config')
    )) {
        if (!(Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Release staging is incomplete: $requiredFile"
        }
    }

    $publishedVersionInfo = (Get-Item -LiteralPath $publishedExecutable).VersionInfo
    $publishedFileVersion = [Version]::new(
        $publishedVersionInfo.FileMajorPart,
        $publishedVersionInfo.FileMinorPart,
        $publishedVersionInfo.FileBuildPart,
        $publishedVersionInfo.FilePrivatePart
    )
    if ($publishedFileVersion -ne $ExpectedFileVersion) {
        throw "Published CodexGuardian.exe version is $publishedFileVersion; expected $ExpectedFileVersion."
    }
    $publishedBrokerVersionInfo = (Get-Item -LiteralPath (
        Join-Path $BrokerRuntimeStage 'CodexGuardian.Broker.exe')).VersionInfo
    $publishedBrokerFileVersion = [Version]::new(
        $publishedBrokerVersionInfo.FileMajorPart,
        $publishedBrokerVersionInfo.FileMinorPart,
        $publishedBrokerVersionInfo.FileBuildPart,
        $publishedBrokerVersionInfo.FilePrivatePart
    )
    if ($publishedBrokerFileVersion -ne $ExpectedFileVersion) {
        throw "Published CodexGuardian.Broker.exe version is $publishedBrokerFileVersion; expected $ExpectedFileVersion."
    }

    Assert-NoExcludedDirectories $RuntimeStage
    Assert-NoExcludedDirectories $SourceStage
    Assert-NoDesktopModificationPayload -Root $RuntimeStage -Label 'Staged runtime package'
    Assert-NoDesktopModificationPayload -Root $SourceStage -Label 'Staged source package'
    Assert-NoRuntimeTestPayload -Root $RuntimeStage -Label 'Staged runtime package'

    $RuntimeStageManifest = @(Get-TreeContentManifest `
        -Root $RuntimeStage `
        -Label 'Staged runtime snapshot')
    $runtimeFileCount = $RuntimeStageManifest.Count
    $sourceFileCount = $SourceStageManifest.Count
    if ($ValidateOnly) {
        $validationRuntimeZip = Join-Path $StagingRoot 'runtime-validation.zip'
        $validationSourceZip = Join-Path $StagingRoot 'source-validation.zip'
        Compress-CanonicalArchive `
            -Source $RuntimeStage `
            -Destination $validationRuntimeZip `
            -ExpectedManifest $RuntimeStageManifest `
            -Label 'Validation runtime ZIP' `
            -DestinationScope scratch
        Compress-CanonicalArchive `
            -Source $SourceStage `
            -Destination $validationSourceZip `
            -ExpectedManifest $SourceStageManifest `
            -Label 'Validation source ZIP' `
            -DestinationScope scratch
        Assert-NoDesktopModificationArchiveEntries -Path $validationRuntimeZip -Label 'Validation runtime ZIP'
        Assert-NoDesktopModificationArchiveEntries -Path $validationSourceZip -Label 'Validation source ZIP'
        Assert-NoRuntimeTestArchiveEntries -Path $validationRuntimeZip -Label 'Validation runtime ZIP'
        Assert-ArchiveMatchesManifest `
            -Path $validationRuntimeZip `
            -ExpectedManifest $RuntimeStageManifest `
            -Label 'Validation runtime ZIP'
        Assert-ArchiveMatchesManifest `
            -Path $validationSourceZip `
            -ExpectedManifest $SourceStageManifest `
            -Label 'Validation source ZIP'
        $validationRuntimeEntryCount = Get-ArchiveEntryCount $validationRuntimeZip
        $validationSourceEntryCount = Get-ArchiveEntryCount $validationSourceZip
        if ($validationRuntimeEntryCount -ne $runtimeFileCount -or
            $validationSourceEntryCount -ne $sourceFileCount) {
            throw "Validation archive check failed: runtime=$validationRuntimeEntryCount/$runtimeFileCount source=$validationSourceEntryCount/$sourceFileCount"
        }

        Write-Host "Release validation passed without modifying formal outputs."
        Write-Host "Validated CodexGuardian.exe version: $publishedFileVersion"
        Write-Host "Validated archive entries: runtime=$validationRuntimeEntryCount source=$validationSourceEntryCount"
        return
    }

    # Future Guardian builds hold this lease for their full lifetime. The process
    # check remains required for older builds that do not yet honor it.
    $guardianReleaseLease = Enter-GuardianReleaseLease
    Assert-GuardianStopped
    $null = Assert-NoReparseTraversal $OutputsRoot
    if (!(Test-Path -LiteralPath $OutputsRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputsRoot -Force | Out-Null
    }
    $null = Assert-NoReparsePointsInTree -Path $OutputsRoot -Label 'Formal release outputs'

    $RuntimeZip = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-win-x64.zip')
    $SourceZip = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-source.zip')
    $ChecksumPath = Assert-OutputPath (Join-Path $OutputsRoot 'SHA256SUMS.txt')
    $RuntimeNext = Assert-OutputPath ($RuntimeOutput + '.next')
    $RuntimePrevious = Assert-OutputPath ($RuntimeOutput + '.previous')
    $SourceNext = Assert-OutputPath ($SourceOutput + '.next')
    $SourcePrevious = Assert-OutputPath ($SourceOutput + '.previous')
    $RuntimeZipNext = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-win-x64.next.zip')
    $RuntimeZipPrevious = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-win-x64.previous.zip')
    $SourceZipNext = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-source.next.zip')
    $SourceZipPrevious = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-source.previous.zip')
    $ChecksumNext = Assert-OutputPath (Join-Path $OutputsRoot 'SHA256SUMS.next.txt')
    $ChecksumPrevious = Assert-OutputPath (Join-Path $OutputsRoot 'SHA256SUMS.previous.txt')
    $ReleaseCommitPath = Assert-OutputPath (Join-Path $OutputsRoot 'CodexGuardian-release-manifest.json')
    $ReleaseJournalPath = Assert-OutputPath (Join-Path $OutputsRoot '.CodexGuardian-release-transaction.json')
    $ReleaseLockPath = Assert-OutputPath (Join-Path $OutputsRoot '.CodexGuardian-release-exchange.lock')
    $ReleaseTransactionId = [Guid]::NewGuid().ToString('N')
    $ReleaseCommitPendingPath = Get-ReleaseCommitPendingPath `
        -OutputsPath $OutputsRoot `
        -TransactionId $ReleaseTransactionId

    $releaseArtifacts = @(
        [pscustomobject]@{ Id = 'runtime-directory'; Label = 'runtime directory'; Kind = 'tree'; Leaf = 'CodexGuardian-win-x64'; Current = $RuntimeOutput; Next = $RuntimeNext; Previous = $RuntimePrevious },
        [pscustomobject]@{ Id = 'source-directory'; Label = 'source directory'; Kind = 'tree'; Leaf = 'CodexGuardian-source'; Current = $SourceOutput; Next = $SourceNext; Previous = $SourcePrevious },
        [pscustomobject]@{ Id = 'runtime-zip'; Label = 'runtime ZIP'; Kind = 'file'; Leaf = 'CodexGuardian-win-x64.zip'; Current = $RuntimeZip; Next = $RuntimeZipNext; Previous = $RuntimeZipPrevious },
        [pscustomobject]@{ Id = 'source-zip'; Label = 'source ZIP'; Kind = 'file'; Leaf = 'CodexGuardian-source.zip'; Current = $SourceZip; Next = $SourceZipNext; Previous = $SourceZipPrevious },
        [pscustomobject]@{ Id = 'checksum'; Label = 'checksum file'; Kind = 'file'; Leaf = 'SHA256SUMS.txt'; Current = $ChecksumPath; Next = $ChecksumNext; Previous = $ChecksumPrevious }
    )

    $releaseExchangeLock = Enter-ReleaseExchangeLock -Path $ReleaseLockPath
    try {
        Resolve-ReleaseExchangeTransaction `
            -Artifacts $releaseArtifacts `
            -JournalPath $ReleaseJournalPath `
            -CommitPath $ReleaseCommitPath `
            -OutputsPath $OutputsRoot
        Assert-ReleaseExchangeWorkspaceSettled `
            -Artifacts $releaseArtifacts `
            -JournalPath $ReleaseJournalPath `
            -OutputsPath $OutputsRoot
        Assert-ExistingDesktopShortcut
        $releaseBaseline = Get-CurrentReleaseBaseline `
            -Artifacts $releaseArtifacts `
            -CommitPath $ReleaseCommitPath

        New-ManagedOutputDirectory -Destination $RuntimeNext
        New-ManagedOutputDirectory -Destination $SourceNext
        Copy-ManagedOutputTree `
            -Source $RuntimeStage `
            -Destination $RuntimeNext `
            -Label 'Next runtime package'
        Copy-ManagedOutputTree `
            -Source $SourceStage `
            -Destination $SourceNext `
            -Label 'Next source package'
        Assert-NoExcludedDirectories $RuntimeNext
        Assert-NoExcludedDirectories $SourceNext
        Assert-NoDesktopModificationPayload -Root $RuntimeNext -Label 'Next runtime package'
        Assert-NoDesktopModificationPayload -Root $SourceNext -Label 'Next source package'
        Assert-NoRuntimeTestPayload -Root $RuntimeNext -Label 'Next runtime package'
        Assert-TreeMatchesManifest `
            -Root $RuntimeNext `
            -ExpectedManifest $RuntimeStageManifest `
            -Label 'Next runtime directory'
        Assert-TreeMatchesManifest `
            -Root $SourceNext `
            -ExpectedManifest $SourceStageManifest `
            -Label 'Next source directory'

        Compress-ManagedOutputArchive `
            -Source $RuntimeNext `
            -Destination $RuntimeZipNext `
            -ExpectedManifest $RuntimeStageManifest `
            -Label 'Next runtime ZIP'
        Compress-ManagedOutputArchive `
            -Source $SourceNext `
            -Destination $SourceZipNext `
            -ExpectedManifest $SourceStageManifest `
            -Label 'Next source ZIP'
        Assert-NoDesktopModificationArchiveEntries -Path $RuntimeZipNext -Label 'Next runtime ZIP'
        Assert-NoDesktopModificationArchiveEntries -Path $SourceZipNext -Label 'Next source ZIP'
        Assert-NoRuntimeTestArchiveEntries -Path $RuntimeZipNext -Label 'Next runtime ZIP'
        Assert-ArchiveMatchesManifest `
            -Path $RuntimeZipNext `
            -ExpectedManifest $RuntimeStageManifest `
            -Label 'Next runtime ZIP'
        Assert-ArchiveMatchesManifest `
            -Path $SourceZipNext `
            -ExpectedManifest $SourceStageManifest `
            -Label 'Next source ZIP'

        $runtimeEntryCount = Get-ArchiveEntryCount $RuntimeZipNext
        $sourceEntryCount = Get-ArchiveEntryCount $SourceZipNext
        if ($runtimeEntryCount -ne $runtimeFileCount -or $sourceEntryCount -ne $sourceFileCount) {
            throw "Release archive validation failed: runtime=$runtimeEntryCount/$runtimeFileCount source=$sourceEntryCount/$sourceFileCount"
        }

        $checksumLines = @(
            "$((Get-FileHash -LiteralPath $RuntimeZipNext -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $RuntimeZip -Leaf)"
            "$((Get-FileHash -LiteralPath $SourceZipNext -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $SourceZip -Leaf)"
        )
        Write-ManagedOutputLines -Destination $ChecksumNext -Lines $checksumLines
        $writtenChecksumLines = @(Get-Content -LiteralPath $ChecksumNext)
        if ($writtenChecksumLines.Count -ne $checksumLines.Count -or
            @(Compare-Object -ReferenceObject $checksumLines -DifferenceObject $writtenChecksumLines -SyncWindow 0).Count -ne 0) {
            throw 'The next checksum file did not round-trip exactly.'
        }

        $releaseExchangeSucceeded = Invoke-DurableReleaseExchangeTransaction `
            -ReleaseArtifacts $releaseArtifacts `
            -ReleaseBaseline $releaseBaseline `
            -ReleaseTransactionId $ReleaseTransactionId `
            -ReleaseCommitPendingPath $ReleaseCommitPendingPath `
            -ReleaseCommitPath $ReleaseCommitPath `
            -ReleaseJournalPath $ReleaseJournalPath `
            -OutputsRoot $OutputsRoot `
            -RuntimeOutput $RuntimeOutput `
            -SourceOutput $SourceOutput `
            -RuntimeZip $RuntimeZip `
            -SourceZip $SourceZip `
            -ChecksumPath $ChecksumPath `
            -RuntimeStageManifest $RuntimeStageManifest `
            -SourceStageManifest $SourceStageManifest `
            -RuntimeEntryCount $runtimeEntryCount `
            -SourceEntryCount $sourceEntryCount `
            -FaultCallback $null
    }
    catch {
        $releaseFailure = $_
        try {
            Resolve-ReleaseExchangeTransaction `
                -Artifacts $releaseArtifacts `
                -JournalPath $ReleaseJournalPath `
                -CommitPath $ReleaseCommitPath `
                -OutputsPath $OutputsRoot
        }
        catch {
            throw "Release exchange failed: $($releaseFailure.Exception.Message). Recovery also failed: $($_.Exception.Message)"
        }
        throw $releaseFailure
    }

    if (!$releaseExchangeSucceeded) {
        throw 'The release exchange reached its ready path without a verified commit.'
    }
    Write-Host "Release ready after validated exchange: $RuntimeOutput"
    Write-Host "Runtime archive entries: $runtimeEntryCount"
    Write-Host "Source archive entries: $sourceEntryCount"
    Get-Content -LiteralPath $ChecksumPath
}
finally {
    if ($null -ne $releaseExchangeLock) {
        $releaseExchangeLock.Dispose()
        $releaseExchangeLock = $null
    }
    if ($null -ne $guardianReleaseLease) {
        Exit-GuardianReleaseLease -Mutex $guardianReleaseLease
        $guardianReleaseLease = $null
    }
    if ($null -ne $DotnetAuthority) {
        try {
            Close-PinnedDotnetLeases -Authority $DotnetAuthority
            $DotnetAuthority = $null
        }
        catch {
            Write-Warning "Pinned .NET authority cleanup failed: $($_.Exception.Message)"
        }
    }

    $cleanupSnapshots = @(
        (Get-CleanupTargetSnapshot $ScratchWorkspace),
        (Get-CleanupTargetSnapshot $TempWorkspace)
    )
    if ($brokerConsentLedgerTestDataOwned) {
        $cleanupSnapshots += (Get-CleanupTargetSnapshot $BrokerConsentLedgerTestData)
    }
    try {
        Write-CleanupManifest -Targets $cleanupSnapshots -VerifiedAbsentAfterDelete $false
    }
    catch {
        Write-Warning "Release cleanup manifest initialization failed: $($_.Exception.Message)"
    }

    $env:TEMP = $TempRoot
    $env:TMP = $TempRoot
    try {
        Remove-ScratchDirectoryTree $ScratchWorkspace
    }
    catch {
        Write-Warning "Release scratch cleanup failed: $($_.Exception.Message)"
    }

    if ($brokerConsentLedgerTestDataOwned) {
        try {
            Remove-TempDirectoryTree $BrokerConsentLedgerTestData
        }
        catch {
            Write-Warning "Release Broker ledger test-data cleanup failed: $($_.Exception.Message)"
        }
    }

    try {
        Remove-TempDirectoryTree $TempWorkspace
    }
    catch {
        Write-Warning "Release temporary cleanup failed: $($_.Exception.Message)"
    }

    $cleanupVerified =
        $null -eq (Get-ExactPathEntry $ScratchWorkspace) -and
        $null -eq (Get-ExactPathEntry $TempWorkspace) -and
        (!$brokerConsentLedgerTestDataOwned -or
         $null -eq (Get-ExactPathEntry $BrokerConsentLedgerTestData))
    try {
        Write-CleanupManifest -Targets $cleanupSnapshots -VerifiedAbsentAfterDelete $cleanupVerified
    }
    catch {
        Write-Warning "Release cleanup manifest finalization failed: $($_.Exception.Message)"
    }

    Assert-NoSourceBuildResidue
}
