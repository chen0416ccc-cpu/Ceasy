#Requires -Version 5.1

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ObserverPath,

  [Parameter(Mandatory = $true)]
  [string]$HookPath,

  [Parameter(Mandatory = $true)]
  [string]$ProfilePath,

  [string]$LogPath = 'D:\CodexData\CodexGuardian\r13-cdp-poc\logs\cdp-observation.jsonl',

  [ValidateRange(30, 3600)]
  [int]$DurationSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedMainName = 'OpenAI.Codex'
$ExpectedMainPublisher = 'CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B'
$ExpectedMainFamilyName = 'OpenAI.Codex_2p2nqsd0c76g0'
$ExpectedMainArchitecture = 'x64'
$ExpectedContractId = 'codex-cdp-observation-v1'
$ExpectedAsarPackageName = 'openai-codex-electron'
$ExpectedAsarProductName = 'Codex'
$ExpectedAsarMainPath = '.vite/build/early-bootstrap.js'
$ExpectedAsarMainSha256 = 'DCC940F4ABB9D2D3C84448B42A6499A19AAE7F3C221D853C48D32C9F62CE5CDB'
$ExpectedPreloadPath = '.vite/build/preload.js'
$ExpectedPreloadSha256 = 'A976C02AB0F9CF0EB11D5E4DA32C95E9F5DB3790D76505888C6E493F137F6AC9'
$ExpectedPreloadMarkers = @(
  'electronBridge',
  'codex_desktop:message-for-view',
  'contextBridge.exposeInMainWorld',
  'MessageEvent'
)
$ExpectedObserverSha256 = '6B4E942575A02DF4B5103EF4DCAE64F37A420FD7EE61011E13D4FA0141B33776'
$ExpectedHookSha256 = 'F483C1A97F138CA884EB8464C3675F0C07CC0B594B866ECF65277EE124413961'
$ExpectedProfileSha256 = '7DE72801982AF8129978E02E5B39F70AE641A138A10DA20C57324EF29A97033E'
$ExpectedNodePath = 'C:\Program Files\nodejs\node.exe'
$ExpectedNodeVersion = '24.11.1'
$ExpectedNodeSha256 = 'F13AC3CA23248DC389507E8FE38C34489AB7EDB3E6D6700EB6DA6A0B7E128EAF'
$ExpectedNodeSigner = 'CN=OpenJS Foundation, O=OpenJS Foundation, L=San Francisco, S=California, C=US'
$ExpectedLogRoot = 'D:\CodexData\CodexGuardian\r13-cdp-poc'

function Fail([string]$Message) {
  throw "[CodexGuardian CDP PoC] $Message"
}

function Resolve-RequiredFile([string]$Path, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
    Fail "$Label must be an absolute path"
  }
  $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
  if (-not $resolved) {
    Fail "$Label does not exist"
  }
  $item = Get-Item -LiteralPath $resolved.ProviderPath -Force
  if ($item.PSIsContainer -or $item.LinkType -or
      (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    Fail "$Label must be a regular non-linked file"
  }
  return $item.FullName
}

function Assert-FileHash([string]$Path, [string]$ExpectedSha256, [string]$Label) {
  $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
  if ($actual -ne $ExpectedSha256) {
    Fail "$Label hash mismatch"
  }
}

function Assert-ProfileValue([object]$Actual, [object]$Expected, [string]$Label) {
  if (-not [string]::Equals(
      [string]$Actual,
      [string]$Expected,
      [StringComparison]::Ordinal)) {
    Fail "ProfilePath has an incompatible $Label"
  }
}

function Assert-ExactProfileProperties([object]$Profile, [string[]]$ExpectedNames) {
  $actualNames = @($Profile.PSObject.Properties | ForEach-Object { [string]$_.Name })
  if ($actualNames.Count -ne $ExpectedNames.Count) {
    Fail 'ProfilePath has an inexact property count'
  }
  foreach ($expectedName in $ExpectedNames) {
    $matches = @($actualNames | Where-Object {
      [string]::Equals($_, $expectedName, [StringComparison]::Ordinal)
    })
    if ($matches.Count -ne 1) {
      Fail "ProfilePath is missing exact property $expectedName"
    }
  }
  foreach ($actualName in $actualNames) {
    $matches = @($ExpectedNames | Where-Object {
      [string]::Equals($_, $actualName, [StringComparison]::Ordinal)
    })
    if ($matches.Count -ne 1) {
      Fail "ProfilePath contains unknown property $actualName"
    }
  }
}

function Read-VerifiedProfile([string]$Path) {
  try {
    $profile = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
  } catch {
    Fail 'ProfilePath is not valid JSON'
  }
  Assert-ExactProfileProperties $profile @(
    'schema', 'mode', 'packageName', 'packageFamilyName', 'packagePublisher',
    'packageArchitecture', 'contractId', 'asarPackageName', 'asarProductName',
    'asarMainPath', 'asarMainSha256', 'preloadPath', 'preloadSha256',
    'preloadMarkers', 'pageProtocol', 'notificationEnvelope', 'hookSha256',
    'observerSha256', 'nodePath', 'nodeVersion', 'nodeSha256', 'nodeSigner'
  )
  Assert-ProfileValue $profile.schema 2 'schema'
  Assert-ProfileValue $profile.mode 'read-only-cdp-poc' 'mode'
  Assert-ProfileValue $profile.packageName $ExpectedMainName 'packageName'
  Assert-ProfileValue $profile.packageFamilyName $ExpectedMainFamilyName 'packageFamilyName'
  Assert-ProfileValue $profile.packagePublisher $ExpectedMainPublisher 'packagePublisher'
  Assert-ProfileValue $profile.packageArchitecture $ExpectedMainArchitecture 'packageArchitecture'
  Assert-ProfileValue $profile.contractId $ExpectedContractId 'contractId'
  Assert-ProfileValue $profile.asarPackageName $ExpectedAsarPackageName 'asarPackageName'
  Assert-ProfileValue $profile.asarProductName $ExpectedAsarProductName 'asarProductName'
  Assert-ProfileValue $profile.asarMainPath $ExpectedAsarMainPath 'asarMainPath'
  Assert-ProfileValue $profile.asarMainSha256 $ExpectedAsarMainSha256 'asarMainSha256'
  Assert-ProfileValue $profile.preloadPath $ExpectedPreloadPath 'preloadPath'
  Assert-ProfileValue $profile.preloadSha256 $ExpectedPreloadSha256 'preloadSha256'
  $markers = @($profile.preloadMarkers)
  if ($markers.Count -ne $ExpectedPreloadMarkers.Count) {
    Fail 'ProfilePath has an incompatible preloadMarkers count'
  }
  for ($index = 0; $index -lt $ExpectedPreloadMarkers.Count; $index++) {
    Assert-ProfileValue $markers[$index] $ExpectedPreloadMarkers[$index] "preloadMarkers[$index]"
  }
  Assert-ProfileValue $profile.pageProtocol 'app' 'pageProtocol'
  Assert-ProfileValue $profile.notificationEnvelope 'top' 'notificationEnvelope'
  Assert-ProfileValue $profile.hookSha256 $ExpectedHookSha256 'hookSha256'
  Assert-ProfileValue $profile.observerSha256 $ExpectedObserverSha256 'observerSha256'
  Assert-ProfileValue $profile.nodePath $ExpectedNodePath 'nodePath'
  Assert-ProfileValue $profile.nodeVersion $ExpectedNodeVersion 'nodeVersion'
  Assert-ProfileValue $profile.nodeSha256 $ExpectedNodeSha256 'nodeSha256'
  Assert-ProfileValue $profile.nodeSigner $ExpectedNodeSigner 'nodeSigner'
  return $profile
}

function Get-CodexProcesses {
  return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
      ($_.Name -eq 'ChatGPT.exe' -or $_.Name -eq 'Codex.exe') -and
      ([string]$_.ExecutablePath) -like '*\WindowsApps\OpenAI.Codex_*\app\*'
    })
}

function Get-GuardianProcesses {
  return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'CodexGuardian.exe' })
}

function Get-FrozenFileIdentity([string]$Path, [string]$Label) {
  $resolved = Resolve-RequiredFile $Path $Label
  $item = Get-Item -LiteralPath $resolved -Force
  return [pscustomobject]@{
    Path = $item.FullName
    Length = [long]$item.Length
    LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
    Sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
  }
}

function Assert-FrozenFileIdentity([object]$Expected, [string]$Label) {
  $actual = Get-FrozenFileIdentity ([string]$Expected.Path) $Label
  if (-not [string]::Equals(
        [string]$actual.Path,
        [string]$Expected.Path,
        [StringComparison]::OrdinalIgnoreCase) -or
      [long]$actual.Length -ne [long]$Expected.Length -or
      -not [string]::Equals(
        [string]$actual.LastWriteTimeUtc,
        [string]$Expected.LastWriteTimeUtc,
        [StringComparison]::Ordinal) -or
      -not [string]::Equals(
        [string]$actual.Sha256,
        [string]$Expected.Sha256,
        [StringComparison]::Ordinal)) {
    Fail "$Label changed after the package baseline was frozen"
  }
}

function Read-PackageManifestIdentity([string]$Path) {
  Add-Type -AssemblyName System.Xml.Linq
  $settings = [Xml.XmlReaderSettings]::new()
  $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver = $null
  $reader = [Xml.XmlReader]::Create($Path, $settings)
  try {
    $document = [Xml.Linq.XDocument]::Load($reader, [Xml.Linq.LoadOptions]::None)
  } finally {
    $reader.Dispose()
  }
  $namespaceName = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
  $identityName = [Xml.Linq.XName]::Get('Identity', $namespaceName)
  $identity = $document.Root.Element($identityName)
  if ($null -eq $identity) {
    Fail 'Codex manifest has no package identity'
  }
  return [pscustomobject]@{
    Name = [string]$identity.Attribute([Xml.Linq.XName]::Get('Name')).Value
    Version = [string]$identity.Attribute([Xml.Linq.XName]::Get('Version')).Value
    Publisher = [string]$identity.Attribute([Xml.Linq.XName]::Get('Publisher')).Value
    Architecture = [string]$identity.Attribute(
      [Xml.Linq.XName]::Get('ProcessorArchitecture')).Value
  }
}

function Get-VerifiedMainPackage {
  $mainPackages = @(Get-AppxPackage -Name $ExpectedMainName -ErrorAction SilentlyContinue)
  if ($mainPackages.Count -ne 1) {
    Fail 'exactly one Codex main package must be installed'
  }
  $main = $mainPackages[0]
  if ([string]::IsNullOrWhiteSpace([string]$main.PackageFullName) -or
      [string]$main.PackageFullName -notlike 'OpenAI.Codex_*__2p2nqsd0c76g0' -or
      [string]$main.PackageFamilyName -cne $ExpectedMainFamilyName -or
      [string]$main.Name -cne $ExpectedMainName -or
      [string]::IsNullOrWhiteSpace([string]$main.Version) -or
      [string]$main.Publisher -ne $ExpectedMainPublisher -or
      -not [string]::Equals(
        [string]$main.Architecture,
        $ExpectedMainArchitecture,
        [StringComparison]::OrdinalIgnoreCase) -or
      [string]$main.Status -ne 'Ok') {
    Fail 'the installed Codex main package does not match the stable package policy'
  }
  if ([string]$main.SignatureKind -ne 'Store') {
    Fail 'the read-only PoC requires Store origin until a signed-patch capability lease is implemented'
  }

  $manifest = Join-Path $main.InstallLocation 'AppxManifest.xml'
  $executable = Join-Path $main.InstallLocation 'app\ChatGPT.exe'
  $codexExecutable = Join-Path $main.InstallLocation 'app\resources\codex.exe'
  $mainAsar = Join-Path $main.InstallLocation 'app\resources\app.asar'
  $manifestIdentity = Read-PackageManifestIdentity $manifest
  if ([string]$manifestIdentity.Name -cne [string]$main.Name -or
      [string]$manifestIdentity.Version -cne [string]$main.Version -or
      [string]$manifestIdentity.Publisher -cne [string]$main.Publisher -or
      -not [string]::Equals(
        [string]$manifestIdentity.Architecture,
        [string]$main.Architecture,
        [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'the observed AppModel package and manifest identities disagree'
  }

  $artifacts = [ordered]@{
    Manifest = Get-FrozenFileIdentity $manifest 'Codex AppxManifest.xml'
    ChatGptExecutable = Get-FrozenFileIdentity $executable 'Codex ChatGPT.exe'
    CodexExecutable = Get-FrozenFileIdentity $codexExecutable 'Codex codex.exe'
    AppAsar = Get-FrozenFileIdentity $mainAsar 'Codex app.asar'
  }

  return [pscustomobject]@{
    Package = $main
    PackageFullName = [string]$main.PackageFullName
    PackageVersion = [string]$main.Version
    Executable = $executable
    InstallRoot = [IO.Path]::GetFullPath($main.InstallLocation).TrimEnd('\')
    Artifacts = $artifacts
  }
}

function Assert-PackageBaselineUnchanged([object]$Baseline) {
  $current = @(Get-AppxPackage -Name $ExpectedMainName -ErrorAction SilentlyContinue)
  if ($current.Count -ne 1 -or
      [string]$current[0].PackageFullName -cne [string]$Baseline.PackageFullName -or
      [string]$current[0].Version -cne [string]$Baseline.PackageVersion -or
      [string]$current[0].PackageFamilyName -cne $ExpectedMainFamilyName -or
      [string]$current[0].Publisher -cne $ExpectedMainPublisher -or
      [string]$current[0].SignatureKind -cne 'Store' -or
      [string]$current[0].Status -cne 'Ok' -or
      -not [string]::Equals(
        [IO.Path]::GetFullPath([string]$current[0].InstallLocation).TrimEnd('\'),
        [string]$Baseline.InstallRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'the observed Codex package registration changed after baseline freeze'
  }
  foreach ($entry in $Baseline.Artifacts.GetEnumerator()) {
    Assert-FrozenFileIdentity $entry.Value ("Codex package artifact " + $entry.Key)
  }
}

function Get-VerifiedNode {
  $node = Resolve-RequiredFile $ExpectedNodePath 'node.exe'
  Assert-FileHash $node $ExpectedNodeSha256 'node.exe'
  $signature = Get-AuthenticodeSignature -LiteralPath $node
  if ([string]$signature.Status -ne 'Valid' -or
      [string]$signature.SignerCertificate.Subject -ne $ExpectedNodeSigner) {
    Fail 'node.exe signature does not match the pinned OpenJS runtime'
  }
  $version = (& $node --version).Trim()
  if ($LASTEXITCODE -ne 0 -or $version -ne "v$ExpectedNodeVersion") {
    Fail 'node.exe version does not match the pinned CDP profile'
  }
  return $node
}

function Resolve-SafeLogPath([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
    Fail 'LogPath must be absolute'
  }
  $root = [IO.Path]::GetFullPath($ExpectedLogRoot).TrimEnd('\')
  $fullPath = [IO.Path]::GetFullPath($Path)
  if (-not $fullPath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'LogPath must remain inside the pinned r13 data directory'
  }
  $directory = Split-Path -Parent $fullPath
  New-Item -ItemType Directory -Force -Path $directory | Out-Null
  $directoryItem = Get-Item -LiteralPath $directory -Force
  if ($directoryItem.LinkType -or
      (($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    Fail 'LogPath directory must not be a link or reparse point'
  }
  if (Test-Path -LiteralPath $fullPath) {
    $logItem = Get-Item -LiteralPath $fullPath -Force
    if ($logItem.PSIsContainer -or $logItem.LinkType -or
        (($logItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
      Fail 'LogPath must be a regular non-linked file'
    }
  }
  return $fullPath
}

function Get-LoopbackPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  try {
    $listener.Start()
    return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
  } finally {
    $listener.Stop()
  }
}

function Test-ProcessTreeContains(
  [int]$CandidateProcessId,
  [int]$RootProcessId,
  [object[]]$Processes
) {
  $parents = @{}
  foreach ($process in $Processes) {
    $parents[[int]$process.ProcessId] = [int]$process.ParentProcessId
  }
  $current = $CandidateProcessId
  for ($depth = 0; $depth -lt 64 -and $current -gt 0; $depth++) {
    if ($current -eq $RootProcessId) {
      return $true
    }
    if (-not $parents.ContainsKey($current)) {
      return $false
    }
    $current = [int]$parents[$current]
  }
  return $false
}

function Get-VerifiedTestProcessTree(
  [int]$RootProcessId,
  [string]$ExpectedRootExecutable,
  [DateTime]$LaunchedAfterUtc,
  [switch]$AllowMissingRoot
) {
  $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
  $root = @($processes | Where-Object { [int]$_.ProcessId -eq $RootProcessId })
  if ($root.Count -eq 0) {
    if ($AllowMissingRoot) {
      return @()
    }
    Fail 'the launched Codex root process disappeared before ownership verification'
  }
  if ($root.Count -ne 1 -or
      -not [string]::Equals(
        [IO.Path]::GetFullPath([string]$root[0].ExecutablePath),
        [IO.Path]::GetFullPath($ExpectedRootExecutable),
        [StringComparison]::OrdinalIgnoreCase) -or
      ([DateTime]$root[0].CreationDate).ToUniversalTime() -lt $LaunchedAfterUtc.AddSeconds(-2)) {
    Fail 'the launched Codex root process identity did not match the pinned executable'
  }
  return @($processes | Where-Object {
    Test-ProcessTreeContains `
      -CandidateProcessId ([int]$_.ProcessId) `
      -RootProcessId $RootProcessId `
      -Processes $processes
  })
}

function Wait-ForOwnedLoopbackListener(
  [int]$Port,
  [int]$RootProcessId,
  [string]$ExpectedRootExecutable,
  [DateTime]$LaunchedAfterUtc,
  [int]$TimeoutSeconds = 30
) {
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    $listeners = @(Get-NetTCPConnection `
      -State Listen `
      -LocalPort $Port `
      -ErrorAction SilentlyContinue |
      Where-Object { [string]$_.LocalAddress -eq '127.0.0.1' })
    if ($listeners.Count -gt 0) {
      $processes = @(Get-VerifiedTestProcessTree `
        -RootProcessId $RootProcessId `
        -ExpectedRootExecutable $ExpectedRootExecutable `
        -LaunchedAfterUtc $LaunchedAfterUtc)
      $unexpected = @($listeners | Where-Object {
        -not (Test-ProcessTreeContains `
          -CandidateProcessId ([int]$_.OwningProcess) `
          -RootProcessId $RootProcessId `
          -Processes $processes)
      })
      if ($unexpected.Count -gt 0) {
        Fail 'the random CDP port was claimed by a process outside the launched Codex tree'
      }
      return
    }
    Start-Sleep -Milliseconds 100
  }
  Fail 'the launched Codex process did not open its verified loopback CDP listener'
}

function Stop-TestProcessTree(
  [int]$RootProcessId,
  [string]$ExpectedRootExecutable,
  [DateTime]$LaunchedAfterUtc
) {
  $tree = @(Get-VerifiedTestProcessTree `
    -RootProcessId $RootProcessId `
    -ExpectedRootExecutable $ExpectedRootExecutable `
    -LaunchedAfterUtc $LaunchedAfterUtc `
    -AllowMissingRoot)
  if ($tree.Count -eq 0) {
    return
  }
  $treeIds = @($tree | ForEach-Object { [int]$_.ProcessId })
  foreach ($processId in @($treeIds | Where-Object { $_ -ne $RootProcessId })) {
    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
  }
  Stop-Process -Id $RootProcessId -Force -ErrorAction SilentlyContinue

  $deadline = [DateTime]::UtcNow.AddSeconds(15)
  do {
    $remaining = @(Get-Process -Id $treeIds -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
      return
    }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $deadline)
  Fail 'the verified CDP test process tree did not stop'
}

function Restart-WithoutCdp(
  [int]$RootProcessId,
  [string]$ExpectedRootExecutable,
  [DateTime]$LaunchedAfterUtc,
  [object]$Baseline
) {
  Write-Host '[CodexGuardian] Closing only the verified short-lived CDP test process tree.'
  Stop-TestProcessTree `
    -RootProcessId $RootProcessId `
    -ExpectedRootExecutable $ExpectedRootExecutable `
    -LaunchedAfterUtc $LaunchedAfterUtc

  $debugProcesses = @(Get-CodexProcesses | Where-Object {
    [string]$_.CommandLine -match '--remote-debugging-(?:address|port|pipe)'
  })
  if ($debugProcesses.Count -ne 0) {
    Fail 'a Codex process with a CDP argument remains; close it manually before continuing'
  }

  Assert-PackageBaselineUnchanged $Baseline
  Write-Host '[CodexGuardian] Relaunching the unchanged stock Codex package without CDP.'
  $explorer = Join-Path $env:WINDIR 'explorer.exe'
  Start-Process `
    -FilePath $explorer `
    -ArgumentList 'shell:AppsFolder\OpenAI.Codex_2p2nqsd0c76g0!App'

  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do {
    Start-Sleep -Milliseconds 200
    $stockProcesses = @(Get-CodexProcesses)
  } while ($stockProcesses.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)
  if ($stockProcesses.Count -eq 0 -or @($stockProcesses | Where-Object {
      [string]$_.CommandLine -match '--remote-debugging-(?:address|port|pipe)'
    }).Count -ne 0) {
    Fail 'stock Codex did not restart cleanly without a CDP argument'
  }
  Assert-PackageBaselineUnchanged $Baseline
}

$observer = Resolve-RequiredFile $ObserverPath 'ObserverPath'
$hook = Resolve-RequiredFile $HookPath 'HookPath'
$profilePathResolved = Resolve-RequiredFile $ProfilePath 'ProfilePath'
Assert-FileHash $observer $ExpectedObserverSha256 'ObserverPath'
Assert-FileHash $hook $ExpectedHookSha256 'HookPath'
Assert-FileHash $profilePathResolved $ExpectedProfileSha256 'ProfilePath'
Read-VerifiedProfile $profilePathResolved | Out-Null
$node = Get-VerifiedNode
$log = Resolve-SafeLogPath $LogPath

if (@(Get-CodexProcesses).Count -ne 0) {
  Fail 'exit every Codex window before starting the CDP observation PoC'
}
if (@(Get-GuardianProcesses).Count -ne 0) {
  Fail 'exit every CodexGuardian window before starting the CDP observation PoC'
}

$baseline = Get-VerifiedMainPackage
$port = Get-LoopbackPort
$launchNotBeforeUtc = [DateTime]::UtcNow

Assert-PackageBaselineUnchanged $baseline
Write-Host "[CodexGuardian] Launching the unchanged Codex package with loopback CDP on port $port."
$codex = Start-Process `
  -FilePath $baseline.Executable `
  -ArgumentList @(
    '--remote-debugging-address=127.0.0.1',
    "--remote-debugging-port=$port"
  ) `
  -PassThru

$observerFailure = $null
$restartFailure = $null
try {
  Get-VerifiedTestProcessTree `
    -RootProcessId $codex.Id `
    -ExpectedRootExecutable $baseline.Executable `
    -LaunchedAfterUtc $launchNotBeforeUtc | Out-Null
  Wait-ForOwnedLoopbackListener `
    -Port $port `
    -RootProcessId $codex.Id `
    -ExpectedRootExecutable $baseline.Executable `
    -LaunchedAfterUtc $launchNotBeforeUtc
  Assert-PackageBaselineUnchanged $baseline
  & $node `
    $observer `
    --port $port `
    --hook $hook `
    --log $log `
    --duration-seconds $DurationSeconds
  if ($LASTEXITCODE -ne 0) {
    Fail "CDP observer exited with code $LASTEXITCODE"
  }
} catch {
  $observerFailure = $_
  Write-Host "[CodexGuardian] $($_.Exception.Message)" -ForegroundColor Red
} finally {
  try {
    Restart-WithoutCdp `
      -RootProcessId $codex.Id `
      -ExpectedRootExecutable $baseline.Executable `
      -LaunchedAfterUtc $launchNotBeforeUtc `
      -Baseline $baseline
  } catch {
    $restartFailure = $_
    Write-Host "[CodexGuardian] cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
  }
}
if ($restartFailure -ne $null) {
  throw $restartFailure
}
if ($observerFailure -ne $null) {
  throw $observerFailure
}
