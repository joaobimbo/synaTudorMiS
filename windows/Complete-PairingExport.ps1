[CmdletBinding(DefaultParameterSetName='Controller')]
param(
    [Parameter(Mandatory, ParameterSetName='Controller')][string]$HostPartitionExport,
    [Parameter(Mandatory, ParameterSetName='Controller')][string]$DriverMetadata,
    [Parameter(Mandatory, ParameterSetName='Controller')][string]$Output,
    [Parameter(Mandatory, ParameterSetName='Worker')][switch]$Worker,
    [Parameter(Mandatory, ParameterSetName='Worker')][string]$WorkerManifest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Set-FileOwnerOnly([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-StagingAcl([string]$Path, [Security.Principal.SecurityIdentifier]$UserSid) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($UserSid)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [Security.AccessControl.PropagationFlags]::None
    foreach ($sidText in @($UserSid.Value, 'S-1-5-18', 'S-1-5-19')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit, $propagate,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Read-LeUInt32([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) { throw 'truncated uint32' }
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Test-EqualBytes([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }
    return $difference -eq 0
}

function Get-WorkerFailureMessage([int]$Code) {
    switch ($Code) {
        10 { return 'could not load or parse the Local Service worker manifest' }
        11 { return 'could not read the wrapped pairing blob, or its SHA-256 changed' }
        12 { return 'the Windows secure-wrapper header or lengths are invalid' }
        20 { return 'DPAPI could not decrypt the pairing data as Local Service' }
        21 { return 'DPAPI could not decrypt the protected integrity hash as Local Service' }
        22 { return 'the decrypted integrity hash does not match the wrapped pairing data' }
        23 { return 'the decrypted pairing container is not exactly 1284 bytes' }
        30 { return 'Local Service could not write pairing-data.bin in the staging directory' }
        default { return 'the worker failed before returning a classified result' }
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Worker') {
    $workerExitCode = 10
    try {
        Add-Type -AssemblyName System.Security
        $manifestPath = (Resolve-Path -LiteralPath $WorkerManifest).Path
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        if ($manifest.format -ne 'TudorLocalServiceWorkerV1') {
            throw 'worker manifest format mismatch'
        }

        $workerExitCode = 11
        [byte[]]$wrapped = [IO.File]::ReadAllBytes([string]$manifest.wrapped_path)
        $actualWrappedHash = ([Security.Cryptography.SHA256]::Create().ComputeHash($wrapped) |
            ForEach-Object { $_.ToString('x2') }) -join ''
        if ($actualWrappedHash -ne [string]$manifest.wrapped_sha256) {
            throw 'wrapped-pairing SHA-256 mismatch'
        }

        $workerExitCode = 12
        if ($wrapped.Length -lt 16) { throw 'truncated secure wrapper' }
        $version = Read-LeUInt32 $wrapped 0
        $clearLength = Read-LeUInt32 $wrapped 4
        $protectedLength = Read-LeUInt32 $wrapped 8
        $hashLength = Read-LeUInt32 $wrapped 12
        if ($version -ne 1 -or $clearLength -ne 0) { throw 'unsupported secure wrapper' }
        if (16 + $clearLength + $protectedLength + $hashLength -ne $wrapped.Length) {
            throw 'secure-wrapper lengths are inconsistent'
        }
        if ($protectedLength -eq 0 -or $hashLength -eq 0) { throw 'empty protected region' }
        [byte[]]$protected = $wrapped[16..(15 + $protectedLength)]
        [byte[]]$protectedHash = $wrapped[(16 + $protectedLength)..($wrapped.Length - 1)]

        $workerExitCode = 20
        [byte[]]$plain = [Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)

        $workerExitCode = 21
        [byte[]]$expectedHash = [Security.Cryptography.ProtectedData]::Unprotect(
            $protectedHash, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)

        $workerExitCode = 22
        $hashInput = [byte[]]::new(16 + $protectedLength)
        [Array]::Copy($wrapped, 0, $hashInput, 0, $hashInput.Length)
        [byte[]]$actualHash = [Security.Cryptography.SHA256]::Create().ComputeHash($hashInput)
        if (-not (Test-EqualBytes $actualHash $expectedHash)) {
            throw 'secure-wrapper integrity hash mismatch'
        }

        $workerExitCode = 23
        if ($plain.Length -ne 0x504) {
            throw "decrypted pairing container must be 1284 bytes; got $($plain.Length)"
        }

        $workerExitCode = 30
        [IO.File]::WriteAllBytes([string]$manifest.plaintext_path, $plain)
        [Array]::Clear($plain, 0, $plain.Length)
        exit 0
    } catch {
        exit $workerExitCode
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from PowerShell as Administrator.'
}
$diagnosticPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) `
    ('TudorPairingExport-diagnostic-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
Write-Utf8NoBom $diagnosticPath ''
Set-FileOwnerOnly $diagnosticPath
Start-Transcript -LiteralPath $diagnosticPath -Append | Out-Null
try {
$source = Get-Content -Raw -LiteralPath (Resolve-Path -LiteralPath $HostPartitionExport) |
    ConvertFrom-Json
$metadata = Get-Content -Raw -LiteralPath (Resolve-Path -LiteralPath $DriverMetadata) |
    ConvertFrom-Json
if ($source.format -ne 'HostPartitionExportV1') { throw 'input format must be HostPartitionExportV1' }
if ($metadata.format -ne 'TudorDriverMetadataV1') { throw 'driver metadata format mismatch' }
if ([int]$source.vid -ne 0x06cb -or [int]$source.pid -ne 0x00c9) { throw 'VID/PID mismatch' }
if ([string]$source.usb_serial -ne [string]$metadata.usb_serial) { throw 'USB serial mismatch' }
if ([string]$metadata.driver_version -ne '6.0.44.1111' -or
    [string]$metadata.dll_sha256 -ne 'da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60') {
    throw 'installed driver version or DLL hash is not the audited build'
}
[byte[]]$privateIdentity = [Convert]::FromBase64String([string]$source.private_sensor_identity)
[byte[]]$wrappedPairing = [Convert]::FromBase64String([string]$source.wrapped_pairing)
if ($privateIdentity.Length -ne 8) { throw 'private identity must be exactly eight bytes' }
$identityHex = ($privateIdentity | ForEach-Object { $_.ToString('X2') }) -join ''
$registry = [Microsoft.Win32.Registry]::Users.OpenSubKey(
    'S-1-5-19\Software\Synaptics\PairingData', $false)
if ($null -eq $registry) { throw 'Local Service PairingData registry key is missing' }
try {
    if ($registry.GetValueNames() -notcontains $identityHex) {
        throw "registry identity $identityHex is missing"
    }
    [byte[]]$slot = $registry.GetValue($identityHex, $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -eq $slot -or $slot.Length -ne 0) {
        throw 'expected the registry pairing fallback value to be zero bytes'
    }
} finally {
    $registry.Dispose()
}

$controllerPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
$converterPath = Join-Path (Split-Path -Parent $controllerPath) 'Export-Pairing.ps1'
if (-not (Test-Path -LiteralPath $converterPath -PathType Leaf)) {
    throw "Export-Pairing.ps1 must be beside this script: $converterPath"
}
$target = [IO.Path]::GetFullPath($Output)
$targetDirectory = [IO.Path]::GetDirectoryName($target)
if (-not [IO.Directory]::Exists($targetDirectory)) { throw "output directory is missing: $targetDirectory" }
$taskName = 'TudorPairingDecrypt-' + [Guid]::NewGuid().ToString('N')
$staging = Join-Path $env:ProgramData $taskName
[IO.Directory]::CreateDirectory($staging) | Out-Null
Set-StagingAcl $staging $identity.User
$workerScript = Join-Path $staging 'Complete-PairingExport.ps1'
$manifestPath = Join-Path $staging 'worker.json'
$wrappedPath = Join-Path $staging 'wrapped.bin'
$plainPath = Join-Path $staging 'pairing-data.bin'
try {
    Copy-Item -LiteralPath $controllerPath -Destination $workerScript
    [IO.File]::WriteAllBytes($wrappedPath, $wrappedPairing)
    $wrappedHash = ([Security.Cryptography.SHA256]::Create().ComputeHash($wrappedPairing) |
        ForEach-Object { $_.ToString('x2') }) -join ''
    $manifest = [ordered]@{
        format = 'TudorLocalServiceWorkerV1'
        wrapped_path = $wrappedPath
        wrapped_sha256 = $wrappedHash
        plaintext_path = $plainPath
    } | ConvertTo-Json
    Write-Utf8NoBom $manifestPath $manifest
    foreach ($path in @($workerScript, $manifestPath, $wrappedPath)) {
        if ([IO.Path]::GetFullPath($path).Contains('"')) { throw 'quoted paths are unsupported' }
    }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $workerScript + '" -Worker -WorkerManifest "' + $manifestPath + '"'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' `
        -LogonType ServiceAccount -RunLevel Limited
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
    $startedAt = Get-Date
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 250
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $state = (Get-ScheduledTask -TaskName $taskName).State
        $hasRun = $info.LastRunTime -ge $startedAt.AddSeconds(-1)
    } while ((-not $hasRun -or $state -eq 'Running') -and
             [DateTime]::UtcNow -lt $deadline)
    if (-not $hasRun -or $state -eq 'Running') { throw 'Local Service worker timed out' }
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if ($info.LastTaskResult -ne 0) {
        $workerFailure = Get-WorkerFailureMessage ([int]$info.LastTaskResult)
        throw "Local Service worker result $($info.LastTaskResult): $workerFailure."
    }
    if (-not (Test-Path -LiteralPath $plainPath -PathType Leaf) -or
        (Get-Item -LiteralPath $plainPath).Length -ne 0x504) {
        throw 'Local Service worker returned success without a 1284-byte pairing container'
    }
    Set-FileOwnerOnly $plainPath
    $identityPath = Join-Path $staging 'private-identity.bin'
    [IO.File]::WriteAllBytes($identityPath, $privateIdentity)
    Set-FileOwnerOnly $identityPath
    & $converterPath -PairingContainer $plainPath `
        -PrivateSensorIdentity $identityPath -UsbSerial ([string]$source.usb_serial) `
        -Output $target -Vid 0x06cb -ProductId 0x00c9
    Write-Host "Completed PairingBundleV1: $target"
    Write-Host 'No sensor API or driver operation was performed.'
} finally {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($staging)) {
        try {
            [IO.Directory]::Delete($staging, $true)
        } catch {
            Write-Warning "Could not remove temporary staging directory $staging`: $($_.Exception.Message)"
        }
    }
    [Array]::Clear($wrappedPairing, 0, $wrappedPairing.Length)
}
} catch {
    Write-Host "EXPORT FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Diagnostic report: $diagnosticPath" -ForegroundColor Yellow
    throw
} finally {
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    Set-FileOwnerOnly $diagnosticPath
}
