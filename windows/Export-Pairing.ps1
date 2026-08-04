[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PairingContainer,
    [Parameter(Mandatory)][string]$PrivateSensorIdentity,
    [Parameter(Mandatory)][string]$UsbSerial,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(0,65535)][int]$Vid = 0x06cb,
    [ValidateRange(0,65535)][int]$ProductId = 0x00c9
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-RestrictedBytes([string]$Path, [int]$ExpectedLength, [string]$Label) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $acl = Get-Acl -LiteralPath $resolved
    if (-not $acl.AreAccessRulesProtected) {
        throw "$Label inherits ACL entries; restrict the temporary file before use"
    }
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') # Everyone/Auth Users/Users
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq 'Allow' -and
            $broad -contains $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value) {
            throw "$Label grants access to a broad Windows group"
        }
    }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($resolved)
    if ($ExpectedLength -gt 0 -and $bytes.Length -ne $ExpectedLength) {
        throw "$Label must contain exactly $ExpectedLength bytes (got $($bytes.Length))"
    }
    return ,$bytes
}

function Set-OwnerOnlyAcl([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

[byte[]]$container = Read-RestrictedBytes $PairingContainer 0 'pairing container'
[byte[]]$identity = Read-RestrictedBytes $PrivateSensorIdentity 0 'private sensor identity'
if ($identity.Length -eq 6) {
    # GET_VERSION carries six identity bytes. The driver/prototype normalize
    # this to the eight-byte private identity by appending two zero bytes.
    [byte[]]$identity = $identity + [byte[]](0, 0)
} elseif ($identity.Length -ne 8) {
    throw "Private sensor identity must contain exactly 6 or 8 bytes; got $($identity.Length)."
}

# Decrypted pairing data is a strict little-endian <uint16 tag, uint32 length,
# bytes> stream. Tags 0-3 form PairingBundleV1. Vendor builds may also carry
# tag 4 (public-key security data) and tag 5 (storage PSK identifier); validate
# their framing but never export them. Reject every other tag.
$values = @{}
$offset = 0
while ($offset -lt $container.Length) {
    if ($container.Length - $offset -lt 6) { throw 'truncated pairing-container header' }
    [int]$tag = [BitConverter]::ToUInt16($container, $offset)
    [int]$length = [BitConverter]::ToUInt32($container, $offset + 2)
    $offset += 6
    if ($tag -gt 5) { throw "unknown pairing-container tag $tag" }
    if ($values.ContainsKey($tag)) { throw "duplicate pairing-container tag $tag" }
    if ($length -eq 0) { throw "empty pairing-container tag $tag" }
    if ($length -gt $container.Length - $offset) { throw "truncated pairing-container tag $tag" }
    [byte[]]$value = $container[$offset..($offset + $length - 1)]
    $values[$tag] = $value
    $offset += $length
}
foreach ($required in 0..3) {
    if (-not $values.ContainsKey($required)) { throw "missing pairing-container tag $required" }
}
if ($values[0].Length -ne 2 -or $values[0][0] -ne 0 -or $values[0][1] -ne 0) {
    throw 'unsupported pairing-container version'
}
[byte[]]$host = $values[1]
[byte[]]$scalar = $values[2]
[byte[]]$sensor = $values[3]
if ($scalar.Length -ne 32) { throw 'private scalar must contain exactly 32 bytes' }
if ($host.Length -ne 400) { throw 'host certificate must contain exactly 400 bytes' }
if ($sensor.Length -ne 400) { throw 'sensor certificate must contain exactly 400 bytes' }
# palCryptoEccExportPrivateKey stores the scalar little-endian; bundle V1 is
# canonical big-endian.
[array]::Reverse($scalar)

# Structural framing checks only. Linux audit-pairing performs elliptic-curve
# key correspondence and firmware signing-key verification before import.
function Assert-Certificate([byte[]]$Certificate, [string]$Label) {
    if ([BitConverter]::ToUInt16($Certificate, 0) -ne 0x5f3f) { throw "$Label certificate magic mismatch" }
    if ([BitConverter]::ToUInt16($Certificate, 2) -ne 23) { throw "$Label certificate curve mismatch" }
    if ([BitConverter]::ToUInt16($Certificate, 142) -gt 256) { throw "$Label certificate signature is oversized" }
}
Assert-Certificate $host 'host'
Assert-Certificate $sensor 'sensor'

$bundle = [ordered]@{
    format = 'PairingBundleV1'
    vid = $Vid
    pid = $ProductId
    usb_serial = $UsbSerial
    private_sensor_identity = [Convert]::ToBase64String($identity)
    host_private_scalar = [Convert]::ToBase64String($scalar)
    host_certificate = [Convert]::ToBase64String($host)
    sensor_certificate = [Convert]::ToBase64String($sensor)
}
$json = $bundle | ConvertTo-Json -Depth 3
$target = [IO.Path]::GetFullPath($Output)
$directory = [IO.Path]::GetDirectoryName($target)
if (-not [IO.Directory]::Exists($directory)) { throw "output directory does not exist: $directory" }
$temporary = Join-Path $directory ('.pairing-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine,
                            [Text.UTF8Encoding]::new($false))
    Set-OwnerOnlyAcl $temporary
    # The File.Move(source, destination, overwrite) overload is unavailable in
    # Windows PowerShell 5.1's .NET Framework. File.Replace remains atomic when
    # the destination exists; otherwise the two-argument Move is atomic.
    if ([IO.File]::Exists($target)) {
        [IO.File]::Replace($temporary, $target, $null)
    } else {
        [IO.File]::Move($temporary, $target)
    }
    Set-OwnerOnlyAcl $target
} finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    [Array]::Clear($scalar, 0, $scalar.Length)
    [Array]::Clear($container, 0, $container.Length)
}
Write-Host "Wrote PairingBundleV1 with owner-only ACL: $target"
Write-Host 'No sensor API was called. Validate this bundle offline in Linux before use.'
