# ChatGPT handoff: final Tudor pairing export on Windows

Give this file, the complete PowerShell output, and the generated diagnostic
text file to ChatGPT when troubleshooting on Windows. Do not paste the contents
of `HostPartitionExportV1.json` or `PairingBundleV1.json` unless necessary;
they contain private pairing material.

## Objective and current state

- Sensor: Synaptics Tudor `USB VID_06CB&PID_00C9`.
- Existing Windows Hello pairing and enrollments must remain unchanged.
- Windows driver: Synaptics `6.0.44.1111`.
- Required driver DLL SHA-256:
  `da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60`.
- Linux has already performed one read-only 4096-byte host-partition read.
- `HostPartitionExportV1.json` passed offline framing and hash validation.
- The expected USB serial is read from `HostPartitionExportV1.json` and must
  match `tudor-00c9-driver-metadata.json` case-insensitively. Never substitute
  a serial copied from another machine.
- The expected private sensor identity is decoded from
  `HostPartitionExportV1.json`. Its uppercase hexadecimal form must name the
  zero-length value under
  `HKEY_USERS\S-1-5-19\Software\Synaptics\PairingData`.
- Encrypted-wrapper component lengths are validated from their little-endian
  header. Do not hardcode lengths observed on another machine. The decrypted
  pairing container must be exactly 1284 bytes.

The active pairing is encrypted with Windows DPAPI in the
`NT AUTHORITY\LOCAL SERVICE` user context. `Complete-PairingExport.ps1`
creates a temporary scheduled task as Local Service, decrypts the copied blob,
validates its integrity and exact 1284-byte plaintext size, converts it to
`PairingBundleV1.json`, then deletes the temporary task and plaintext.

The scripts do not call the sensor, driver, Device Manager, firmware tools, or
registry-write APIs.

## Absolute safety limits

Do not suggest or run any of the following:

- USB or sensor reset;
- forced TLS close or a raw sensor command;
- pairing or re-pairing;
- enrollment, deletion, cleanup, or formatting;
- firmware installation or update;
- registry writes to Synaptics pairing keys;
- disabling, enabling, uninstalling, or repairing the biometric device;
- BIOS fingerprint reset or recovery.

Troubleshooting must remain limited to local files, ACLs, PowerShell syntax,
DPAPI execution context, and the temporary scheduled task.

## Required files in one directory

```text
HostPartitionExportV1.json
Collect-DriverMetadata.ps1
Complete-PairingExport.ps1
Export-Pairing.ps1
```

Use these files from the same current repository revision. Do not use or
combine scripts from historical `TudorFinalWindowsExport*.zip` archives.

Two PowerShell-specific converter bugs are fixed in the current scripts: the
product-ID parameter is named `$ProductId` rather than the reserved automatic
variable `$PID`, and parsed TLV tags/lengths are normalized to `Int32` before
hashtable lookups. Do not revert either correction.

## Exact Administrator PowerShell procedure

The files in this example are on the Desktop. `$HostExport` is used
deliberately: `$input` is an automatic PowerShell variable and variable names
are case-insensitive.

```powershell
$Work = "$env:USERPROFILE\Desktop"
cd $Work
Set-ExecutionPolicy -Scope Process Bypass

.\Collect-DriverMetadata.ps1

$HostExport = "$Work\HostPartitionExportV1.json"
$Metadata = "$env:USERPROFILE\Documents\tudor-00c9-driver-metadata.json"
$Bundle = "$env:USERPROFILE\Documents\PairingBundleV1.json"

.\Complete-PairingExport.ps1 `
  -HostPartitionExport $HostExport `
  -DriverMetadata $Metadata `
  -Output $Bundle

Get-Item -LiteralPath $Bundle | Format-List FullName,Length
```

On success, lock Windows with `Win+L` and perform two ordinary fingerprint
unlocks. Then return `PairingBundleV1.json` to Linux without printing it.

For subsequent Windows-to-Linux transitions, close applications and use a
complete shutdown rather than Restart:

```powershell
shutdown.exe /s /t 0
```

Wait about 30 seconds after power-off before starting Linux. Do not propose a
sensor reset or forced TLS close as a substitute.

## Diagnostics

Every controller run creates an owner-only report in Documents:

```text
TudorPairingExport-diagnostic-YYYYMMDD-HHMMSS.txt
```

Display the newest report with:

```powershell
$Diagnostic = Get-ChildItem "$env:USERPROFILE\Documents\TudorPairingExport-diagnostic-*.txt" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
$Diagnostic | Format-List FullName,Length,LastWriteTime
Get-Content -LiteralPath $Diagnostic.FullName
```

The Local Service worker returns classified task results:

| Result | Meaning |
|---:|---|
| 10 | Worker manifest could not be loaded or parsed |
| 11 | Wrapped blob could not be read or its SHA-256 changed |
| 12 | Secure-wrapper header or lengths are invalid |
| 20 | Local Service DPAPI could not decrypt pairing data |
| 21 | Local Service DPAPI could not decrypt the protected hash |
| 22 | Decrypted integrity hash mismatch |
| 23 | Decrypted pairing container is not exactly 1284 bytes |
| 30 | Local Service could not write `pairing-data.bin` in staging |

The controller reports validation failures directly, including mismatched
format, VID/PID, USB serial, driver version/hash, registry identity, output
directory, timeout, task result, plaintext size, certificate framing, and
pairing-container tags.

Useful read-only checks are:

```powershell
Get-Item .\HostPartitionExportV1.json,
  .\Collect-DriverMetadata.ps1,
  .\Complete-PairingExport.ps1,
  .\Export-Pairing.ps1 | Format-Table Name,Length,LastWriteTime

Get-Content -Raw "$env:USERPROFILE\Documents\tudor-00c9-driver-metadata.json"

Get-Acl -LiteralPath $Work | Format-List Owner,AreAccessRulesProtected,Access
```

If the script fails, preserve the exact console output and diagnostic report.
Do not work around an identity, integrity, certificate, DPAPI, or driver-hash
failure. Only PowerShell syntax, task execution, and staging ACL problems may
be corrected, and corrections must not add any sensor operation.
