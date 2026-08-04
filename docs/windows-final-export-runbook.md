# Windows pairing export from zero

This is the complete procedure for a `06cb:00c9` sensor whose installed
Windows driver exactly matches the audited build below. It is not valid for a
different driver version or DLL hash:

- Windows driver: Synaptics 6.0.44.1111
- DLL: `synaWudfBioUsb111.dll`
- required SHA-256: `da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60`

From zero, this requires an initial Windows baseline, one Linux read, and one
final Windows export. All remaining Windows work after the Linux read is done
in a single boot. If a stated check fails, stop. Do not reset, disable, repair,
re-pair, update, recover, or remove the sensor.

## 1. Put the scripts on Windows

Copy these three repository files from the same revision to
`%USERPROFILE%\Desktop`:

```text
windows\Collect-DriverMetadata.ps1
windows\Export-Pairing.ps1
windows\Complete-PairingExport.ps1
```

`Prepare-PairingExport.ps1` belongs to the withdrawn debugger-based workflow
and is not part of this procedure.

## 2. Record the Windows baseline

Open an ordinary PowerShell window and run:

```powershell
$Devices = @(Get-PnpDevice -PresentOnly |
  Where-Object InstanceId -Like 'USB\VID_06CB&PID_00C9\*')
if ($Devices.Count -ne 1) {
  throw "Expected exactly one present 06cb:00c9 sensor; found $($Devices.Count)"
}
$Instance = $Devices[0].InstanceId
$UsbSerial = ($Instance -split '\\')[-1]
if (-not $UsbSerial) { throw 'The USB instance ID has no serial component' }
$StableId = "06cb-00c9-$UsbSerial"
$Instance
$UsbSerial
$StableId
$Baseline = "$env:USERPROFILE\Documents\tudor-00c9-windows-baseline.txt"

@(
  'Baseline: before Linux sensor access'
  "Recorded: $(Get-Date -Format o)"
  "Windows: $([Environment]::OSVersion.VersionString)"
  "Computer: $env:COMPUTERNAME"
  'Sensor changes performed: none'
  ''
) | Set-Content -LiteralPath $Baseline -Encoding utf8

Get-PnpDevice -InstanceId $Instance |
  Format-List Status,Class,FriendlyName,InstanceId |
  Out-String | Add-Content -LiteralPath $Baseline
```

Lock the computer with `Win+L`, then unlock with the normally enrolled finger.
Repeat once. Both attempts must succeed. Append the result:

```powershell
@(
  ''
  'Windows Hello test: PASS'
  "Test time: $(Get-Date -Format o)"
  'Method: lock screen followed by ordinary fingerprint unlock'
  'Finger: normally enrolled finger'
  'Attempts: 1'
  'Unexpected messages: none'
  'Repeat Windows Hello test: PASS'
  "Repeat time: $(Get-Date -Format o)"
  'Sensor pairing/enrollment/storage changed: no'
) | Add-Content -LiteralPath $Baseline

Get-Content -LiteralPath $Baseline
```

## 3. Capture and verify the installed driver

Open **PowerShell as Administrator** and run:

```powershell
cd "$env:USERPROFILE\Desktop"
Set-ExecutionPolicy -Scope Process Bypass
.\Collect-DriverMetadata.ps1
Get-Content -LiteralPath "$env:USERPROFILE\Documents\tudor-00c9-driver-metadata.json"
```

The output must identify version `6.0.44.1111` and SHA-256
`da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60`.
The installed DLL is expected below a directory such as:

```text
C:\Windows\System32\DriverStore\FileRepository\synawudfbiousbuwp.inf_amd64_*\synaWudfBioUsb111.dll
```

Do not derive that directory from `oem68.inf`; the script searches
`FileRepository` and binds the DLL to the signed driver's exact version.
Record the `usb_serial`, `usb_instance_id`, and `dll_driverstore_path` values
printed by the script. Every later reference to `USB_SERIAL` means that exact
value. The script discovers the serial from the PnP instance ID; do not type or
guess it separately.

## 4. Record the Local Service fallback observation

On the observed system, the driver host runs as Local Service and the actual
path is:

```text
HKEY_USERS\S-1-5-19\Software\Synaptics\PairingData
```

On the tested machine, the single 16-hex-digit `REG_BINARY` value had length
zero. Its name records the eight-byte private identity but it contains no
wrapped pairing material. Therefore neither an interactive-user DPAPI exporter
nor a registry dump can produce a bundle. Do not assume the example value name
from another computer, and do not use WinDbg or the withdrawn lock/unlock
breakpoint procedure.

Run this read-only confirmation in the Administrator PowerShell window:

```powershell
$Key = [Microsoft.Win32.Registry]::Users.OpenSubKey(
  'S-1-5-19\Software\Synaptics\PairingData', $false)
if ($null -eq $Key) { throw 'PairingData key is missing' }
$Key.GetValueNames() | ForEach-Object {
  $Value = [byte[]]$Key.GetValue($_)
  [pscustomobject]@{ Name = $_; Length = $Value.Length }
}
$Key.Dispose()
```

Record the output. A normal result for this audited configuration is one
16-hex-digit name and `Length` zero. `Complete-PairingExport.ps1` later checks
that the name equals the private identity read from this sensor's host
partition. Do not write to this key.

## 5. Return to Linux and export the wrapped field

This is the only intermediate Linux step. From the repository, first run all
offline tests. Then obtain explicit approval for the exact hardware command in
[coexistence-complete-procedure.md](coexistence-complete-procedure.md), which
creates `HostPartitionExportV1.json`. Copy that file back to the Windows
Desktop. It contains encrypted pairing data and must not be shared.

## 6. Complete the export in the final Windows boot

Copy these Linux-generated files to the Windows Desktop:

```text
HostPartitionExportV1.json
```

The driver metadata generated in step 3 must still be at:

```text
%USERPROFILE%\Documents\tudor-00c9-driver-metadata.json
```

Open **PowerShell as Administrator** and run exactly:

```powershell
cd "$env:USERPROFILE\Desktop"
Set-ExecutionPolicy -Scope Process Bypass
$HostExport = "$env:USERPROFILE\Desktop\HostPartitionExportV1.json"
$Metadata = "$env:USERPROFILE\Documents\tudor-00c9-driver-metadata.json"
$Bundle = "$env:USERPROFILE\Documents\PairingBundleV1.json"
.\Complete-PairingExport.ps1 -HostPartitionExport $HostExport `
  -DriverMetadata $Metadata -Output $Bundle
Get-Item -LiteralPath $Bundle | Format-List FullName,Length
```

`Complete-PairingExport.ps1` validates the device identifiers, pinned driver
version/hash, and empty registry fallback. It creates a temporary scheduled
task running as `NT AUTHORITY\LOCAL SERVICE`, uses that account only to unwrap
the copied DPAPI blob, converts the 1284-byte plaintext with
`Export-Pairing.ps1`, then removes the task and temporary plaintext. It calls no
sensor API and performs no driver or registry write.

If the command fails, retain the error text and stop. Do not reset, repair, or
pair the sensor.

## 7. Verify Windows still works and return once to Linux

Lock with `Win+L` and unlock twice using the normally enrolled finger. Append
the final result to the baseline:

```powershell
@(
  ''
  'Post-export Windows Hello test: PASS'
  "Post-export time: $(Get-Date -Format o)"
  'Attempts: 2'
  'Sensor pairing/enrollment/storage changed: no'
) | Add-Content -LiteralPath "$env:USERPROFILE\Documents\tudor-00c9-windows-baseline.txt"
```

Copy `PairingBundleV1.json`, the baseline text, and driver metadata back to
Linux. Keep `PairingBundleV1.json` private; Linux installs it as mode `0600`.

After Linux coexistence is installed, Windows-to-Linux transitions must use a
complete Windows shutdown, not **Restart**. Close applications, run the
following in PowerShell, wait about 30 seconds after power-off, and then power
on into Linux:

```powershell
shutdown.exe /s /t 0
```

The tested Windows driver can retain a volatile TLS session across a warm
restart. Linux intentionally refuses to reset or force-close that session.
