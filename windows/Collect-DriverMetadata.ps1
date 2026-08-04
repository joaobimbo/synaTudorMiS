[CmdletBinding()]
param(
    [string]$InstanceId,
    [string]$Output = "$env:USERPROFILE\Documents\tudor-00c9-driver-metadata.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $InstanceId) {
    $devices = @(Get-PnpDevice -PresentOnly |
        Where-Object InstanceId -Like 'USB\VID_06CB&PID_00C9\*')
    if ($devices.Count -ne 1) {
        throw "expected exactly one present USB VID_06CB&PID_00C9 device; found $($devices.Count)"
    }
    $InstanceId = $devices[0].InstanceId
}
$usbSerial = ($InstanceId -split '\\')[-1]
if (-not $usbSerial) { throw 'USB instance ID does not contain a serial component' }

$driver = Get-CimInstance Win32_PnPSignedDriver |
    Where-Object DeviceID -EQ $InstanceId
if (@($driver).Count -ne 1) {
    throw "expected exactly one signed driver for the requested instance ID"
}
$repository = "$env:SystemRoot\System32\DriverStore\FileRepository"
# Win32_PnPSignedDriver reports the published INF name (for example
# oem68.inf), while DriverStore directories use the original vendor INF name.
# Locate candidates by the fixed binary name, then bind the result to the
# signed driver's exact version.
$dlls = @(Get-ChildItem -LiteralPath $repository -Filter 'synaWudfBioUsb111.dll' `
        -File -Recurse |
    Where-Object { $_.VersionInfo.FileVersion -eq $driver.DriverVersion })
if ($dlls.Count -ne 1) {
    $found = $dlls | ForEach-Object { "$($_.FullName) [$($_.VersionInfo.FileVersion)]" }
    throw "expected exactly one synaWudfBioUsb111.dll matching driver version $($driver.DriverVersion); found $($dlls.Count): $found"
}
$dll = $dlls[0]
$version = $dll.VersionInfo
$result = [ordered]@{
    format = 'TudorDriverMetadataV1'
    captured = (Get-Date -Format o)
    device_status = (Get-PnpDevice -InstanceId $InstanceId).Status
    device_name = $driver.DeviceName
    provider = $driver.DriverProviderName
    driver_version = $driver.DriverVersion
    driver_date = $driver.DriverDate.ToString('o')
    inf_name = $driver.InfName
    usb_instance_id = $InstanceId
    usb_serial = $usbSerial
    dll_driverstore_path = $dll.FullName
    dll_original_filename = $version.OriginalFilename
    dll_file_version = $version.FileVersion
    dll_product_version = $version.ProductVersion
    dll_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $dll.FullName).Hash.ToLowerInvariant()
}
$target = [IO.Path]::GetFullPath($Output)
# Windows PowerShell 5.1 does not recognize the PowerShell 7-only
# "utf8NoBOM" encoding name. A UTF-8 BOM is valid for this JSON metadata and
# is accepted by both PowerShell and the Linux-side importer.
$result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $target -Encoding utf8
Write-Host "Wrote read-only driver metadata: $target"
Write-Host 'No sensor command, driver change, or Device Manager action was performed.'
