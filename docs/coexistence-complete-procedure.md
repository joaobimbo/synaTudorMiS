# Complete 06cb:00c9 Windows/Linux coexistence procedure

This is the authoritative end-to-end procedure. Windows keeps its existing
Synaptics 6.0.44.1111 pairing and templates. Linux imports that same pairing,
claims an existing template locally, and never sends pairing, enrollment,
deletion, cleanup, formatting, reset, recovery, or firmware commands.

## 1. Prepare and test Linux without touching the sensor

```bash
cd ~/code/synaTudorMiS
sudo apt-get update
sudo apt-get install python3-venv python3-pip python3-usb python3-cryptography python3-matplotlib \
  git meson ninja-build pkg-config gcc gettext libglib2.0-dev libgusb-dev libssl-dev \
  libpolkit-gobject-1-dev libsystemd-dev python3-dbusmock
python3 -m venv --system-site-packages pydrv/.venv
pydrv/.venv/bin/pip install --no-build-isolation --no-deps -e pydrv
PYTHONPATH=pydrv python3 -m unittest discover -s pydrv/tests -v
./packaging/build-isolated.sh
systemctl is-enabled fprintd.service tudor-host-launcher.service
systemctl is-active fprintd.service tudor-host-launcher.service
```

Both services must report `masked` and `inactive`. The isolated libfprint build
is in `build-opt/`; nothing has been installed under `/opt` yet.

Dependency roles for later packaging:

- Build-only: `git`, `meson`, `ninja-build`, `pkg-config`, `gcc`, `gettext`,
  `libglib2.0-dev`, `libgusb-dev`, `libssl-dev`,
  `libpolkit-gobject-1-dev`, and `libsystemd-dev`.
- Offline-test-only: `python3-dbusmock`; Python prototype tests and conversion
  additionally use `python3-venv`, `python3-pip`, `python3-usb`,
  `python3-cryptography`, and `python3-matplotlib`.
- Runtime package dependencies must be derived from the final installed
  binaries with `dpkg-shlibdeps` (and verified with `ldd`); do not copy the
  development/test package list into runtime dependencies.

## 2. Record the Windows baseline and driver metadata

Follow steps 1 through 4 of
[windows-final-export-runbook.md](windows-final-export-runbook.md). The observed
Local Service registry value is empty, so registry and breakpoint exports are
withdrawn. Return to Linux with the baseline and driver metadata.

## 3. Export the encrypted host-partition field in Linux

This gate sends a TLS-status control query, `GET_VERSION`, and exactly one
4096-byte `STORAGE_PART_READ`. It sends no TLS handshake, pairing, storage
write, reset, event, biometric, or DB2 command. Show this exact command and
obtain explicit approval before running it:

```bash
cd ~/code/synaTudorMiS
sudo pydrv/.venv/bin/tudor-safe export-host-pairing \
  ./HostPartitionExportV1.json --vid 06cb --pid 00c9
sudo chown "$(id -u):$(id -g)" ./HostPartitionExportV1.json
chmod 600 ./HostPartitionExportV1.json
stat -c '%a %U:%G %n' ./HostPartitionExportV1.json
```

The last line must report mode `600`. If the sensor reports stale TLS,
bootloader mode, an invalid container, a missing tag 2, or any identity/state
mismatch, stop. The command refuses forced recovery.

Copy `HostPartitionExportV1.json` plus `Collect-DriverMetadata.ps1`,
`Export-Pairing.ps1`, and `Complete-PairingExport.ps1` from `windows/` to the
Windows Desktop, then follow steps 6 and 7 of the Windows runbook. Do not use
`Prepare-PairingExport.ps1`; it belongs to the withdrawn debugger workflow.
Return to Linux with `PairingBundleV1.json` only after Windows Hello succeeds
twice.

## 4. Validate and convert the returned bundle offline

Replace `/path/from/transfer` with the actual source path:

```bash
cd ~/code/synaTudorMiS
install -m 600 /path/from/transfer/PairingBundleV1.json ./PairingBundleV1.json

USB_SERIAL=$(pydrv/.venv/bin/python -c 'import json; print(json.load(open("PairingBundleV1.json"))["usb_serial"])')
STABLE_ID="06cb-00c9-$USB_SERIAL"
printf 'USB_SERIAL=%s\nSTABLE_ID=%s\n' "$USB_SERIAL" "$STABLE_ID"

pydrv/.venv/bin/tudor-safe audit-pairing ./PairingBundleV1.json \
  --serial "$USB_SERIAL"
pydrv/.venv/bin/tudor-safe import-pairing ./PairingBundleV1.json \
  "$STABLE_ID" ./pairing-data
stat -c '%a %U:%G %n' ./PairingBundleV1.json ./pairing-data
```

Both files must show mode `600`. These operations are offline and do not open
the USB sensor.

## 5. Run the standalone hardware gates

Do not combine these gates. Show each exact command for approval immediately
before running it. Stop on any error or snapshot change.

### Gate 1: read-only probe

```bash
sudo pydrv/.venv/bin/tudor-safe probe --vid 06cb --pid 00c9 | tee probe.json
```

Confirm that `stable_device_id` equals `$STABLE_ID`. Select the firmware key:

```bash
if grep -q '"key_flag": true' probe.json; then
  KEY="$PWD/pydrv/tudor/sensor/sensor_keys/10.1-kf.tsk"
else
  KEY="$PWD/pydrv/tudor/sensor/sensor_keys/10.1.tsk"
fi
printf 'KEY=%s\n' "$KEY"
```

### Gate 2: repeated read-only snapshot

Firmware `10.1.3399660` denies DB2 reads before TLS with status `0x0404`.
Therefore this public command emits `PreAuthSnapshotV1`: firmware/security/
provision state plus the host-partition hash only. Authenticated list and
verify operations separately take full `SnapshotV1` DB2 snapshots internally
before and after their volatile work.

```bash
sudo pydrv/.venv/bin/tudor-safe snapshot --vid 06cb --pid 00c9 | tee snapshot-before.json
sudo pydrv/.venv/bin/tudor-safe snapshot --vid 06cb --pid 00c9 | tee snapshot-repeat.json
diff -u snapshot-before.json snapshot-repeat.json
```

`diff` must print nothing.

### Gate 3: imported-pairing TLS and sanitized list

```bash
sudo pydrv/.venv/bin/tudor-safe list ./PairingBundleV1.json \
  --sensor-key "$KEY" | tee template-list.json
sudo pydrv/.venv/bin/tudor-safe snapshot --vid 06cb --pid 00c9 | tee snapshot-after-list.json
diff -u snapshot-before.json snapshot-after-list.json
```

Choose exactly one `template_sha256` from `template-list.json`:

```bash
TEMPLATE_SHA256='replace-with-one-64-digit-hash-from-template-list.json'
```

### Gates 4 and 5: wrong finger, then selected finger

Run the same restricted command once with the wrong finger and once with the
selected finger. It rings the terminal bell immediately before touch:

```bash
sudo pydrv/.venv/bin/tudor-safe verify ./PairingBundleV1.json \
  "$TEMPLATE_SHA256" --sensor-key "$KEY"
```

After each run:

```bash
sudo pydrv/.venv/bin/tudor-safe snapshot --vid 06cb --pid 00c9 | tee snapshot-after-verify.json
diff -u snapshot-before.json snapshot-after-verify.json
```

The wrong finger must produce `NO MATCH`, the selected finger must produce
`MATCH`, and snapshots must remain identical.

### Gate 6: create the local Linux claim

Replace the Linux username and finger name if needed:

```bash
LINUX_USER=$(id -un)
LINUX_FINGER=right-index-finger
sudo pydrv/.venv/bin/tudor-safe claim-existing ./PairingBundleV1.json \
  "$LINUX_USER" "$LINUX_FINGER" "$TEMPLATE_SHA256" --sensor-key "$KEY"
sudo find "/var/lib/fprint/$LINUX_USER/synatlsmoc/$STABLE_ID" \
  -maxdepth 1 -type f -printf '%m %u:%g %f\n'
```

For `right-index-finger`, fprintd's exact file is:

```text
/var/lib/fprint/<user>/synatlsmoc/<stable-id>/7
```

Local-only rollback for that claim:

```bash
sudo pydrv/.venv/bin/tudor-safe unclaim \
  "$LINUX_USER" "$STABLE_ID" "$LINUX_FINGER"
```

## 6. Install isolated libfprint

Only after the standalone gates and Windows Hello checks pass:

```bash
cd ~/code/synaTudorMiS
sudo meson install -C build-opt
find /opt/synatlsmoc-coexist -maxdepth 4 \( -type f -o -type l \) -print
```

This does not replace the distribution libfprint.

## 7. Fetch, patch, build, and install fprintd 1.94.5

Obtain the exact audited upstream tag (the build dependencies were installed in
step 1):

```bash
cd ~/code/synaTudorMiS
git clone --depth 1 --branch v1.94.5 \
  https://gitlab.freedesktop.org/libfprint/fprintd.git fprintd-1.94.5
git -C fprintd-1.94.5 rev-parse HEAD
```

The expected commit is `b54a007ccf58ac0ae074c7151b223f35cbd17306`.
Apply the repository patch exactly:

```bash
git -C fprintd-1.94.5 apply --check \
  "$PWD/libfprint/fprintd-load-store-persistent-data-from-device.patch"
git -C fprintd-1.94.5 apply \
  "$PWD/libfprint/fprintd-load-store-persistent-data-from-device.patch"
git -C fprintd-1.94.5 apply --check \
  "$PWD/libfprint/fprintd-isolated-prefix.patch"
git -C fprintd-1.94.5 apply \
  "$PWD/libfprint/fprintd-isolated-prefix.patch"
```

Configure it against only the `/opt` libfprint, without installing another PAM
module or upstream service files:

```bash
PKG_CONFIG_PATH=/opt/synatlsmoc-coexist/lib/x86_64-linux-gnu/pkgconfig \
meson setup build-fprintd fprintd-1.94.5 \
  --prefix=/opt/synatlsmoc-coexist --libexecdir=libexec \
  -Dpam=false -Dman=false -Dsystemd=false \
  -Dc_link_args=-Wl,-rpath,/opt/synatlsmoc-coexist/lib/x86_64-linux-gnu
meson compile -C build-fprintd
meson test -C build-fprintd --print-errorlogs
sudo meson install -C build-fprintd
ldd /opt/synatlsmoc-coexist/libexec/fprintd | grep libfprint
```

`ldd` must resolve libfprint from `/opt/synatlsmoc-coexist`, not `/usr`.

## 8. Atomically install imported pairing data

These commands preserve the source `pairing-data`, create the destination with
mode `0700`, stage the file in the same filesystem, and rename it atomically:

```bash
PAIRING_DIR=/var/lib/fprint/0-persistent/synatlsmoc
PAIRING_DEST="$PAIRING_DIR/$STABLE_ID"
PAIRING_STAGE="$PAIRING_DIR/.pairing-data.new.$$"
sudo test ! -e "$PAIRING_DEST"
sudo install -d -o root -g root -m 700 \
  /var/lib/fprint/0-persistent "$PAIRING_DIR"
sudo install -o root -g root -m 600 ./pairing-data "$PAIRING_STAGE"
sudo mv "$PAIRING_STAGE" "$PAIRING_DEST"
sudo stat -c '%a %U:%G %n' \
  /var/lib/fprint/0-persistent "$PAIRING_DIR" "$PAIRING_DEST"
sha256sum ./pairing-data
sudo sha256sum "$PAIRING_DEST"
```

Expected modes are `700 root:root` for the directory and `600 root:root` for
the file. The refreshed fprintd patch is load-only: fprintd never rewrites or
deletes this pairing file.

## 9. Install reversible systemd and D-Bus overrides

Do this only at the custom-fprintd activation gate:

```bash
sudo install -d -m 755 /etc/systemd/system/fprintd.service.d
sudo install -m 644 packaging/fprintd.service.d/10-synatlsmoc-coexist.conf \
  /etc/systemd/system/fprintd.service.d/10-synatlsmoc-coexist.conf
sudo install -d -o root -g root -m 700 /var/backups/synatlsmoc-coexist
sudo test ! -e \
  /var/backups/synatlsmoc-coexist/net.reactivated.Fprint.service.distribution
sudo install -o root -g root -m 600 \
  /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
  /var/backups/synatlsmoc-coexist/net.reactivated.Fprint.service.distribution
sudo install -d -m 755 /etc/dbus-1/system-services
sudo install -m 644 packaging/net.reactivated.Fprint.service \
  /etc/dbus-1/system-services/net.reactivated.Fprint.service
sudo systemctl daemon-reload
sudo systemctl unmask fprintd.service
sudo systemctl start fprintd.service
systemctl status fprintd.service --no-pager
systemctl is-enabled tudor-host-launcher.service
```

The custom service runs fprintd with `--no-timeout`. This is mandatory for
coexistence: fprintd's normal idle process exit does not guarantee an orderly
libfprint close, which can leave the sensor's volatile TLS session active and
make the next daemon activation refuse to proceed. Stop the service explicitly
before rebooting or switching operating systems.

The Tudor launcher must still report `masked`.

Test fprintd with the existing local claim; do not run `fprintd-enroll`:

```bash
fprintd-list "$LINUX_USER"
printf '\a'
fprintd-verify -f "$LINUX_FINGER" "$LINUX_USER"
```

## 10. Enable PAM while retaining password fallback

Back up the PAM file and use Ubuntu's PAM profile selector:

```bash
sudo test ! -e \
  /var/backups/synatlsmoc-coexist/common-auth.before-synatlsmoc
sudo install -m 600 /etc/pam.d/common-auth \
  /var/backups/synatlsmoc-coexist/common-auth.before-synatlsmoc
sudo pam-auth-update
```

In the dialog, keep **Unix authentication** selected and also select
**Fingerprint authentication**. Never disable password authentication. Test in
a separate terminal while the existing root-capable session remains open.

## 11. Exact service rollback

If custom fprintd or PAM testing fails:

```bash
sudo systemctl mask --now fprintd.service
sudo rm -f /etc/systemd/system/fprintd.service.d/10-synatlsmoc-coexist.conf
sudo rm -f /etc/dbus-1/system-services/net.reactivated.Fprint.service
sudo systemctl daemon-reload
sudo install -m 644 \
  /var/backups/synatlsmoc-coexist/common-auth.before-synatlsmoc \
  /etc/pam.d/common-auth
systemctl is-enabled fprintd.service tudor-host-launcher.service
```

This rollback leaves the `/opt` build and imported pairing file in place but
inactive. Do not reset or repair the sensor.

## 12. Final coexistence acceptance

Complete five alternating Windows/Linux cycles. In each OS, authenticate
successfully. On every Linux cycle compare a fresh snapshot to the baseline.

Use an orderly full shutdown, not Windows **Restart**, when switching from
Windows to Linux. The tested Windows driver can leave its volatile TLS session
active across a warm reboot. The Linux driver deliberately refuses to
force-close or reset that session, so verification will be unavailable until
the sensor loses power. The exact safe transition is:

1. Close applications and run `shutdown.exe /s /t 0` in Windows PowerShell.
2. Wait approximately 30 seconds after the machine powers off.
3. Power on and boot Linux.

Microsoft documents `shutdown.exe /s /t 0` as a full shutdown; the optional
`/hybrid` switch requests Fast Startup instead. Do not use the Windows Restart
menu item as a substitute for powering off. In the 2026-10-06 test on firmware
`10.1.3399660`, Windows Restart led to a stale remote TLS refusal. After a
subsequent full power-off and roughly 30 seconds off, the existing Linux claim
returned `verify-match`; the post-match pre-authentication snapshot matched
the baseline exactly. The experiment does not establish that every full
shutdown removes sensor power or that every `0x05cb` capture response has the
same cause. See the [Microsoft shutdown documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail).

For Linux to Windows, keep the custom no-timeout fprintd service under systemd
control and use a normal orderly shutdown. Its tested stop path closes TLS.
Never kill fprintd or remove `--no-timeout` before switching operating systems.

If Linux reports `Sensor has a stale remote TLS session`, mask and stop fprintd,
power off completely, wait 30 seconds, and boot Linux again:

```bash
sudo systemctl mask --now fprintd.service
sudo poweroff
# After powering on and booting Linux:
sudo systemctl unmask fprintd.service
sudo systemctl start fprintd.service
```

The mask survives reboot until the `unmask` command is run. Keep password
authentication available during this recovery; restoring the fingerprint prompt
does not by itself prove the stale session is gone.

Stop immediately if Windows Hello fails, any snapshot field changes, or a
power cycle does not clear the volatile session. Do not reset or force-close
the sensor.

## 13. Private reinstall backup

Keep one encrypted, offline backup tied to this physical sensor. At minimum,
preserve:

```text
PairingBundleV1.json
pairing-data
claim/<finger-number>
```

The claim is the installed `FP3` file from:

```text
/var/lib/fprint/<linux-user>/synatlsmoc/<stable-device-id>/<finger-number>
```

For example, a right-index claim uses finger number `7`. Also preserve these
useful recovery/evidence files when available:

```text
HostPartitionExportV1.json
tudor-00c9-driver-metadata.json
tudor-00c9-windows-baseline.txt
probe.json
snapshot-before.json
template-list.json
```

`PairingBundleV1.json`, `pairing-data`, and `HostPartitionExportV1.json` are
private pairing material. Store the backup on encrypted removable storage,
never in Git or a distributable package. Keep files mode `0600` and the backup
directory mode `0700` after restoring to Linux.

Example, after mounting an encrypted private disk at `/mnt/private` (replace
the username, stable ID, and finger number as required):

```bash
BACKUP=/mnt/private/synatlsmoc-06cb-00c9
LINUX_USER=$(id -un)
USB_SERIAL=$(pydrv/.venv/bin/python -c \
  'import json; print(json.load(open("PairingBundleV1.json"))["usb_serial"])')
STABLE_ID="06cb-00c9-$USB_SERIAL"
FINGER_NUMBER=7
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 700 "$BACKUP"
install -m 600 ./PairingBundleV1.json ./pairing-data \
  ./HostPartitionExportV1.json "$BACKUP/"
sudo install -m 600 \
  "/var/lib/fprint/$LINUX_USER/synatlsmoc/$STABLE_ID/$FINGER_NUMBER" \
  "$BACKUP/claim-right-index-finger.fp3"
sha256sum "$BACKUP"/* > "$BACKUP/SHA256SUMS"
chmod 600 "$BACKUP/SHA256SUMS"
```

Do not back up the entire `/var/lib/fprint` tree: it may contain unrelated
users/devices. The runtime binaries, integration templates, Windows scripts,
and documentation are non-secret and should come from the versioned package
or Git fork instead.
