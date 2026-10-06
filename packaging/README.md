# Isolated coexistence deployment

These files are staging templates, not an installer. The complete ordered
procedure is in `docs/coexistence-complete-procedure.md`. Do not copy them, unmask
`fprintd.service`, or modify D-Bus/PAM until standalone probe, snapshot,
pairing reuse, listing, and selected-template verification gates have passed
with unchanged snapshots and successful Windows Hello checks.

## Release boundary

A distributable package must be device-independent and inactive by default.
It must never contain or generate any of the following:

- `HostPartitionExportV1.json`, `PairingBundleV1.json`, or `pairing-data`;
- local `FP3` claim files, USB serials, private sensor identities, Windows SIDs,
  template IDs/hashes, snapshots, or hardware logs;
- vendor DLLs/driver packages or historical Windows export ZIP files;
- a post-install action that unmasks/starts fprintd, edits PAM, pairs, enrolls,
  resets, force-closes TLS, or writes sensor persistence.

The package may install the isolated runtime, current Windows scripts,
documentation, and inactive integration templates. Per-device pairing import,
claim creation, D-Bus override installation, service activation, and PAM
selection remain explicit audited operator gates.

`packaging/check-release.sh` checks the current scripts/docs for known Windows
regressions and machine-specific identifiers, verifies that the fprintd Meson
manifest does not escape `/opt`, confirms isolated libfprint resolution, and
runs the Python safety suite. Passing it validates release inputs; it does not
create a `.deb` or prove install/upgrade/removal behavior.

There is not yet a distributable package definition. Before release, add and
test a versioned package build with declared runtime dependencies, inactive
install semantics, upgrade behavior, and rollback/removal tests on a clean
Ubuntu 26.04 system.

## Dependency record

The reproducible Ubuntu build/test environment currently requires:

```bash
sudo apt-get install git meson ninja-build pkg-config gcc gettext \
  libglib2.0-dev libgusb-dev libssl-dev libpolkit-gobject-1-dev \
  libsystemd-dev python3-dbusmock
```

`gettext` supplies `msgfmt`, which fprintd requires while generating its data
files. `python3-dbusmock` is test-only. The `-dev` packages and compiler tools
are build-only. For the eventual binary package, calculate runtime shared
library dependencies from the staged executables using `dpkg-shlibdeps`, then
confirm that `/opt/synatlsmoc-coexist/libexec/fprintd` resolves the isolated
libfprint with `ldd`.

Apply both fprintd patches. `fprintd-isolated-prefix.patch` is required because
upstream otherwise obtains D-Bus and polkit install directories from system
pkg-config metadata and writes under `/usr/share` even with a `/opt` prefix.
The isolated patch stages those files under `/opt`; system integration remains
a separate reversible gate.

The intended prefix is `/opt/synatlsmoc-coexist`. Configure libfprint with an
embedded runtime path rather than replacing distribution libraries:

```bash
meson setup build-opt libfprint/libfprint \
  --prefix=/opt/synatlsmoc-coexist \
  --libdir=lib/x86_64-linux-gnu \
  -Ddrivers=synatlsmoc -Dintrospection=false -Ddoc=false \
  -Dc_link_args=-Wl,-rpath,/opt/synatlsmoc-coexist/lib/x86_64-linux-gnu
meson compile -C build-opt
```

Do not run `meson install` yet. fprintd 1.94.5 must be built separately against
that prefix after applying `libfprint/fprintd-load-store-persistent-data-from-device.patch`.
The patch loads pre-imported pairing data from
`/var/lib/fprint/0-persistent/synatlsmoc/<stable-device-id>` with directory mode
`0700`, file mode `0600`, and load-before-open semantics. It deliberately has
no save/delete path for pairing data.

At the eventual custom-service gate, back up the existing D-Bus activation file
and install the supplied service/drop-in files explicitly. Rollback consists of
masking `fprintd.service`, removing the drop-in, restoring the exact D-Bus
backup, running `systemctl daemon-reload`, and reloading the D-Bus configuration.
Never unmask or start `tudor-host-launcher.service`.

The custom fprintd drop-in uses `--no-timeout`. Do not remove it: an automatic
idle process exit can leave a volatile remote TLS session behind. Lifecycle is
therefore owned by systemd, and the service must be stopped normally before an
OS switch.

The tested Windows driver may retain its volatile TLS session across a warm
restart. The 06cb:00c9 driver now makes one GET_VERSION close attempt and
requires a read-only TLS-status check before opening a new session. One
approved experiment cleared the stale session without rebooting Linux and
left the persistence snapshot unchanged. Windows Hello was checked after a
later Windows Restart recovery cycle and still worked. Linux fingerprint login
also succeeded after that Restart with the snapshot unchanged. This is one
validated cycle on firmware `10.1.3399660`. If the bounded attempt fails, use a
complete shutdown and roughly 30 seconds powered off. Do not reset the sensor
or repeat the close attempt.

The validated Ubuntu GDM setup uses five fingerprint tries in the dedicated
`gdm-fingerprint` PAM service and skips the fingerprint module from
`common-auth` in the `gdm-password` service, preventing two GDM workers from
running separate fingerprint checks during GDM login. Password authentication
remains available. These PAM
changes are machine-specific and remain an explicit operator gate; the package
does not edit PAM.

PAM must retain the existing password authentication line. Adding fingerprint
authentication must not make it `sufficient` in a way that bypasses password
fallback or lock out recovery; PAM changes require a separate reviewed gate.
