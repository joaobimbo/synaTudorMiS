# TODO

The `06cb:00c9` coexistence path has been proven with an imported Windows
pairing, an existing Windows template, standalone libfprint, isolated fprintd,
PAM authentication, password fallback, and unchanged pre-authentication
snapshots. Windows Hello continued to work after the Linux tests.

## Capture failure and power-cycle result (2026-10-06)

On firmware `10.1.3399660`, the isolated fprintd and standalone Python verify
both establish the imported pairing but receive status `0x05cb` from
`VCSFW_CMD_FRAME_ACQ` (`0x80`) before capture. The old "generic
VCS_RESULT_SENSOR_MALFUNCTIONED" message is a fallback for unknown statuses;
the reverse-engineering notes map `0x05cb` to an unnamed vendor result `0x0dd`.
The cause of `0x05cb` is not yet known. The Python frame-acquire path now raises
the numeric status instead of waiting forever for a finger event. A post-failure
read-only snapshot matched `snapshot-before.json`, and no stale remote TLS was
reported then. A subsequent Windows Restart into Linux reported stale remote
TLS. After a full power-off and roughly 30 seconds off, the isolated fprintd
verified the existing finger successfully; the post-match pre-authentication
snapshot was byte-for-byte identical to the baseline. This demonstrates
recovery for this cycle, not a general fix for the capture or reboot lifecycle.
Do not reset, force-close TLS, re-pair, or change sensor persistence to work
around these statuses.

The following work remains before treating this as a generally installable
solution.

## Reboot and session lifecycle

- Reproduce and characterize the stale remote TLS state seen after some Linux
  reboots and Windows-to-Linux transitions. Record whether it depends on warm
  reboot, full shutdown, fprintd timeout, cancellation, or shutdown ordering.
- Make one component the sole owner of every TLS session and retry. Ensure all
  normal verification, cancellation, daemon-stop, logout, shutdown, and reboot
  paths attempt an ordinary TLS close-notify and wait for completion.
- Add a systemd shutdown ordering test so fprintd closes the device before USB
  teardown. Confirm that a normal Linux reboot returns with the sensor ready
  without requiring a manual service restart or a full power-off.
- Add automated lifecycle tests for daemon start/stop, cancellation, service
  restart, suspend/resume, warm reboot, cold boot, and alternating
  Windows/Linux boots.
- Preserve the hard refusal when the sensor already reports remote TLS. Do not
  add forced TLS close, USB reset, sensor reset, re-pairing, or automatic
  recovery as a workaround.

## Packaging and installation

- Build a Debian/Ubuntu package that installs the isolated libfprint and
  fprintd under `/opt/synatlsmoc-coexist` with an embedded runtime path.
- Declare build and runtime dependencies from `packaging/README.md`, using
  `dpkg-shlibdeps` against the staged binaries to finalize runtime dependency
  versions.
- Package reversible systemd and D-Bus activation helpers. Installation must
  not overwrite distribution binaries, enable fingerprint authentication, or
  unmask experimental services automatically.
- Add uninstall and rollback commands that restore the distribution D-Bus
  service definition and remove only coexistence-owned files.
- Add an upgrade path that preserves the pairing file and local template
  claims with modes `0600` and directories with modes `0700`.
- Add package tests in a clean VM for install, upgrade, rollback, purge, and
  reinstall from backed-up private state.

## Setup and recovery tooling

- Provide a root-only installer that validates `PairingBundleV1`, writes the
  versioned GVariant pairing data atomically, imports a selected local claim,
  and prints every privileged change before making it.
- Provide a read-only diagnostic command that reports service ownership,
  device state, pairing-file validity, claim validity, and stale TLS without
  logging keys, certificates, SIDs, raw template IDs, or biometric data.
- Document and optionally automate backup/restore of the private reinstall
  state: `PairingBundleV1.json`, `pairing-data`, local claim files, and the
  Windows export archive. Backups must be encrypted and access-restricted.
- Improve actionable errors for missing pairing data, wrong permissions,
  device-identity mismatch, stale TLS, unavailable templates, and incorrect
  service activation.

## Driver and daemon hardening

- Add transcript-driven C tests proving open, list, verify, cancel, and close
  cannot emit persistent-write commands.
- Add fprintd integration tests for load-before-open, persistence across daemon
  restart, local-only unclaim, cancellation, and password fallback.
- Run ASan and UBSan builds in CI in addition to the Meson and Python tests.
- Add CI checks that reject sample/private pairing material, Windows SIDs,
  raw biometric payloads, and unknown command IDs in coexistence paths.
- Review the remaining legacy Python entry points and either route them through
  the central safety policy or clearly mark them as unsafe development tools.

## Broader hardware validation

- Repeat the complete safety runbook on additional `06cb:00c9` units and
  supported firmware variants using generated or independently exported
  pairing fixtures.
- Verify five alternating Windows/Linux boot cycles per test device, including
  warm reboot and full shutdown cases, with Windows Hello, Linux verification,
  and snapshot comparison after each gate.
- Keep enrollment, deletion, clearing, pairing, firmware operations, forced
  recovery, and unknown commands outside the production feature set.

Any unexpected snapshot change, identity mismatch, pairing failure, or Windows
Hello regression remains a stop condition.
