# Handoff: `fix-stale` (06cb:00c9 TLS lifecycle)

This branch starts at `main` commit `9a72095`. Its goal is to prevent **Linux-owned**
TLS sessions from being left active after ordinary verification, cancellation,
daemon stop, suspend, shutdown, or reboot. Characterize Windows-to-Linux warm
restarts separately; do not assume Linux can safely close a session created by
Windows.

## Established observations (one device, firmware 10.1.3399660)

- An existing Windows pairing and template worked with isolated fprintd, PAM,
  and Windows Hello. A successful Linux `verify-match` left the read-only
  pre-authentication snapshot byte-for-byte equal to its baseline.
- Windows **Restart** into Linux produced a stale remote TLS refusal. Windows
  `shutdown.exe /s /t 0`, approximately 30 seconds powered off, then a Linux
  boot cleared it in one observed cycle. This is a workaround, not proof about
  all machines or all warm restarts.
- Both isolated fprintd and standalone Python have also seen frame-acquire
  (`0x80`) fail with `0x05cb`. Its cause is unknown; do not conflate it with
  stale TLS. Python now reports the status instead of waiting indefinitely.
- The isolated fprintd service uses `--no-timeout` because idle daemon exit did
  not synchronously close the device. Its normal stop path has closed TLS in a
  prior test, but shutdown/reboot/cancel paths are not comprehensively proven.

## Safety boundaries

Read `docs/06cb-00c9-coexistence-safety.md` before any hardware work. Keep the
stable public USB-serial identity and reuse only the pre-imported Windows
pairing and the single existing template. Never automatically pair, enroll,
reset sensor/USB, clear or write persistence, force-close a foreign TLS session,
or start the Tudor host launcher. A stale remote session with no matching
host-owned session remains a **hard refusal**. Keep password login available.
Keep experimental services masked except during a separately approved test.
Show each exact sensor-facing command and get explicit approval before running
it; ring the terminal bell immediately before an approved finger touch. Compare
read-only snapshots at hardware gates and stop if Windows Hello or any snapshot
field regresses. Never commit pairing bundles, keys, claims, sensor identities,
SIDs, template IDs, snapshots, or raw biometric/protocol payloads.

## Investigation and implementation queue

1. Map session ownership and cleanup paths in
   `libfprint/libfprint/libfprint/drivers/synatlsmoc/synatlsmoc.c`:
   `synatlsmoc_open*`, `synatlsmoc_cancel`, `synatlsmoc_suspend`,
   `synatlsmoc_close*`, `close_tls_session`, and asynchronous callbacks.
   Check whether all post-handshake failures and cancellation paths complete
   ordinary TLS close-notify **before** USB release/process exit, and whether
   `CLOSE_TLS_SESSION_CLOSE` advances when `self->session` is null. Treat these
   as review targets, not established defects.
2. Review Python cleanup in `pydrv/tudor/sensor/sensor.py` (`initialize`,
   `uninitialize`) and the TLS close implementation. Ensure partial opens and
   exceptions have one session owner and no skipped close-notify. Keep retry
   ownership in one layer only.
3. Trace fprintd's real lifecycle with sanitized logs: normal verify,
   no-match, cancel, client disconnect, daemon stop/restart, suspend/resume,
   orderly Linux reboot, and Windows Restart versus full shutdown. Record
   TLS-status transitions, close-notify completion, and process/USB release
   ordering without private payloads. Distinguish a Linux-left session from a
   Windows-left session before proposing a fix.
4. Review `packaging/fprintd.service.d/10-synatlsmoc-coexist.conf` and systemd
   shutdown ordering. Add a tested, graceful stop path if needed; avoid a
   timer, signal, or retry that races the device close. Preserve `--no-timeout`
   until a verified replacement exists.
5. Add hardware-independent lifecycle tests (recorded transcripts or fakes)
   for successful close, partial-open failure, cancellation, and close errors.
   Assert no reset/force-close/persistent-write command is emitted. Then run
   the existing release check and Meson tests.
6. With separate approval per gate, validate on 06cb:00c9: Linux verify and
   orderly stop/reboot, then alternating Windows/Linux boots. Recheck Windows
   Hello and the baseline snapshot. If Windows leaves a foreign TLS session,
   retain the safe refusal and document the power-off procedure; do not
   disguise that limitation as a Linux software fix.

## Starting points and completion criteria

- `TODO.md` has the wider reboot/session-lifecycle backlog and test history.
- `docs/coexistence-complete-procedure.md` has the deployment, recovery, and
  full-shutdown procedure; `packaging/README.md` explains service ownership.
- `pydrv/tudor/hardware.py` and `pydrv/tudor/safety.py` define the safe Python
  hardware boundary. Do not use legacy development commands as a workaround.
- Completion means ordinary **Linux-owned** session exits leave remote TLS
  clear, proven by automated lifecycle tests and approved hardware tests;
  normal Linux reboot does not require a power cycle; Windows Hello and the
  persistence snapshot remain unchanged. Any Windows-origin warm-restart
  limitation must be stated explicitly if it remains.
