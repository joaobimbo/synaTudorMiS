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
reset sensor/USB, clear or write persistence, make repeated/unrestricted
force-close attempts, or start the Tudor host launcher. The default 06cb:00c9
path is limited to one GET_VERSION close attempt and a mandatory status check;
if TLS remains active, it is a **hard refusal**. Keep password login available.
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
   Assert no reset/repeated-close/persistent-write command is emitted. Then run
   the existing release check and Meson tests.
6. With separate approval per gate, validate on 06cb:00c9: Linux verify and
   orderly stop/reboot, then alternating Windows/Linux boots. Recheck Windows
   Hello and the baseline snapshot. If Windows leaves a foreign TLS session,
   retain the safe refusal and document the power-off procedure; do not
   disguise that limitation as a Linux software fix.

## Code progress (2026-10-06)

- The C close state machine now advances without a local session, handles its
  own close response, and checks the read-only remote TLS status before it
  reports a successful close. Failed opens that sent handshake data attempt
  ordinary close-notify before releasing USB.
- Python closes an established session after failed initialization or event
  cleanup, and checks remote TLS status after close-notify. Authenticated
  command callers release the USB transport even if cleanup raises.
- Hardware-independent Python lifecycle tests pass. The isolated C driver
  builds and the available Meson tests pass. These tests do not prove daemon
  stop, suspend, or Linux reboot on the device; the hardware observations below
  cover one Windows warm-restart recovery cycle.
- Windows-origin stale TLS after **Restart** was a hard refusal before the
  single approved experiment below. The default driver now makes one
  `GET_VERSION` close attempt on 06cb:00c9, then requires remote TLS to clear
  before proceeding. Full shutdown remains the fallback if it fails.

## One approved Windows Restart recovery experiment (2026-10-06)

- Windows Hello worked before Windows Restart. The isolated fprintd reported a
  stale remote TLS session on the following Linux boot.
- The fingerprint reader was on a root-hub port whose descriptor advertises no
  per-port power switching. One approved USB reset left remote TLS active.
- A separately approved, single plaintext `GET_VERSION` (`0x01`) returned
  `0x0315` and cleared remote TLS. A fresh read-only probe succeeded, and the
  pre-authentication snapshot matched the saved baseline in every field.
- The first approved fprintd touch returned no match; a separately approved
  second touch returned `verify-match`. The post-match snapshot still matched.
- The next Windows Restart was recovered by the installed default driver; Linux
  fingerprint login and subsequent Windows Hello both succeeded, and the
  persistence snapshot remained unchanged. This is one validated cycle on
  firmware `10.1.3399660`. Do not infer that USB reset or port disable removes
  power.
- The default build was installed into the isolated `/opt/synatlsmoc-coexist`
  libfprint location, and fprintd restarted successfully. The previous library
  is backed up under `/opt/synatlsmoc-coexist/rollback-stale-recovery/`.
  The installed library hash matched the tested build.
- GDM fingerprint login is configured for five tries within 60 seconds. The
  password PAM service skips its one-try fingerprint module from `common-auth`,
  leaving the dedicated fingerprint worker to own sensor retries. A failed
  scan followed by a second touch logged in successfully; password login still
  works.

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
