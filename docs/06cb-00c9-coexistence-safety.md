# 06cb:00c9 coexistence safety runbook

This work reuses the one existing Windows host identity. It must not create a
second pairing or modify sensor persistence. Keep `fprintd.service` and
`tudor-host-launcher.service` masked during development. Never unmask or start
the Tudor host launcher.

## Command safety matrix

| Classification | Commands / operations |
|---|---|
| Permanently denied | POKE, PROVISION, RESET_OWNERSHIP, storage format/write, DB object create, TAKE_OWNERSHIP, bootloader patch/DFT write, PAIR, enrollment (0x96), DB2 write/delete/cleanup/format, reset-SBL, firmware commands, unknown and extended commands |
| Denied until proven | USB/sensor reset, repeated or unrestricted forced TLS close, bootloader transitions, SSO |
| Read-only | TLS-status control read, GET_VERSION only when TLS is clear, GET_START_INFO, PEEK, certificate/IOTA/storage reads, DB2 info/list/info/data, operation/hardware info |
| Bounded 06cb:00c9 runtime recovery | One GET_VERSION while a foreign TLS session is active; this can close the volatile session and must be followed by a TLS-status check |
| Authenticated verify only | TLS data, event config/read, frame read/acquire/finish, image metrics, and identify-match restricted to exactly one template ID |

The Python boundary in `tudor.safety` checks plaintext before TLS wrapping and
defaults to `READ_ONLY`. There is no destructive override. Protocol audit logs
contain only direction, command, length, status, and SHA-256—not raw payloads,
SIDs, certificates, keys, TLS data, or biometric data.

## Pairing extraction (Windows, read-only)

The observed driver host uses the Local Service hive at
`HKEY_USERS\S-1-5-19\Software\Synaptics\PairingData`. Its sensor-named value is
zero length, so it is not a source of active pairing material. Do not substitute
interactive-user DPAPI or attempt to populate that fallback value. The current
candidate is a read-only export of the wrapped pairing field already present
in the sensor host partition, followed by offline decryption in the matching
Local Service DPAPI context. Keep all intermediate and JSON files owner-only
(`0600` when transferred to Linux).

Before use, run `tudor-safe audit-pairing BUNDLE --serial SERIAL`. This checks
format, permissions, P-256 key/certificate correspondence, certificate framing,
VID/PID, serial, and the sensor-certificate signature against an explicitly
selected firmware key. Private sensor-ID matching remains a hardware gate.

The offline audit/import commands select exactly one matching bundled firmware
key automatically:

```bash
tudor-safe audit-pairing pairing.json --serial SERIAL
tudor-safe import-pairing pairing.json 06cb-00c9-SERIAL pairing-data
```

The second command creates the versioned libfprint `(issv)` envelope containing
an `a{sv}` `PairingDataV1`, using atomic replacement and mode `0600`. Install it
only after confirming its stable device ID, under
`/var/lib/fprint/0-persistent/synatlsmoc/<stable-device-id>`.

After an approved `list`, local claims use
`sudo tudor-safe claim-existing BUNDLE USER FINGER TEMPLATE_SHA256 --sensor-key KEY`.
This command requires root, resolves exactly one hash inside a snapshot-checked
authenticated session, then creates a libfprint `FP3` record containing the
`TemplateRefV1` template ID and finger subtype below `/var/lib/fprint`;
`unclaim` deletes only that local file. Never guess a
template selector or use a Windows SID for authorization.

## Hardware gates

Display and get explicit approval for every manual sensor-facing experiment.
The installed driver's bounded GET_VERSION recovery is part of the approved
default behavior for 06cb:00c9.
Confirm Windows Hello before work and after each gate: read-only probe; stable
snapshot; imported-pairing TLS/list; one wrong-finger test; one selected-template
test; isolated libfprint; custom fprintd; PAM with password fallback; then five
alternating Windows/Linux boot cycles. Emit a terminal bell immediately before
every requested touch. Only one layer owns retries.

Stop immediately on any snapshot change, identity mismatch, pairing failure,
unclassified command requirement, bootloader state, stale TLS after the single
bounded close attempt, or Windows Hello failure. Do not reset, clear, repair,
re-pair, or use BIOS recovery automatically. A failed reuse attempt is a safe
refusal, not permission to pair.

The first two standalone gates are implemented but must not be run without
separate approval of the exact command:

```bash
tudor-safe probe --vid 06cb --pid 00c9
tudor-safe snapshot --vid 06cb --pid 00c9
```

Neither command configures or resets USB, detaches a kernel driver, starts TLS,
or performs recovery. Both refuse an active remote TLS session, bootloader mode,
active kernel ownership, missing USB serial, malformed responses, and any
command outside the read-only policy.

On one approved 06cb:00c9 Windows Restart experiment, a USB reset left remote
TLS active. One separately approved plaintext GET_VERSION returned `0x0315` and
cleared it. The pre-authentication snapshot matched the saved baseline and
Linux verification matched. After installing the default driver path, another
Windows Restart was followed by successful Linux fingerprint login and a
successful Windows Hello check; the snapshot remained unchanged. This is one
validated recovery cycle, not proof across all devices or firmware. GET_VERSION
is **not** read-only while foreign TLS is active. The C driver performs at most
one GET_VERSION close attempt for `06cb:00c9`, checks remote TLS status
afterward, and retains the hard refusal if TLS remains active. This closes a
volatile TLS session; it does not reset the sensor or guarantee a power cycle.

The tested Ubuntu PAM setup gives scan retries to the dedicated
`gdm-fingerprint` service (`max-tries=5 timeout=60`) and makes the
`gdm-password` service skip the fingerprint module included by `common-auth`.
The password modules remain active. A failed scan followed by a second touch
logged in successfully. PAM syntax is machine-specific and is not installed by
the coexistence package.

The later authenticated commands are `tudor-safe list BUNDLE --sensor-key KEY`
and `tudor-safe verify BUNDLE TEMPLATE_SHA256 --sensor-key KEY`. Both compare
full `SnapshotV1` values before and after their operation. Verification accepts
only one listed hash and emits the terminal bell immediately before capture.
