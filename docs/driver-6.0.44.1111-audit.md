# Synaptics driver 6.0.44.1111 offline audit

This audit applies only to `synaWudfBioUsb111.dll` with SHA-256
`da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60`.
Addresses are preferred-image virtual addresses with image base
`0x180000000`; WinDbg offsets below are relative to exported
`FxDriverEntryUm` at RVA `0x21c90`.

## Pairing read path

Static comparison against analyzed build 6.0.59.1111 establishes these
instruction-equivalent functions:

| Purpose | 6.0.44 address | 6.0.59 address |
|---|---:|---:|
| `palSecureUnwrap` wrapper | `0x1800683f0` | `0x18006c370` |
| DPAPI/MAC unwrap core | `0x180068ea0` | `0x18006ce20` |
| `tudorSecurityGetPairingData` | `0x1800871a0` | `0x18008be00` |
| `_unwrapPairingData` | `0x180089070` | `0x18008dce0` |

The pairing getter copies the existing wrapped blob from the device context,
calls `_unwrapPairingData` at `0x18008728b`, and then parses the returned
plaintext. `_unwrapPairingData` calls `palSecureUnwrap` twice: first to obtain
the required allocation size, then at `0x1800891f4` to fill the allocated
buffer. The pairing-specific post-return instruction is `0x1800891f9`, or
`FxDriverEntryUm+0x67569`. At that instruction the caller's output blob pointer
is stored at `[rsp+0x68]`; its 32-bit length is at offset 0 and data pointer at
offset 8.

The generic `CryptUnprotectData` return sites (`0x1800692fd` and
`0x1800694d5`) are unsuitable breakpoints because they can expose unrelated
DPAPI plaintext. The late-attach lock/unlock method is also unreliable because
the active pairing path has already executed.

## Windows persistence path

The exact DLL opens `HKEY_CURRENT_USER\Software\Synaptics\PairingData`
read-only at
`0x180003d9d` and reads a binary value with `RegQueryValueExW`. The value name
is constructed at `0x180009191` as 16 uppercase hexadecimal characters from
the eight private-identity bytes.

The secure-wrapper header is four little-endian `uint32` fields: version,
clear-region length, DPAPI-region length, and protected-hash length. For
pairing data, version is 1 and the clear region is empty. The DLL computes
SHA-256 over the header, clear region, and still-protected DPAPI region at
`0x18006923b`; it decrypts and compares the separately DPAPI-protected hash,
then decrypts the pairing region at `0x1800694d0`. Both
`CryptUnprotectData` calls use current-user scope, flags zero, and no optional
entropy. Runtime observation establishes that the UMDF host's current user is
Local Service, whose hive is `HKEY_USERS\S-1-5-19`, and that the value for the
observed sensor is zero length. It is therefore a fallback slot, not the active
pairing source, on this installation. The withdrawn interactive-user registry
exporter could not have decrypted this context or recovered an empty value.

The registry load happens only after initial device initialization returns
missing-pairing status (`0x800700cc`), as shown by the branch at
`0x180003fe3`. Consequently, attaching WinDbg after successful initialization
and then performing an ordinary verification does not reliably execute the
unwrap path. The former lock/unlock breakpoint procedure was withdrawn.

## Container evidence

The prior 6.0.59 trace shows a little-endian `<uint16 tag, uint32 length,
bytes>` container ordered `2, 0, 1, 4, 3`. Required bundle fields are version
tag 0, 400-byte host certificate tag 1, 32-byte private scalar tag 2, and
400-byte sensor certificate tag 3. Tag 4 is auxiliary public-key security data;
tag 5 is an optional storage PSK identifier. `Export-Pairing.ps1` validates but
does not export tags 4 or 5, and rejects all unknown tags.

No driver code was executed and no sensor was contacted during this audit.

## Private identity read path

The instruction-equivalent `tudorCmdGetVersion` function is at
`0x18007cff0`. On its successful path it copies the six identity bytes from
GET_VERSION response offsets 18-23 into output-structure offset `0x10`. The
copy returns at `0x18007d260`, or `FxDriverEntryUm+0x5b5d0`; the output pointer
is `[rsp+0x78]`. A breakpoint there can write exactly six bytes from
`poi(@rsp+0x78)+0x10`, without recording the rest of the response. The bundle
converter appends the two zero bytes used by the driver/prototype's normalized
eight-byte identity.

## Operational procedure

The technical evidence above is intentionally separate from the operator
instructions. The authoritative from-zero extraction procedure is
[windows-final-export-runbook.md](windows-final-export-runbook.md). Do not copy
commands from older notes or derive offsets for another DLL from this audit.
