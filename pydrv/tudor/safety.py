"""Non-bypassable command policy for coexistence experiments.

The policy is applied to the plaintext command, before TLS framing.  Anything
not explicitly listed is denied.  In particular, there is intentionally no
"unsafe" mode or environment-variable escape hatch.
"""
from __future__ import annotations

import enum
import hashlib
import json
import logging
from dataclasses import dataclass


class SafetyViolation(PermissionError):
    pass


class SafetyMode(enum.Enum):
    READ_ONLY = "read-only"
    AUTHENTICATED_VERIFY = "authenticated-verify"


# Commands whose use is observational and does not require a TLS session.
READ_COMMANDS = frozenset({
    0x01,  # GET_VERSION
    0x07,  # PEEK
    0x19,  # GET_START_INFO
    0x3E,  # STORAGE_INFO_GET
    0x40,  # STORAGE_PART_READ
    0x50,  # GET_CERTIFICATE_EX
    0x82,  # FRAME_STATE_GET
    0x87,  # EVENT_READ
    0x8E,  # READ_IOTA
    0x9E, 0x9F, 0xA0, 0xA1,  # DB2 reads
    0xAE, 0xAF,  # operation/hardware info
})

# Volatile commands needed for a template-restricted verification.  Subcommand
# validation below prevents 0x96 enrollment and unrestricted 0x99 identify.
VERIFY_COMMANDS = frozenset({0x7F, 0x80, 0x81, 0x86, 0x87, 0x9D, 0x99})


@dataclass(frozen=True)
class AuditRecord:
    direction: str
    command: int
    size: int
    payload_sha256: str
    status: int | None = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))


class SafetyPolicy:
    def __init__(self, mode: SafetyMode = SafetyMode.READ_ONLY):
        self.mode = mode

    def check_command(self, command: bytes, *, tls_active: bool = False,
                      raw: bool = False) -> None:
        if not command:
            raise SafetyViolation("empty command denied")
        if raw:
            if self.mode is not SafetyMode.AUTHENTICATED_VERIFY:
                raise SafetyViolation("raw TLS transport requires authenticated-verify mode")
            if 0x14 <= command[0] <= 0x17:
                return
            if len(command) >= 5 and command[0] == 0x44 and 0x14 <= command[4] <= 0x17:
                return
            raise SafetyViolation("raw transport is not a recognized TLS record")
        command_id = command[0]
        allowed = READ_COMMANDS
        if self.mode is SafetyMode.AUTHENTICATED_VERIFY:
            allowed = allowed | VERIFY_COMMANDS
        if command_id not in allowed:
            raise SafetyViolation(f"command 0x{command_id:02x} denied by {self.mode.value} policy")
        if command_id in (VERIFY_COMMANDS - READ_COMMANDS) and not tls_active:
            raise SafetyViolation(f"verification command 0x{command_id:02x} requires TLS")
        if command_id == 0x99:
            self._check_restricted_match(command)

    @staticmethod
    def _check_restricted_match(command: bytes) -> None:
        # Tudor identify-match contains a little-endian template-array byte
        # length at offset 5. Only one explicit 16-byte reference is allowed.
        if len(command) < 9 or int.from_bytes(command[5:9], "little") != 16:
            raise SafetyViolation("identify-all denied; exactly one template is required")
        if len(command) != 29:
            raise SafetyViolation("truncated template-restricted identify command")

    @staticmethod
    def deny_usb_reset() -> None:
        raise SafetyViolation("USB reset is unproven and denied")

    @staticmethod
    def deny_dft_write() -> None:
        raise SafetyViolation("DFT/control write is permanently denied")


def audit_record(direction: str, command: int, payload: bytes, status: int | None = None) -> AuditRecord:
    """Create a metadata-only record; payload bytes are never logged."""
    return AuditRecord(direction, command, len(payload), hashlib.sha256(payload).hexdigest(), status)


def log_audit(record: AuditRecord) -> None:
    logging.info("protocol-audit %s", record.to_json())
