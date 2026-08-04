import hashlib
import unittest

from tudor.safety import READ_COMMANDS, SafetyMode, SafetyPolicy, SafetyViolation, audit_record


class SafetyPolicyTests(unittest.TestCase):
    def test_every_byte_is_default_denied_or_explicit_read(self):
        policy = SafetyPolicy()
        for command in range(256):
            if command in READ_COMMANDS:
                policy.check_command(bytes([command]))
            else:
                with self.assertRaises(SafetyViolation):
                    policy.check_command(bytes([command]))

    def test_persistent_commands_are_denied_in_both_modes(self):
        for mode in SafetyMode:
            policy = SafetyPolicy(mode)
            for command in (0x08, 0x0E, 0x10, 0x3F, 0x41, 0x47, 0x4F, 0x7D,
                            0x93, 0x96, 0xA2, 0xA3, 0xA4, 0xA5, 0xAA, 0xAC):
                with self.assertRaises(SafetyViolation):
                    policy.check_command(bytes([command]), tls_active=True)

    def test_identify_all_is_denied(self):
        policy = SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY)
        with self.assertRaises(SafetyViolation):
            policy.check_command(b"\x99" + b"\0" * 28, tls_active=True)
        restricted = b"\x99" + b"\0" * 4 + (16).to_bytes(4, "little") + b"\0" * 4 + b"x" * 16
        policy.check_command(restricted, tls_active=True)

    def test_raw_transport_accepts_only_tls_records_in_verify_mode(self):
        read_only = SafetyPolicy()
        verify = SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY)
        for record in (b"\x16tls", b"\x44\0\0\0\x16tls"):
            with self.assertRaises(SafetyViolation):
                read_only.check_command(record, raw=True)
            verify.check_command(record, raw=True)
        for invalid in (b"\x93pair", b"\x44\0\0\0\x93pair", b"\xff"):
            with self.assertRaises(SafetyViolation):
                verify.check_command(invalid, raw=True)

    def test_tls_outer_command_is_never_accepted_as_plaintext(self):
        policy = SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY)
        with self.assertRaises(SafetyViolation):
            policy.check_command(b"\x44\0\0\0\x16tls", tls_active=True)

    def test_audit_contains_hash_not_payload(self):
        secret = b"private-key-material"
        rendered = audit_record("request", 1, secret).to_json()
        self.assertNotIn(secret.decode(), rendered)
        self.assertIn(hashlib.sha256(secret).hexdigest(), rendered)


if __name__ == "__main__":
    unittest.main()
