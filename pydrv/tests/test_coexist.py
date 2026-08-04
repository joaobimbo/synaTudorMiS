import base64
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from tudor.coexist import (HostPartitionExportV1, PairingBundleV1,
                           PreAuthSnapshotV1, SnapshotV1,
                           extract_wrapped_pairing, find_bundled_sensor_key,
                           load_tudor_sensor_key)
from tudor.claims import ClaimStore, TemplateRefV1
from tudor.gvariant import (atomic_write_owner_only, serialize_pairing_data,
                            serialize_template_ref)
from tudor.hardware import (ProbeV1, export_host_pairing_transport,
                            parse_version_response, preauth_snapshot_transport,
                            probe_transport,
                            sanitize_template_list, select_template,
                            snapshot_transport)
from tudor.sensor.pair import SensorCertificate
from tudor.sensor.sensor import Sensor


class CoexistFormatsTests(unittest.TestCase):
    @staticmethod
    def _host_partition_fixture():
        wrapped = struct.pack("<IIII", 1, 0, 4, 3) + b"ABCD" + b"XYZ"

        def entry(tag, value):
            return (struct.pack("<HH", tag, len(value)) +
                    hashlib.sha256(value).digest() + value)

        contents = (entry(1, b"\x01\x00\x00\x00") + entry(2, wrapped) +
                    b"\xff\xff")
        return contents + bytes(0x1000 - len(contents)), wrapped

    def test_host_partition_export_extracts_only_validated_wrapped_pairing(self):
        partition, wrapped = self._host_partition_fixture()
        self.assertEqual(extract_wrapped_pairing(partition), wrapped)
        damaged = bytearray(partition)
        damaged[4] ^= 1
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            extract_wrapped_pairing(bytes(damaged))

    def test_host_partition_export_transcript_is_two_read_commands(self):
        partition, wrapped = self._host_partition_fixture()
        fixture_identity = bytes.fromhex("010203040506")
        version = struct.pack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", 12, 10, 1,
                              ord("A"), fixture_identity, 1, 0x20, 3)

        class Transcript:
            def __init__(self):
                self.sent = []

            def remote_tls_status(self):
                return False

            def send_command(self, command, _size):
                self.sent.append(command[0])
                if command[0] == 0x01:
                    return version
                if command[0] == 0x40:
                    return (b"\0\0" + (0x1000).to_bytes(4, "little") +
                            b"\0\0" + partition)
                raise AssertionError("unexpected command")

        transcript = Transcript()
        result = export_host_pairing_transport(
            transcript, vid=0x06CB, pid=0x00C9, usb_serial="fixture")
        self.assertIsInstance(result, HostPartitionExportV1)
        self.assertEqual(transcript.sent, [0x01, 0x40])
        self.assertEqual(result.private_sensor_identity,
                         fixture_identity + b"\0\0")
        self.assertEqual(result.wrapped_pairing, wrapped)
        self.assertEqual(result.host_partition_sha256,
                         hashlib.sha256(partition).hexdigest())

    def test_host_partition_export_refuses_stale_tls_without_command(self):
        class Transcript:
            sent = False

            def remote_tls_status(self):
                return True

            def send_command(self, *_args):
                self.sent = True

        transcript = Transcript()
        with self.assertRaisesRegex(RuntimeError, "active TLS"):
            export_host_pairing_transport(
                transcript, vid=0x06CB, pid=0x00C9, usb_serial="fixture")
        self.assertFalse(transcript.sent)

    def test_bundled_sensor_keys_load_from_padded_vendor_records(self):
        keys = Path(__file__).parents[1] / "tudor" / "sensor" / "sensor_keys"
        for name in ("10.1.tsk", "10.1-kf.tsk"):
            key = load_tudor_sensor_key(keys / name)
            self.assertEqual(key.curve.name, "secp256r1")

    def test_windows_exporter_has_no_sensor_or_debugger_actions(self):
        script = (Path(__file__).parents[2] / "windows" / "Export-Pairing.ps1").read_text()
        for forbidden in ("DeviceIoControl", "WinDbg", "PAIR", "Set-PnpDevice",
                          "Disable-PnpDevice", "Enable-PnpDevice"):
            self.assertNotIn(forbidden, script)
        self.assertIn("SetAccessRuleProtection($true, $false)", script)
        self.assertIn("if ($tag -gt 5)", script)
        self.assertIn("$sensor = $values[3]", script)
        self.assertNotIn("$values[4]", script)
        self.assertNotIn("$values[5]", script)
        self.assertNotIn("$Pid", script)
        self.assertIn("[int]$ProductId", script)
        self.assertIn("[int]$tag = [BitConverter]::ToUInt16", script)
        self.assertIn("[int]$length = [BitConverter]::ToUInt32", script)

    def test_windows_controller_uses_non_reserved_product_id_parameter(self):
        script = (Path(__file__).parents[2] / "windows" /
                  "Complete-PairingExport.ps1").read_text()
        self.assertIn("-ProductId 0x00c9", script)
        self.assertNotIn("-Pid 0x00c9", script)

    def test_windows_metadata_collector_is_read_only(self):
        script = (Path(__file__).parents[2] / "windows" / "Collect-DriverMetadata.ps1").read_text()
        for forbidden in ("DeviceIoControl", "WinDbg", "Set-PnpDevice",
                          "Disable-PnpDevice", "Enable-PnpDevice", "pnputil"):
            self.assertNotIn(forbidden, script)
        self.assertIn("Get-FileHash -Algorithm SHA256", script)
        self.assertNotIn("$infBase", script)
        self.assertIn("$_.VersionInfo.FileVersion -eq $driver.DriverVersion", script)
        self.assertIn("USB\\VID_06CB&PID_00C9\\*", script)
        self.assertIn("usb_serial = $usbSerial", script)

    def test_windows_export_preparation_is_hash_pinned_and_non_mutating(self):
        script = (Path(__file__).parents[2] / "windows" /
                  "Prepare-PairingExport.ps1").read_text()
        self.assertIn("da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60",
                      script)
        self.assertIn("SetAccessRuleProtection($true, $false)", script)
        for forbidden in ("DeviceIoControl", "Set-PnpDevice", "Disable-PnpDevice",
                          "Enable-PnpDevice", "pnputil", "PAIR"):
            self.assertNotIn(forbidden, script)

    def test_fprintd_patch_is_synatlsmoc_load_only(self):
        patch = (Path(__file__).parents[2] / "libfprint" /
                 "fprintd-load-store-persistent-data-from-device.patch").read_text()
        self.assertIn("file_storage_persistent_data_load", patch)
        self.assertIn('g_strcmp0 (fp_device_get_driver (priv->dev), "synatlsmoc")', patch)
        self.assertNotIn("persistent_data_save", patch)
        self.assertNotIn("g_unlink", patch)

    def test_final_windows_runbook_refuses_empty_registry_fallback(self):
        runbook = (Path(__file__).parents[2] / "docs" /
                   "windows-final-export-runbook.md").read_text()
        self.assertIn("HKEY_USERS\\S-1-5-19\\Software\\Synaptics\\PairingData", runbook)
        self.assertIn("`Length` zero", runbook)
        self.assertIn("Linux and export the wrapped field", runbook)
        self.assertNotIn("bu /1", runbook)
        self.assertIn("do not use WinDbg", runbook)
        self.assertNotIn('Get-Content -LiteralPath "$Export\\PairingBundleV1.json"', runbook)

    def test_windows_local_service_exporter_is_bounded_and_non_mutating(self):
        script = (Path(__file__).parents[2] / "windows" /
                  "Complete-PairingExport.ps1").read_text()
        self.assertIn("NT AUTHORITY\\LOCAL SERVICE", script)
        self.assertIn("ProtectedData]::Unprotect", script)
        self.assertIn("Unregister-ScheduledTask", script)
        self.assertIn("decrypted pairing container must be 1284 bytes", script)
        self.assertIn("wrapped-pairing SHA-256 mismatch", script)
        self.assertIn("TudorPairingExport-diagnostic-", script)
        self.assertIn("DPAPI could not decrypt the pairing data as Local Service", script)
        self.assertNotIn("status.txt", script)
        for forbidden in ("DeviceIoControl", "Set-PnpDevice", "Disable-PnpDevice",
                          "Enable-PnpDevice", "PAIR", "SetValue("):
            self.assertNotIn(forbidden, script)

    def test_windows_chatgpt_handoff_has_safe_exact_diagnostics(self):
        handoff = (Path(__file__).parents[2] / "docs" /
                   "windows-chatgpt-handoff.md").read_text()
        self.assertIn("$HostExport", handoff)
        self.assertNotIn("$Input", handoff)
        self.assertIn("TudorPairingExport-diagnostic-", handoff)
        self.assertIn("Local Service could not write", handoff)
        self.assertIn("Do not suggest or run", handoff)
        self.assertIn("shutdown.exe /s /t 0", handoff)
        self.assertNotIn("TudorFinalWindowsExport-v4", handoff)

    def test_windows_runbook_uses_discovery_and_current_script_parameters(self):
        root = Path(__file__).parents[2]
        runbook = (root / "docs" / "windows-final-export-runbook.md").read_text()
        exporter = (root / "windows" / "Export-Pairing.ps1").read_text()
        controller = (root / "windows" / "Complete-PairingExport.ps1").read_text()
        self.assertIn("USB\\VID_06CB&PID_00C9\\*", runbook)
        self.assertIn("FileRepository", runbook)
        self.assertIn("shutdown.exe /s /t 0", runbook)
        self.assertIn("`Prepare-PairingExport.ps1` belongs to the withdrawn", runbook)
        required_block = runbook[runbook.index("Copy these three"):runbook.index("## 2.")]
        self.assertNotIn("windows\\Prepare-PairingExport.ps1", required_block)
        self.assertIn("[int]$ProductId", exporter)
        self.assertIn("-ProductId 0x00c9", controller)
        self.assertNotIn("-Pid 0x00c9", controller)
        self.assertNotIn("utf8NoBOM", runbook)
        self.assertNotIn("$Input", runbook)

    def test_driver_6044_audit_and_export_are_hash_pinned_without_vendor_binary(self):
        root = Path(__file__).parents[2]
        expected = "da51a2461e7b4c2d9c2e4054337c5250b6f15c921ed77dc0181d17b56378ec60"
        audit = (root / "docs" / "driver-6.0.44.1111-audit.md").read_text()
        collector = (root / "windows" / "Collect-DriverMetadata.ps1").read_text()
        controller = (root / "windows" / "Complete-PairingExport.ps1").read_text()
        self.assertIn(expected, audit)
        self.assertIn("Get-FileHash -Algorithm SHA256", collector)
        self.assertIn(expected, controller)

    def test_compiled_driver_registers_only_verify_and_list(self):
        source = (Path(__file__).parents[2] / "libfprint" / "libfprint" /
                  "libfprint" / "drivers" / "synatlsmoc" / "synatlsmoc.c").read_text()
        class_init = source[source.index("fpi_device_synatlsmoc_class_init"):]
        self.assertIn("dev_class->verify =", class_init)
        self.assertIn("dev_class->list =", class_init)
        self.assertIn("dev_class->features |= FP_DEVICE_FEATURE_STORAGE", class_init)
        for feature in ("enroll", "identify", "delete", "clear_storage"):
            self.assertNotIn(f"dev_class->{feature} =", class_init)

    def test_python_event_handler_construction_does_not_configure_sensor(self):
        source = (Path(__file__).parents[1] / "tudor" / "sensor" / "event.py").read_text()
        constructor = source[source.index("def __init__", source.index("class SensorEventHandler")):
                             source.index("def set_event_mask", source.index("class SensorEventHandler"))]
        self.assertNotIn("set_event_mask(", constructor)

    def test_c_command_policy_has_default_deny(self):
        source = (Path(__file__).parents[2] / "libfprint" / "libfprint" /
                  "libfprint" / "drivers" / "synatlsmoc" / "synatlsmoc.c").read_text()
        policy = source[source.index("coexist_command_allowed"):source.index("synatlsmoc_exec_cmd")]
        self.assertIn("default:", policy)
        self.assertIn("return FALSE", policy)

    def test_c_diagnostics_hash_payloads_and_never_log_private_pem(self):
        driver = Path(__file__).parents[2] / "libfprint" / "libfprint" / "libfprint" / "drivers" / "synatlsmoc"
        utils = (driver / "utils.c").read_text()
        source = (driver / "synatlsmoc.c").read_text()
        self.assertIn("G_CHECKSUM_SHA256", utils)
        self.assertIn('sha256:%s', utils)
        self.assertNotIn('fp_dbg ("\\tPEM private key:', source)
        policy = source[source.index("coexist_command_allowed"):source.index("synatlsmoc_exec_cmd")]
        for forbidden in ("VCSFW_CMD_PAIR", "VCSFW_CMD_DB2_WRITE_OBJECT",
                          "VCSFW_CMD_DB2_DELETE_OBJECT", "VCSFW_CMD_DB2_FORMAT"):
            self.assertNotIn(f"case {forbidden}", policy)

    def test_pairing_bundle_key_match_and_permissions(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = SensorCertificate(0, key.public_key(), b"").tobytes()
        other = SensorCertificate(1, ec.generate_private_key(ec.SECP256R1()).public_key(), b"").tobytes()
        data = {"format": "PairingBundleV1", "vid": 0x06CB, "pid": 0x00C9,
                "usb_serial": "fixture", "private_sensor_identity": base64.b64encode(b"sensorid").decode(),
                "host_private_scalar": base64.b64encode(key.private_numbers().private_value.to_bytes(32, "big")).decode(),
                "host_certificate": base64.b64encode(cert).decode(),
                "sensor_certificate": base64.b64encode(other).decode()}
        with tempfile.NamedTemporaryFile("w", delete=False) as stream:
            json.dump(data, stream)
            path = stream.name
        try:
            os.chmod(path, 0o600)
            PairingBundleV1.load(path).validate(expected_vid=0x06CB, expected_pid=0x00C9)
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                PairingBundleV1.load(path)
        finally:
            os.unlink(path)

    def test_pairing_bundle_refuses_private_identity_mismatch(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = SensorCertificate(0, key.public_key(), b"").tobytes()
        sensor = SensorCertificate(1, ec.generate_private_key(ec.SECP256R1()).public_key(), b"").tobytes()
        bundle = PairingBundleV1(0x06CB, 0x00C9, "x", b"expected",
                                 key.private_numbers().private_value.to_bytes(32, "big"), cert, sensor)
        with self.assertRaises(RuntimeError):
            bundle.validate_private_identity(b"different")

    def test_snapshot_detects_change(self):
        base = SnapshotV1("1", "advanced", "provisioned", "a", 1, {"templates": 1}, ("b",))
        same = SnapshotV1("1", "advanced", "provisioned", "a", 1, {"templates": 1}, ("b",))
        base.assert_unchanged(same)
        with self.assertRaises(RuntimeError):
            base.assert_unchanged(SnapshotV1("2", "advanced", "provisioned", "a", 1, {"templates": 1}, ("b",)))

    def test_preauth_snapshot_reads_host_partition_only(self):
        class Transcript:
            def __init__(self):
                self.sent = []

            def send_command(self, command, _size):
                self.sent.append(command[0])
                if command[0] != 0x40:
                    raise AssertionError("pre-authentication snapshot attempted DB2")
                return (b"\0\0" + (0x1000).to_bytes(4, "little") +
                        b"\0\0" + b"h" * 0x1000)

        observed = ProbeV1("06cb-00c9-x", 0x06CB, 0x00C9, "x", "10.1.12",
                           ord("A"), True, True, 3)
        transcript = Transcript()
        result = preauth_snapshot_transport(transcript, observed)
        self.assertIsInstance(result, PreAuthSnapshotV1)
        self.assertEqual(transcript.sent, [0x40])
        self.assertEqual(result.format, "PreAuthSnapshotV1")

    def test_claim_is_atomic_local_and_unclaim_only_removes_file(self):
        with tempfile.TemporaryDirectory() as root:
            store = ClaimStore(root)
            ref = TemplateRefV1("01" * 16, "right-index-finger")
            path = store.claim("alice", "06cb-00c9-serial", ref, require_root=False)
            self.assertEqual(path.name, "7")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(path.read_bytes().startswith(b"FP3"))
            store.unclaim("alice", "06cb-00c9-serial", ref.finger, require_root=False)
            self.assertFalse(path.exists())

    def test_template_reference_is_fp3_and_omits_windows_sid(self):
        data = serialize_template_ref("06cb-00c9-fixture", "alice",
                                      "right-index-finger", 3, b"t" * 16)
        self.assertEqual(data[:3], b"FP3")
        self.assertIn(b"synatlsmoc", data)
        self.assertIn(b"alice", data)
        self.assertNotIn(b"windows", data.lower())

    def test_claim_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as root:
            store = ClaimStore(root)
            ref = TemplateRefV1("01" * 16, "right-index-finger")
            with self.assertRaises(ValueError):
                store.claim("../root", "device", ref, require_root=False)

    def test_pairing_gvariant_is_serialized_owner_only(self):
        data = serialize_pairing_data("06cb-00c9-fixture", b"h" * 400,
                                      b"s" * 400, b"PEM fixture")
        self.assertGreater(len(data), 800)
        with tempfile.TemporaryDirectory() as root:
            path = atomic_write_owner_only(os.path.join(root, "pairing"), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), data)

    def test_probe_refuses_stale_tls_before_command(self):
        class Fake:
            sent = False
            def remote_tls_status(self): return True
            def send_command(self, *_args, **_kwargs):
                self.sent = True
        fake = Fake()
        with self.assertRaises(RuntimeError):
            probe_transport(fake, vid=0x06CB, pid=0x00C9, usb_serial="fixture")
        self.assertFalse(fake.sent)

    def test_probe_parses_public_fields_and_omits_private_identity(self):
        response = struct.pack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", 12, 10, 1,
                               ord("A"), b"secret", 1, 0x20, 3)
        parsed = parse_version_response(response, vid=0x06CB, pid=0x00C9,
                                        usb_serial="fixture")
        rendered = parsed.to_json()
        self.assertEqual(parsed.stable_device_id, "06cb-00c9-fixture")
        self.assertNotIn("secret", rendered)

    def test_probe_refuses_bootloader(self):
        response = struct.pack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", 12, 10, 1,
                               ord("B"), b"secret", 1, 0x20, 3)
        with self.assertRaises(RuntimeError):
            parse_version_response(response, vid=0x06CB, pid=0x00C9,
                                   usb_serial="fixture")

    def test_safe_state_read_omits_firmware_variant_diagnostic_iotas(self):
        response = struct.pack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", 3399660,
                               10, 1, ord("A"), b"secret", 1, 0x20, 3)

        class Transcript:
            def __init__(self):
                self.sent = []

            def send_command(self, command, _size):
                self.sent.append(command[0])
                return response

        transcript = Transcript()
        sensor = Sensor(transcript)
        sensor.read_state(include_diagnostic_iotas=False)
        self.assertEqual(transcript.sent, [0x01])
        self.assertFalse(hasattr(sensor, "wbf_param_iota"))
        self.assertEqual(sensor.id, b"secret\0\0")

    def test_snapshot_hashes_ids_and_never_exposes_them(self):
        user = b"u" * 16
        template = b"t" * 16
        payload = b"p" * 16
        info_fields = (0, 1, 2, 7, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0)
        db2 = struct.pack("<2xHHHLHHHHHHHHHHHHHH", *info_fields)

        class Transcript:
            def send_command(self, command, _size):
                if command[0] == 0x40:
                    return b"\0\0" + (0x1000).to_bytes(4, "little") + b"\0\0" + b"h" * 0x1000
                if command[0] == 0x9E:
                    return db2
                object_type = int.from_bytes(command[1:5], "little")
                value = {1: user, 2: template, 3: payload}[object_type]
                return b"\0\0\1\0" + value

        probe_result = ProbeV1("06cb-00c9-x", 0x06CB, 0x00C9, "x", "10.1.12",
                               ord("A"), True, True, 3)
        snapshot = snapshot_transport(Transcript(), probe_result)
        rendered = snapshot.to_json()
        self.assertNotIn(user.decode(), rendered)
        self.assertNotIn(template.decode(), rendered)
        self.assertNotIn(payload.decode(), rendered)
        self.assertEqual(snapshot.db2_counts["templates"], 1)

    def test_template_listing_suppresses_sid_and_raw_id(self):
        template = b"t" * 16
        sid = b"private-windows-sid"
        listed = sanitize_template_list([(template, sid, b"\xf7")])
        rendered = json.dumps(listed)
        self.assertNotIn(template.decode(), rendered)
        self.assertNotIn(sid.decode(), rendered)
        self.assertEqual(listed[0]["finger_subtype"], "f7")

    def test_verification_selects_exactly_one_hashed_template(self):
        first, second = b"a" * 16, b"b" * 16
        enrollments = [(first, b"sid-1", b"\xf7"),
                       (second, b"sid-2", b"\xf8")]
        selector = __import__("hashlib").sha256(second).hexdigest()
        self.assertEqual(select_template(enrollments, selector), second)
        with self.assertRaises(RuntimeError):
            select_template(enrollments, "0" * 64)
        with self.assertRaises(ValueError):
            select_template(enrollments, "not-hex")


if __name__ == "__main__":
    unittest.main()
