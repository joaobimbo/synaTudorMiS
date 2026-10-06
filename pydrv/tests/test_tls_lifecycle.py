import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tudor.sensor.sensor import Sensor
from tudor.tls.session import TlsSession


class FakeComm:
    def __init__(self, *, stale=False, frame_error=False):
        self.stale = stale
        self.frame_error = frame_error
        self.commands = []
        self.tls = None

    def remote_tls_status(self):
        return self.stale

    def set_tls_session(self, session):
        self.tls = session

    def send_command(self, command, _size):
        self.commands.append(command[0])
        if command[0] == 0x19:  # GET_START_INFO
            return bytes(0x44)
        if self.frame_error:
            raise RuntimeError("frame state failed")
        return bytes(0x22)


class TlsLifecycleTests(unittest.TestCase):
    def make_sensor(self, comm):
        sensor = Sensor(comm)
        sensor.read_state = Mock()
        sensor.in_bootloader_mode = Mock(return_value=False)
        sensor.is_paired = Mock(return_value=True)
        sensor.advanced_security = True
        sensor.id = b"fixture"
        sensor.pub_key = SimpleNamespace(verify=Mock())
        sensor.fw_major = sensor.fw_minor = sensor.fw_build_num = 0
        sensor.key_flag = sensor.product_id = sensor.prov_state = 0
        return sensor

    @staticmethod
    def pairing():
        numbers = object()
        key = SimpleNamespace(public_key=lambda: SimpleNamespace(
            public_numbers=lambda: numbers))
        cert = SimpleNamespace(signature=b"", signbytes=lambda: b"",
                               pub_key=SimpleNamespace(public_numbers=lambda: numbers))
        return SimpleNamespace(priv_key=key, host_cert=cert, sensor_cert=cert)

    def test_stale_remote_session_refuses_without_command(self):
        comm = FakeComm(stale=True)
        sensor = self.make_sensor(comm)
        with self.assertRaisesRegex(RuntimeError, "stale remote TLS"):
            sensor.initialize(self.pairing(), expected_private_identity=b"fixture")
        self.assertEqual(comm.commands, [])
        self.assertIsNone(sensor.tls_session)

    def test_failed_authenticated_open_closes_owned_session(self):
        comm = FakeComm(frame_error=True)
        sensor = self.make_sensor(comm)
        tls = Mock(established=True)
        with patch("tudor.tls.TlsEccRemoteKey"), patch("tudor.tls.TlsSession", return_value=tls):
            with self.assertRaisesRegex(RuntimeError, "frame state failed"):
                sensor.initialize(self.pairing(), expected_private_identity=b"fixture")
        tls.close.assert_called_once_with()
        self.assertIsNone(comm.tls)
        self.assertIsNone(sensor.tls_session)

    def test_event_cleanup_error_still_closes_owned_session(self):
        comm = FakeComm()
        sensor = self.make_sensor(comm)
        sensor.initialized = True
        tls = Mock(established=True)
        sensor.tls_session = tls
        sensor.event_handler = SimpleNamespace(
            event_mask=[1], set_event_mask=Mock(side_effect=RuntimeError("event failed")))
        with self.assertRaisesRegex(RuntimeError, "event failed"):
            sensor.uninitialize()
        tls.close.assert_called_once_with()
        self.assertIsNone(comm.tls)

    def test_close_error_keeps_session_for_diagnosis(self):
        comm = FakeComm()
        sensor = self.make_sensor(comm)
        sensor.initialized = True
        sensor.event_handler = SimpleNamespace(event_mask=[])
        tls = Mock(established=True)
        tls.close.side_effect = RuntimeError("close failed")
        sensor.tls_session = tls
        with self.assertRaisesRegex(RuntimeError, "close failed"):
            sensor.uninitialize()
        self.assertIs(sensor.tls_session, tls)
        self.assertTrue(sensor.initialized)
        self.assertIsNone(comm.tls)

    def test_tls_close_sends_notify_and_requires_remote_clear(self):
        class RawComm:
            def __init__(self, stale):
                self.stale = stale
                self.sent = []

            def send_command(self, data, size, *, raw):
                self.sent.append((data, size, raw))
                return b""

            def remote_tls_status(self):
                return self.stale

        for stale in (False, True):
            with self.subTest(stale=stale):
                comm = RawComm(stale)
                session = TlsSession(comm, None)
                session.established = True
                record = Mock()
                session.record_layer = record
                record.has_data.side_effect = [True, False]
                record.flush_send_buffer.return_value = b"\x15notify"
                if stale:
                    with self.assertRaisesRegex(RuntimeError, "still reports TLS"):
                        session.close()
                    self.assertTrue(session.established)
                else:
                    session.close()
                    self.assertFalse(session.established)
                self.assertEqual(comm.sent, [(b"\x15notify", 0x964, True)])
                record.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
