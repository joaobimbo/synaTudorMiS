import unittest

from tudor.comm import CommandFailedException
from tudor.sensor.sensor import Sensor


class FakeCommunication:
    def __init__(self, statuses):
        self.statuses = iter(statuses)
        self.commands = []

    def send_command(self, command, response_size, check_response=True):
        self.commands.append(command)
        return next(self.statuses).to_bytes(2, "little")


class FrameAcquireTests(unittest.TestCase):
    def test_retries_processing_status_then_succeeds(self):
        sensor = object.__new__(Sensor)
        sensor.comm = FakeCommunication([0x6EA, 0x5CC])

        self.assertTrue(sensor.send_frame_acq(capture_flags=7))
        self.assertEqual(len(sensor.comm.commands), 2)
        self.assertEqual(sensor.comm.commands[0], sensor.comm.commands[1])

    def test_rejected_acquire_raises_numeric_status(self):
        sensor = object.__new__(Sensor)
        sensor.comm = FakeCommunication([0x5CB])

        with self.assertRaises(CommandFailedException) as raised:
            sensor.send_frame_acq(capture_flags=7)
        self.assertEqual(raised.exception.status, 0x5CB)
        self.assertEqual(len(sensor.comm.commands), 1)


if __name__ == "__main__":
    unittest.main()
