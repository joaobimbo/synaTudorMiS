from .cmd import *
from .context import *

import tudor.sensor

@cmd("test")
class CmdTest(Command):
    """
    Usage: test
    """

    def run(self, ctx: CmdContext, args: list):
        ctx.sensor.test()

@cmd("gpio_write_test")
class CmdGpioWrite(Command):
    """
    Tries to send request for state change to GPIO AL0 pin (will likely enable/disable power button)
    Usage: gpio_write_test <state: True/False>
    """

    def run(self, ctx: CmdContext, args: list):
        if len(args) <= 0:
            raise Exception("No state specified!")
        normalized = args[0].strip().lower()
        if normalized not in ("true", "false"):
            raise ValueError("state must be true or false")
        state = normalized == "true"

        ctx.sensor.gpio_write(state)
