from .context import *


def parse_hex_bytes(value: str, *, length: int | None = None) -> bytes:
    """Parse plain hexadecimal input without evaluating Python expressions."""
    value = value.removeprefix("0x").replace(":", "")
    if not value or len(value) % 2:
        raise ValueError("expected an even number of hexadecimal digits")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("expected hexadecimal bytes") from exc
    if length is not None and len(result) != length:
        raise ValueError(f"expected exactly {length} bytes")
    return result


class Command:
    commands = {}

    def run(self, ctx: CmdContext, args: list):
        raise NotImplementedError()


def cmd(name: str):
    def wrapper(ctype: type):
        Command.commands[name] = ctype()
        return ctype

    return wrapper
