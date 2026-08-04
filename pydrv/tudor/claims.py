"""Local-only Linux claims for existing sensor templates."""
from __future__ import annotations

import json
import os
import pwd
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .gvariant import serialize_template_ref


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_FINGERS = frozenset({
    "left-thumb", "left-index-finger", "left-middle-finger",
    "left-ring-finger", "left-little-finger", "right-thumb",
    "right-index-finger", "right-middle-finger", "right-ring-finger",
    "right-little-finger",
})
_FINGER_VALUES = {
    "left-thumb": 1, "left-index-finger": 2, "left-middle-finger": 3,
    "left-ring-finger": 4, "left-little-finger": 5, "right-thumb": 6,
    "right-index-finger": 7, "right-middle-finger": 8,
    "right-ring-finger": 9, "right-little-finger": 10,
}


@dataclass(frozen=True)
class TemplateRefV1:
    template_id: str
    finger: str
    sensor_subtype: int = 0
    format: str = "TemplateRefV1"

    def __post_init__(self):
        try:
            raw = bytes.fromhex(self.template_id)
        except ValueError as exc:
            raise ValueError("template ID must be hexadecimal") from exc
        if len(raw) != 16:
            raise ValueError("template ID must contain exactly 16 bytes")
        if self.finger not in _FINGERS:
            raise ValueError("unsupported finger name")
        if not 0 <= self.sensor_subtype <= 0xff:
            raise ValueError("sensor finger subtype must fit in one byte")

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")) + "\n"


class ClaimStore:
    def __init__(self, root: str | os.PathLike[str] = "/var/lib/fprint"):
        self.root = Path(root)

    @staticmethod
    def _component(value: str, label: str) -> str:
        if not _SAFE_COMPONENT.fullmatch(value) or value in (".", ".."):
            raise ValueError(f"unsafe {label}")
        return value

    def path(self, username: str, stable_device_id: str, finger: str) -> Path:
        self._component(username, "username")
        self._component(stable_device_id, "device ID")
        if finger not in _FINGERS:
            raise ValueError("unsupported finger name")
        return (self.root / username / "synatlsmoc" / stable_device_id /
                format(_FINGER_VALUES[finger], "x"))

    def claim(self, username: str, stable_device_id: str, reference: TemplateRefV1,
              *, require_root: bool = True) -> Path:
        if require_root and os.geteuid() != 0:
            raise PermissionError("claim-existing must run as root")
        if require_root:
            pwd.getpwnam(username)
        target = self.path(username, stable_device_id, reference.finger)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        fd, temporary = tempfile.mkstemp(prefix=".claim-", dir=target.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                data = serialize_template_ref(stable_device_id, username,
                                              reference.finger,
                                              reference.sensor_subtype,
                                              bytes.fromhex(reference.template_id))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return target

    def unclaim(self, username: str, stable_device_id: str, finger: str,
                *, require_root: bool = True) -> None:
        if require_root and os.geteuid() != 0:
            raise PermissionError("unclaim must run as root")
        # This is deliberately the only deletion: no sensor API is involved.
        self.path(username, stable_device_id, finger).unlink(missing_ok=True)
