"""Versioned, offline-only coexistence data formats."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from .sensor.pair import SensorCertificate, SensorPairingData


def _decode_field(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be Base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{name} is not valid Base64") from exc


@dataclass(frozen=True)
class PairingBundleV1:
    vid: int
    pid: int
    usb_serial: str
    private_sensor_identity: bytes
    host_private_scalar: bytes
    host_certificate: bytes
    sensor_certificate: bytes

    @classmethod
    def load(cls, path: str | os.PathLike[str], *, require_owner_only: bool = True):
        source = Path(path)
        mode = source.stat().st_mode & 0o777
        if require_owner_only and mode & 0o077:
            raise PermissionError(f"{source} permissions must be 0600 or stricter")
        raw = json.loads(source.read_text(encoding="utf-8"))
        if raw.get("format") != "PairingBundleV1":
            raise ValueError("unsupported pairing bundle format")
        bundle = cls(
            int(raw["vid"]), int(raw["pid"]), str(raw["usb_serial"]),
            _decode_field(raw["private_sensor_identity"], "private_sensor_identity"),
            _decode_field(raw["host_private_scalar"], "host_private_scalar"),
            _decode_field(raw["host_certificate"], "host_certificate"),
            _decode_field(raw["sensor_certificate"], "sensor_certificate"),
        )
        bundle.validate()
        return bundle

    def validate(self, *, expected_vid: int | None = None, expected_pid: int | None = None,
                 expected_serial: str | None = None,
                 sensor_signing_key: ec.EllipticCurvePublicKey | None = None) -> None:
        if not 0 <= self.vid <= 0xFFFF or not 0 <= self.pid <= 0xFFFF:
            raise ValueError("VID/PID must be 16-bit values")
        if not self.usb_serial or "\0" in self.usb_serial:
            raise ValueError("USB serial is missing or invalid")
        if len(self.private_sensor_identity) != 8:
            raise ValueError("private sensor identity must be exactly 8 bytes")
        if not 0 < len(self.host_private_scalar) <= 32:
            raise ValueError("host private scalar must be 1..32 bytes")
        scalar = int.from_bytes(self.host_private_scalar, "big")
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        host = SensorCertificate.frombytes(self.host_certificate)
        sensor = SensorCertificate.frombytes(self.sensor_certificate)
        if key.public_key().public_numbers() != host.pub_key.public_numbers():
            raise ValueError("private key does not match host certificate")
        if expected_vid is not None and self.vid != expected_vid:
            raise ValueError("VID mismatch")
        if expected_pid is not None and self.pid != expected_pid:
            raise ValueError("PID mismatch")
        if expected_serial is not None and self.usb_serial != expected_serial:
            raise ValueError("USB serial mismatch")
        if sensor_signing_key is not None:
            sensor_signing_key.verify(sensor.signature, sensor.signbytes(), ec.ECDSA(hashes.SHA256()))

    def private_key_pem(self) -> bytes:
        key = ec.derive_private_key(int.from_bytes(self.host_private_scalar, "big"), ec.SECP256R1())
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    def sensor_pairing_data(self) -> SensorPairingData:
        key = ec.derive_private_key(int.from_bytes(self.host_private_scalar, "big"), ec.SECP256R1())
        return SensorPairingData(key, SensorCertificate.frombytes(self.host_certificate),
                                 SensorCertificate.frombytes(self.sensor_certificate))

    def validate_private_identity(self, observed: bytes) -> None:
        if observed != self.private_sensor_identity:
            raise RuntimeError("private sensor identity mismatch; refusing pairing reuse")


def load_tudor_sensor_key(path: str | os.PathLike[str]) -> ec.EllipticCurvePublicKey:
    raw = Path(path).read_bytes()
    # Vendor .tsk records contain the 0x88-byte little-endian X/Y key used by
    # the original driver, optionally padded to 0x100 bytes with zeroes.
    if len(raw) not in (0x88, 0x100) or any(raw[0x88:]):
        raise ValueError("Tudor sensor key must be 136 bytes or a zero-padded 256-byte record")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(raw[:0x44], "little"),
                                         int.from_bytes(raw[0x44:0x88], "little"),
                                         ec.SECP256R1()).public_key()


def find_bundled_sensor_key(bundle: PairingBundleV1) -> Path:
    """Select the sole bundled firmware key that signs the sensor certificate."""
    directory = Path(__file__).parent / "sensor" / "sensor_keys"
    matches = []
    for path in sorted(directory.glob("*.tsk")):
        try:
            bundle.validate(sensor_signing_key=load_tudor_sensor_key(path))
        except Exception:
            continue
        matches.append(path)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one matching bundled sensor key; found {len(matches)}")
    return matches[0]


@dataclass(frozen=True)
class SnapshotV1:
    firmware: str
    security_state: str
    provision_state: str
    host_partition_sha256: str
    db2_version: int
    db2_counts: dict[str, int]
    object_id_sha256: tuple[str, ...]
    format: str = "SnapshotV1"

    def to_json(self) -> str:
        data = asdict(self)
        data["object_id_sha256"] = sorted(data["object_id_sha256"])
        return json.dumps(data, sort_keys=True, indent=2) + "\n"

    def assert_unchanged(self, other: "SnapshotV1") -> None:
        if self != other:
            raise RuntimeError("sensor snapshot changed; stop coexistence testing")


@dataclass(frozen=True)
class PreAuthSnapshotV1:
    firmware: str
    security_state: str
    provision_state: str
    host_partition_sha256: str
    format: str = "PreAuthSnapshotV1"

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"

    def assert_unchanged(self, other: "PreAuthSnapshotV1") -> None:
        if self != other:
            raise RuntimeError("pre-authentication sensor snapshot changed; stop testing")


@dataclass(frozen=True)
class HostPartitionExportV1:
    vid: int
    pid: int
    usb_serial: str
    private_sensor_identity: bytes
    host_partition_sha256: str
    wrapped_pairing: bytes
    format: str = "HostPartitionExportV1"

    def to_json(self) -> str:
        return json.dumps({
            "format": self.format,
            "vid": self.vid,
            "pid": self.pid,
            "usb_serial": self.usb_serial,
            "private_sensor_identity": base64.b64encode(
                self.private_sensor_identity).decode("ascii"),
            "host_partition_sha256": self.host_partition_sha256,
            "wrapped_pairing": base64.b64encode(self.wrapped_pairing).decode("ascii"),
        }, sort_keys=True, indent=2) + "\n"


def extract_wrapped_pairing(host_partition: bytes) -> bytes:
    """Validate a 4 KiB Windows hash-tag container and return tag 2 only."""
    if len(host_partition) != 0x1000:
        raise ValueError("host partition must be exactly 4096 bytes")
    values: dict[int, bytes] = {}
    offset = 0
    terminated = False
    while offset + 2 <= len(host_partition):
        tag = int.from_bytes(host_partition[offset:offset + 2], "little")
        if tag == 0xFFFF:
            terminated = True
            offset += 2
            break
        if offset + 36 > len(host_partition):
            raise ValueError("truncated host-partition entry header")
        size = int.from_bytes(host_partition[offset + 2:offset + 4], "little")
        end = offset + 36 + size
        if end > len(host_partition):
            raise ValueError("truncated host-partition entry")
        if tag in values:
            raise ValueError(f"duplicate host-partition tag {tag}")
        stored_hash = host_partition[offset + 4:offset + 36]
        value = host_partition[offset + 36:end]
        if hashlib.sha256(value).digest() != stored_hash:
            raise ValueError(f"host-partition tag {tag} hash mismatch")
        values[tag] = value
        offset = end
    if not terminated:
        raise ValueError("host partition has no terminator")
    if any(byte not in (0x00, 0xFF) for byte in host_partition[offset:]):
        raise ValueError("host partition has non-padding data after terminator")
    if values.get(1) != b"\x01\x00\x00\x00":
        raise ValueError("unsupported host-partition version")
    wrapped = values.get(2)
    if not wrapped or len(wrapped) < 16:
        raise ValueError("host partition has no wrapped pairing field")
    version, clear_len, protected_len, hash_len = struct.unpack("<IIII", wrapped[:16])
    if version != 1 or clear_len != 0:
        raise ValueError("unsupported Windows secure-wrapper header")
    if 16 + clear_len + protected_len + hash_len != len(wrapped):
        raise ValueError("Windows secure-wrapper lengths are inconsistent")
    if protected_len == 0 or hash_len == 0:
        raise ValueError("Windows secure-wrapper has an empty protected region")
    return wrapped
