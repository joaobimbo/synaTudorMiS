"""Hardware-gated, observational coexistence operations.

Nothing in this module resets, configures, detaches, pairs, or recovers a
sensor. Callers are responsible for displaying the exact command and obtaining
approval before invoking :func:`probe`.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pwd
import struct

from .comm import Command, SafetyMode, SafetyPolicy, USBCommunication
from .coexist import (HostPartitionExportV1, PreAuthSnapshotV1, SnapshotV1,
                      extract_wrapped_pairing)
from .coexist import PairingBundleV1, load_tudor_sensor_key
from .claims import ClaimStore, TemplateRefV1
from .sensor.sensor import Sensor


@dataclasses.dataclass(frozen=True)
class ProbeV1:
    stable_device_id: str
    vid: int
    pid: int
    usb_serial: str
    firmware: str
    product: int
    advanced_security: bool
    key_flag: bool
    provision_state: int
    format: str = "ProbeV1"

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True, indent=2) + "\n"


def parse_version_response(response: bytes, *, vid: int, pid: int,
                           usb_serial: str) -> ProbeV1:
    if len(response) != 0x26:
        raise RuntimeError(f"unexpected GET_VERSION response size {len(response)}")
    try:
        build, major, minor, product, _private_id, flags1, flags2, provision = struct.unpack(
            "<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", response
        )
    except struct.error as exc:
        raise RuntimeError("malformed GET_VERSION response") from exc
    if product in (ord("B"), ord("C")):
        raise RuntimeError("sensor is in bootloader mode; recovery is forbidden")
    if not usb_serial or "\0" in usb_serial:
        raise RuntimeError("USB serial is required for stable public identity")
    return ProbeV1(
        f"{vid:04x}-{pid:04x}-{usb_serial}", vid, pid, usb_serial,
        f"{major}.{minor}.{build}", product, bool(flags1 & 1),
        bool(flags2 & 0x20), provision & 0x0F,
    )


def probe_transport(comm, *, vid: int, pid: int, usb_serial: str) -> ProbeV1:
    if comm.remote_tls_status():
        raise RuntimeError("sensor reports an active TLS session; forced close is forbidden")
    response = comm.send_command(bytes([Command.GET_VERSION]), 0x26)
    return parse_version_response(response, vid=vid, pid=pid, usb_serial=usb_serial)


def _object_list(comm, object_type: int, parent: bytes, count: int) -> list[bytes]:
    if len(parent) != 16 or count < 0:
        raise ValueError("invalid DB2 object-list request")
    request = struct.pack("<BI", Command.DB2_GET_OBJ_LIST, object_type) + parent
    response = comm.send_command(request, 4 + 16 * count)
    if len(response) < 4:
        raise RuntimeError("truncated DB2 object list")
    returned = int.from_bytes(response[2:4], "little")
    if returned > count or len(response) != 4 + 16 * returned:
        raise RuntimeError("inconsistent DB2 object list")
    return [response[4 + 16 * i:20 + 16 * i] for i in range(returned)]


def snapshot_transport(comm, probe_result: ProbeV1) -> SnapshotV1:
    host_request = struct.pack("<BBBHII", Command.STORAGE_PART_READ, 2, 0,
                               0xFFFF, 0, 0x1000)
    host_response = comm.send_command(host_request, 0x1008)
    if len(host_response) != 0x1008 or int.from_bytes(host_response[2:6], "little") != 0x1000:
        raise RuntimeError("invalid host-partition read response")
    host_hash = hashlib.sha256(host_response[8:]).hexdigest()

    db2_format = "<2xHHHLHHHHHHHHHHHHHH"
    db2 = comm.send_command(struct.pack("<BB", Command.DB2_GET_DB_INFO, 1), 0x40)
    expected_db2_size = struct.calcsize(db2_format)
    if len(db2) != expected_db2_size:
        raise RuntimeError(
            f"invalid DB2 info response size {len(db2)}; expected {expected_db2_size}; "
            f"sha256={hashlib.sha256(db2).hexdigest()}")
    fields = struct.unpack(db2_format, db2)
    version_major, version_minor, partition_version = fields[1:4]
    current_users, current_templates, current_payloads = fields[9], fields[12], fields[15]

    users = _object_list(comm, 1, bytes(16), current_users)
    templates = _object_list(comm, 2, bytes([0xFF]) * 16, current_templates)
    payloads = []
    for template in templates:
        # Payloads are parented by template. The aggregate advertised count is
        # an upper bound for each response and is checked after collection.
        payloads.extend(_object_list(comm, 3, template, current_payloads))
    unique_ids = set(users + templates + payloads)
    if len(set(payloads)) > current_payloads:
        raise RuntimeError("DB2 returned more payload IDs than advertised")
    hashes = tuple(sorted(hashlib.sha256(value).hexdigest() for value in unique_ids))
    return SnapshotV1(
        probe_result.firmware,
        "advanced" if probe_result.advanced_security else "basic",
        str(probe_result.provision_state), host_hash, partition_version,
        {"users": current_users, "templates": current_templates,
         "payloads": current_payloads, "version_major": version_major,
         "version_minor": version_minor}, hashes,
    )


def preauth_snapshot_transport(comm, probe_result: ProbeV1) -> PreAuthSnapshotV1:
    """Snapshot only persistence fields proven readable without TLS.

    DB2 reads return operation-denied on 10.1.3399660 before authentication;
    full DB2 snapshots remain mandatory inside authenticated operations.
    """
    host_request = struct.pack("<BBBHII", Command.STORAGE_PART_READ, 2, 0,
                               0xFFFF, 0, 0x1000)
    host_response = comm.send_command(host_request, 0x1008)
    if (len(host_response) != 0x1008 or
            int.from_bytes(host_response[2:6], "little") != 0x1000):
        raise RuntimeError("invalid host-partition read response")
    return PreAuthSnapshotV1(
        probe_result.firmware,
        "advanced" if probe_result.advanced_security else "basic",
        str(probe_result.provision_state),
        hashlib.sha256(host_response[8:]).hexdigest(),
    )


def export_host_pairing_transport(comm, *, vid: int, pid: int,
                                  usb_serial: str) -> HostPartitionExportV1:
    if comm.remote_tls_status():
        raise RuntimeError("sensor reports an active TLS session; forced close is forbidden")
    version_response = comm.send_command(bytes([Command.GET_VERSION]), 0x26)
    probe_result = parse_version_response(version_response, vid=vid, pid=pid,
                                          usb_serial=usb_serial)
    private_identity = version_response[18:24] + b"\x00\x00"
    request = struct.pack("<BBBHII", Command.STORAGE_PART_READ, 2, 0,
                          0xFFFF, 0, 0x1000)
    response = comm.send_command(request, 0x1008)
    if len(response) != 0x1008 or int.from_bytes(response[2:6], "little") != 0x1000:
        raise RuntimeError("invalid host-partition read response")
    partition = response[8:]
    wrapped = extract_wrapped_pairing(partition)
    return HostPartitionExportV1(
        probe_result.vid, probe_result.pid, probe_result.usb_serial,
        private_identity, hashlib.sha256(partition).hexdigest(), wrapped)


def probe(*, vid: int = 0x06CB, pid: int = 0x00C9) -> ProbeV1:
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for hardware probe") from exc
    device = usb.core.find(idVendor=vid, idProduct=pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {vid:04x}:{pid:04x} found")
    serial = str(device.serial_number or "")
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.READ_ONLY))
    try:
        return probe_transport(comm, vid=vid, pid=pid, usb_serial=serial)
    finally:
        comm.close()


def snapshot(*, vid: int = 0x06CB, pid: int = 0x00C9) -> SnapshotV1:
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for hardware snapshot") from exc
    device = usb.core.find(idVendor=vid, idProduct=pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {vid:04x}:{pid:04x} found")
    serial = str(device.serial_number or "")
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.READ_ONLY))
    try:
        observed = probe_transport(comm, vid=vid, pid=pid, usb_serial=serial)
        return preauth_snapshot_transport(comm, observed)
    finally:
        comm.close()


def export_host_pairing(*, vid: int = 0x06CB,
                        pid: int = 0x00C9) -> HostPartitionExportV1:
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for host-partition export") from exc
    device = usb.core.find(idVendor=vid, idProduct=pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {vid:04x}:{pid:04x} found")
    serial = str(device.serial_number or "")
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.READ_ONLY))
    try:
        return export_host_pairing_transport(comm, vid=vid, pid=pid,
                                             usb_serial=serial)
    finally:
        comm.close()


def list_templates(bundle_path: str, sensor_key_path: str) -> list[dict[str, object]]:
    """Authenticated listing that returns no Windows SID or raw template ID."""
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for authenticated listing") from exc
    bundle = PairingBundleV1.load(bundle_path)
    bundle.validate(expected_vid=0x06CB, expected_pid=0x00C9,
                    sensor_signing_key=load_tudor_sensor_key(sensor_key_path))
    device = usb.core.find(idVendor=bundle.vid, idProduct=bundle.pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {bundle.vid:04x}:{bundle.pid:04x} found")
    serial = str(device.serial_number or "")
    bundle.validate(expected_serial=serial)
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY))
    sensor = Sensor(comm)
    try:
        sensor.initialize(bundle.sensor_pairing_data(),
                          expected_private_identity=bundle.private_sensor_identity)
        observed = _probe_from_initialized_sensor(sensor, bundle, serial)
        before = snapshot_transport(comm, observed)
        enrollments = sensor.get_enrollment_cache()
        result = sanitize_template_list(enrollments)
        before.assert_unchanged(snapshot_transport(comm, observed))
        return result
    finally:
        if sensor.initialized:
            sensor.uninitialize()
        comm.close()


def sanitize_template_list(enrollments) -> list[dict[str, object]]:
    result = []
    for index, (template_id, _windows_sid, subtype) in enumerate(enrollments, 1):
        result.append({"index": index, "finger_subtype": subtype.hex(),
                       "template_sha256": hashlib.sha256(template_id).hexdigest()})
    return result


def _probe_from_initialized_sensor(sensor: Sensor, bundle: PairingBundleV1,
                                   serial: str) -> ProbeV1:
    return ProbeV1(
        f"{bundle.vid:04x}-{bundle.pid:04x}-{serial}", bundle.vid, bundle.pid,
        serial, f"{sensor.fw_major}.{sensor.fw_minor}.{sensor.fw_build_num}",
        int(sensor.product_id), sensor.advanced_security, sensor.key_flag,
        int(sensor.prov_state),
    )


def select_template(enrollments, template_sha256: str) -> bytes:
    try:
        if len(template_sha256) != 64:
            raise ValueError
        bytes.fromhex(template_sha256)
    except ValueError as exc:
        raise ValueError("template selector must be exactly 64 hexadecimal digits") from exc
    matches = [template_id for template_id, _sid, _subtype in enrollments
               if hashlib.sha256(template_id).hexdigest() == template_sha256.lower()]
    if len(matches) != 1:
        raise RuntimeError("selected template hash was not found uniquely")
    return matches[0]


def select_enrollment(enrollments, template_sha256: str):
    selected = select_template(enrollments, template_sha256)
    matches = [entry for entry in enrollments if entry[0] == selected]
    if len(matches) != 1:
        raise RuntimeError("selected template was not found uniquely")
    return matches[0]


def verify_template(bundle_path: str, sensor_key_path: str,
                    template_sha256: str) -> bool:
    """Match only one selected existing template, with persistence snapshots."""
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for authenticated verification") from exc
    bundle = PairingBundleV1.load(bundle_path)
    bundle.validate(expected_vid=0x06CB, expected_pid=0x00C9,
                    sensor_signing_key=load_tudor_sensor_key(sensor_key_path))
    device = usb.core.find(idVendor=bundle.vid, idProduct=bundle.pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {bundle.vid:04x}:{bundle.pid:04x} found")
    serial = str(device.serial_number or "")
    bundle.validate(expected_serial=serial)
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY))
    sensor = Sensor(comm)
    try:
        sensor.initialize(bundle.sensor_pairing_data(),
                          expected_private_identity=bundle.private_sensor_identity)
        observed = _probe_from_initialized_sensor(sensor, bundle, serial)
        before = snapshot_transport(comm, observed)
        selected = select_template(sensor.get_enrollment_cache(), template_sha256)
        print("\aTouch the sensor now with the finger being tested.", flush=True)
        matched = sensor.auth([selected])
        before.assert_unchanged(snapshot_transport(comm, observed))
        return matched
    finally:
        if sensor.initialized:
            sensor.uninitialize()
        comm.close()


def claim_existing(bundle_path: str, sensor_key_path: str, template_sha256: str,
                   username: str, finger: str):
    """Resolve one existing template and create only a local Linux claim."""
    if os.geteuid() != 0:
        raise PermissionError("claim-existing must run as root")
    # Validate the public metadata before any hardware access.
    TemplateRefV1("00" * 16, finger)
    pwd.getpwnam(username)
    try:
        import usb.core
    except ModuleNotFoundError as exc:
        raise RuntimeError("pyusb is required for claim-existing") from exc
    bundle = PairingBundleV1.load(bundle_path)
    bundle.validate(expected_vid=0x06CB, expected_pid=0x00C9,
                    sensor_signing_key=load_tudor_sensor_key(sensor_key_path))
    device = usb.core.find(idVendor=bundle.vid, idProduct=bundle.pid)
    if device is None:
        raise RuntimeError(f"no USB sensor {bundle.vid:04x}:{bundle.pid:04x} found")
    serial = str(device.serial_number or "")
    bundle.validate(expected_serial=serial)
    stable_id = f"{bundle.vid:04x}-{bundle.pid:04x}-{serial}"
    comm = USBCommunication(device, SafetyPolicy(SafetyMode.AUTHENTICATED_VERIFY))
    sensor = Sensor(comm)
    try:
        sensor.initialize(bundle.sensor_pairing_data(),
                          expected_private_identity=bundle.private_sensor_identity)
        observed = _probe_from_initialized_sensor(sensor, bundle, serial)
        before = snapshot_transport(comm, observed)
        selected, _windows_sid, subtype = select_enrollment(
            sensor.get_enrollment_cache(), template_sha256)
        before.assert_unchanged(snapshot_transport(comm, observed))
    finally:
        if sensor.initialized:
            sensor.uninitialize()
        comm.close()
    if not isinstance(subtype, (bytes, bytearray)) or len(subtype) != 1:
        raise RuntimeError("sensor returned an invalid finger subtype")
    reference = TemplateRefV1(selected.hex(), finger, subtype[0])
    return ClaimStore().claim(username, stable_id, reference)
