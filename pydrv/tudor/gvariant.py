"""Minimal GLib serializer for libfprint persistent PairingDataV1."""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import tempfile
from pathlib import Path


def _glib():
    name = ctypes.util.find_library("glib-2.0")
    if not name:
        raise RuntimeError("GLib 2.0 is required to export libfprint pairing data")
    lib = ctypes.CDLL(name)
    pointer = ctypes.c_void_p
    lib.g_variant_type_new.argtypes = [ctypes.c_char_p]
    lib.g_variant_type_new.restype = pointer
    lib.g_variant_type_free.argtypes = [pointer]
    lib.g_variant_new_fixed_array.argtypes = [pointer, pointer, ctypes.c_size_t, ctypes.c_size_t]
    lib.g_variant_new_fixed_array.restype = pointer
    lib.g_variant_new_string.argtypes = [ctypes.c_char_p]
    lib.g_variant_new_string.restype = pointer
    lib.g_variant_new_int32.argtypes = [ctypes.c_int32]
    lib.g_variant_new_int32.restype = pointer
    lib.g_variant_new_boolean.argtypes = [ctypes.c_int]
    lib.g_variant_new_boolean.restype = pointer
    lib.g_variant_new_byte.argtypes = [ctypes.c_ubyte]
    lib.g_variant_new_byte.restype = pointer
    lib.g_variant_new_maybe.argtypes = [pointer, pointer]
    lib.g_variant_new_maybe.restype = pointer
    lib.g_variant_new_variant.argtypes = [pointer]
    lib.g_variant_new_variant.restype = pointer
    lib.g_variant_new_dict_entry.argtypes = [pointer, pointer]
    lib.g_variant_new_dict_entry.restype = pointer
    lib.g_variant_builder_new.argtypes = [pointer]
    lib.g_variant_builder_new.restype = pointer
    lib.g_variant_builder_add_value.argtypes = [pointer, pointer]
    lib.g_variant_builder_end.argtypes = [pointer]
    lib.g_variant_builder_end.restype = pointer
    lib.g_variant_builder_unref.argtypes = [pointer]
    lib.g_variant_new_tuple.argtypes = [ctypes.POINTER(pointer), ctypes.c_size_t]
    lib.g_variant_new_tuple.restype = pointer
    lib.g_variant_ref_sink.argtypes = [pointer]
    lib.g_variant_ref_sink.restype = pointer
    lib.g_variant_get_size.argtypes = [pointer]
    lib.g_variant_get_size.restype = ctypes.c_size_t
    lib.g_variant_store.argtypes = [pointer, pointer]
    lib.g_variant_unref.argtypes = [pointer]
    lib.g_variant_parse.argtypes = [pointer, ctypes.c_char_p, pointer, pointer,
                                    ctypes.POINTER(pointer)]
    lib.g_variant_parse.restype = pointer
    return lib


_FINGER_VALUES = {
    "left-thumb": 1, "left-index-finger": 2, "left-middle-finger": 3,
    "left-ring-finger": 4, "left-little-finger": 5, "right-thumb": 6,
    "right-index-finger": 7, "right-middle-finger": 8,
    "right-ring-finger": 9, "right-little-finger": 10,
}


def serialize_template_ref(device_id: str, username: str, finger: str,
                           sensor_subtype: int, template_id: bytes) -> bytes:
    """Create the exact FP3/FpPrint record consumed by fprintd 1.94.5."""
    if finger not in _FINGER_VALUES:
        raise ValueError("unsupported finger name")
    if not 0 <= sensor_subtype <= 0xff:
        raise ValueError("sensor finger subtype must fit in one byte")
    if len(template_id) != 16:
        raise ValueError("template ID must contain exactly 16 bytes")
    lib = _glib()
    print_type = lib.g_variant_type_new(b"(issbymsmsia{sv}v)")
    try:
        if "\0" in device_id or "\0" in username:
            raise ValueError("GVariant string contains NUL")
        byte_array = ", ".join(f"byte 0x{value:02x}" for value in template_id)
        source = (
            f"(1, {json.dumps('synatlsmoc')}, {json.dumps(device_id)}, true, "
            f"byte {_FINGER_VALUES[finger]}, just {json.dumps(username)}, "
            f"just {json.dumps(username)}, -2147483648, {{}}, "
            f"<<(byte {sensor_subtype}, [{byte_array}])>>)"
        ).encode()
        error = ctypes.c_void_p()
        outer = lib.g_variant_parse(print_type, source, None, None, ctypes.byref(error))
        if not outer:
            raise ValueError("failed to construct libfprint FP3 variant")
        outer = lib.g_variant_ref_sink(outer)
        size = lib.g_variant_get_size(outer)
        body = ctypes.create_string_buffer(size)
        lib.g_variant_store(outer, body)
        result = b"FP3" + body.raw
        lib.g_variant_unref(outer)
        return result
    finally:
        lib.g_variant_type_free(print_type)


def serialize_pairing_data(device_id: str, host_certificate: bytes,
                           sensor_certificate: bytes, private_key_pem: bytes) -> bytes:
    """Return the `(issv)` byte representation consumed by libfprint."""
    lib = _glib()
    variant_type = lib.g_variant_type_new(b"a{sv}")
    byte_type = lib.g_variant_type_new(b"y")
    builder = lib.g_variant_builder_new(variant_type)
    buffers = []

    def string(value: str | bytes):
        raw = value.encode() if isinstance(value, str) else value
        if b"\0" in raw:
            raise ValueError("GVariant string contains NUL")
        return lib.g_variant_new_string(raw)

    def byte_array(value: bytes):
        buffer = ctypes.create_string_buffer(value)
        buffers.append(buffer)
        return lib.g_variant_new_fixed_array(byte_type, buffer, len(value), 1)

    def add(name: str, value):
        entry = lib.g_variant_new_dict_entry(string(name), lib.g_variant_new_variant(value))
        lib.g_variant_builder_add_value(builder, entry)

    try:
        add("format", string("PairingDataV1"))
        add("host-certificate", byte_array(host_certificate))
        add("sensor-certificate", byte_array(sensor_certificate))
        add("host-private-key-pem", string(private_key_pem))
        dictionary = lib.g_variant_builder_end(builder)
        children = (ctypes.c_void_p * 4)(lib.g_variant_new_int32(1), string("synatlsmoc"),
                                        string(device_id), lib.g_variant_new_variant(dictionary))
        outer = lib.g_variant_ref_sink(lib.g_variant_new_tuple(children, 4))
        size = lib.g_variant_get_size(outer)
        output = ctypes.create_string_buffer(size)
        lib.g_variant_store(outer, output)
        lib.g_variant_unref(outer)
        return output.raw
    finally:
        lib.g_variant_builder_unref(builder)
        lib.g_variant_type_free(byte_type)
        lib.g_variant_type_free(variant_type)


def atomic_write_owner_only(path: str | os.PathLike[str], data: bytes) -> Path:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pairing-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
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
