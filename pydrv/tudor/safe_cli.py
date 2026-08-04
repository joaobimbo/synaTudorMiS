"""Safe coexistence entry point.  Hardware verbs are intentionally absent."""
import argparse

from .coexist import PairingBundleV1, find_bundled_sensor_key, load_tudor_sensor_key
from .claims import ClaimStore
from .gvariant import atomic_write_owner_only, serialize_pairing_data
from .hardware import (claim_existing, export_host_pairing, list_templates,
                       probe, snapshot, verify_template)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tudor-safe")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit-pairing", help="validate a PairingBundleV1 offline")
    audit.add_argument("bundle")
    audit.add_argument("--vid", type=lambda value: int(value, 16), default=0x06CB)
    audit.add_argument("--pid", type=lambda value: int(value, 16), default=0x00C9)
    audit.add_argument("--serial")
    audit.add_argument("--sensor-key",
                       help="firmware-matched Tudor public key; auto-selects a bundled key when omitted")
    export = sub.add_parser("import-pairing", help="validate and serialize pairing for libfprint")
    export.add_argument("bundle")
    export.add_argument("stable_device_id")
    export.add_argument("output")
    export.add_argument("--sensor-key",
                        help="firmware-matched Tudor public key; auto-selects a bundled key when omitted")
    claim = sub.add_parser("claim-existing", help="create a local reference; never enrolls")
    claim.add_argument("bundle")
    claim.add_argument("username")
    claim.add_argument("finger")
    claim.add_argument("template_sha256", help="64-digit hash shown by list")
    claim.add_argument("--sensor-key", required=True)
    unclaim = sub.add_parser("unclaim", help="remove only a local reference")
    unclaim.add_argument("username")
    unclaim.add_argument("stable_device_id")
    unclaim.add_argument("finger")
    hardware_probe = sub.add_parser("probe", help="approved TLS-status/version probe; no reset")
    hardware_probe.add_argument("--vid", type=lambda value: int(value, 16), default=0x06CB)
    hardware_probe.add_argument("--pid", type=lambda value: int(value, 16), default=0x00C9)
    hardware_snapshot = sub.add_parser("snapshot", help="approved read-only persistence snapshot")
    hardware_snapshot.add_argument("--vid", type=lambda value: int(value, 16), default=0x06CB)
    hardware_snapshot.add_argument("--pid", type=lambda value: int(value, 16), default=0x00C9)
    host_export = sub.add_parser(
        "export-host-pairing",
        help="read host partition once and export only its wrapped pairing field")
    host_export.add_argument("output")
    host_export.add_argument("--vid", type=lambda value: int(value, 16), default=0x06CB)
    host_export.add_argument("--pid", type=lambda value: int(value, 16), default=0x00C9)
    hardware_list = sub.add_parser("list", help="approved authenticated template listing")
    hardware_list.add_argument("bundle")
    hardware_list.add_argument("--sensor-key", required=True)
    hardware_verify = sub.add_parser(
        "verify", help="approved match against exactly one existing template")
    hardware_verify.add_argument("bundle")
    hardware_verify.add_argument("template_sha256",
                                 help="64-digit hash shown by the list command")
    hardware_verify.add_argument("--sensor-key", required=True)
    args = parser.parse_args(argv)
    if args.command == "audit-pairing":
        bundle = PairingBundleV1.load(args.bundle)
        sensor_key = (load_tudor_sensor_key(args.sensor_key) if args.sensor_key else
                      load_tudor_sensor_key(find_bundled_sensor_key(bundle)))
        bundle.validate(expected_vid=args.vid, expected_pid=args.pid, expected_serial=args.serial,
                        sensor_signing_key=sensor_key)
        print("PairingBundleV1 is structurally valid and matches the requested device")
    elif args.command == "claim-existing":
        path = claim_existing(args.bundle, args.sensor_key, args.template_sha256,
                              args.username, args.finger)
        print(f"Created local-only claim: {path}")
    elif args.command == "unclaim":
        ClaimStore().unclaim(args.username, args.stable_device_id, args.finger)
        print("Removed local-only claim; sensor storage was not contacted")
    elif args.command == "import-pairing":
        bundle = PairingBundleV1.load(args.bundle)
        sensor_key = (load_tudor_sensor_key(args.sensor_key) if args.sensor_key else
                      load_tudor_sensor_key(find_bundled_sensor_key(bundle)))
        bundle.validate(sensor_signing_key=sensor_key)
        expected = f"{bundle.vid:04x}-{bundle.pid:04x}-{bundle.usb_serial}"
        if args.stable_device_id != expected:
            raise ValueError(f"stable device ID mismatch; expected {expected}")
        serialized = serialize_pairing_data(args.stable_device_id,
                                            bundle.host_certificate,
                                            bundle.sensor_certificate,
                                            bundle.private_key_pem())
        path = atomic_write_owner_only(args.output, serialized)
        print(f"Wrote owner-only libfprint PairingDataV1: {path}")
    elif args.command == "probe":
        print(probe(vid=args.vid, pid=args.pid).to_json(), end="")
    elif args.command == "snapshot":
        print(snapshot(vid=args.vid, pid=args.pid).to_json(), end="")
    elif args.command == "export-host-pairing":
        exported = export_host_pairing(vid=args.vid, pid=args.pid)
        path = atomic_write_owner_only(args.output, exported.to_json().encode("utf-8"))
        print(f"Wrote owner-only HostPartitionExportV1: {path}")
    elif args.command == "list":
        import json
        print(json.dumps({"format": "TemplateListV1",
                          "templates": list_templates(args.bundle, args.sensor_key)},
                         sort_keys=True, indent=2))
    elif args.command == "verify":
        print("MATCH" if verify_template(args.bundle, args.sensor_key,
                                         args.template_sha256) else "NO MATCH")


if __name__ == "__main__":
    main()
