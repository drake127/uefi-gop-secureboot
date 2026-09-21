#!/usr/bin/env python3
"""Dynamically generate valid PE32+ (x86_64 UEFI) binaries and a synthetic TCG TPM 2.0 eventlog."""

import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secureboot import get_pe_authenticode_hash


def create_minimal_pe(payload: bytes, subsystem: int = 11) -> bytes:
    """Construct a minimal valid PE32+ (x86_64 UEFI) executable binary."""
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes): AMD64, 1 section, optional header 240 bytes
    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)

    # Optional Header PE32+ (240 bytes)
    opt_header = bytearray(240)
    struct.pack_into("<HBB", opt_header, 0, 0x020B, 1, 0)
    struct.pack_into("<III", opt_header, 4, 0x200, 0, 0)
    struct.pack_into("<III", opt_header, 16, 0x1000, 0x1000, 0)
    struct.pack_into("<Q", opt_header, 24, 0x400000)
    struct.pack_into("<II", opt_header, 32, 0x1000, 0x200)
    struct.pack_into("<HH", opt_header, 40, 6, 0)
    struct.pack_into("<HH", opt_header, 44, 0, 0)
    struct.pack_into("<HH", opt_header, 48, 6, 0)
    struct.pack_into("<I", opt_header, 52, 0)
    struct.pack_into("<III", opt_header, 56, 0x2000, 0x200, 0)
    struct.pack_into("<HH", opt_header, 68, subsystem, 0)  # Subsystem 11 = EFI_BOOT_SERVICE_DRIVER
    struct.pack_into("<QQQQ", opt_header, 72, 0x10000, 0x1000, 0x10000, 0x1000)
    struct.pack_into("<II", opt_header, 104, 0, 16)

    # Section Header (40 bytes)
    sec_name = b".text\x00\x00\x00"
    sec_header = struct.pack("<8sIIIIIIHHI", sec_name, 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    headers = (bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + sec_header).ljust(0x200, b"\x00")
    sec_data = payload.ljust(0x200, b"\x00")
    return headers + sec_data


def hash_pe_bytes(pe_bytes: bytes) -> str:
    """Calculate Authenticode SHA-256 hash using secureboot.get_pe_authenticode_hash."""
    with tempfile.NamedTemporaryFile(suffix=".efi", delete=False) as f:
        f.write(pe_bytes)
        tmp_path = Path(f.name)
    try:
        return get_pe_authenticode_hash(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def build_dynamic_mock_eventlog() -> tuple[bytes, list[dict]]:
    """Dynamically generate 2 valid PE drivers and pack their hashes into a TCG TPM2 eventlog."""
    # Generate 2 distinct valid PE drivers
    pe1 = create_minimal_pe(payload=b"GOP_DRIVER_PRIMARY_PCI_1_0")
    pe2 = create_minimal_pe(payload=b"GOP_DRIVER_SECONDARY_PCI_2_0")

    h1 = hash_pe_bytes(pe1)
    h2 = hash_pe_bytes(pe2)

    # 1. Spec ID Event (Header, TCG_PCR_EVENT format)
    spec_id_data = (
        b"Spec ID Event03\x00"
        + struct.pack("<IBBBB I", 0, 0, 2, 0, 2, 1)
        + struct.pack("<HH", 0x000B, 32)
        + struct.pack("<B", 0)
    )
    hdr_event = (
        struct.pack("<II", 0, 3)
        + b"\x00" * 20
        + struct.pack("<I", len(spec_id_data))
        + spec_id_data
    )

    def make_pci_driver_event(pci_dev: int, pci_fn: int, sha256_hex: str) -> bytes:
        pci_devpath = bytes([
            0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x01, 0x06, 0x00, pci_fn, pci_dev,
            0x7F, 0xFF, 0x04, 0x00,
        ])
        event_data = (
            struct.pack("<QQQQ", 0x70000000, 0x10000, 0x70000000, len(pci_devpath))
            + pci_devpath
        )
        digest = bytes.fromhex(sha256_hex)
        return (
            struct.pack("<II", 2, 0x80000004)  # EV_EFI_BOOT_SERVICES_DRIVER
            + struct.pack("<I", 1)              # Digest count = 1
            + struct.pack("<H", 0x000B)          # TPM_ALG_SHA256
            + digest
            + struct.pack("<I", len(event_data))
            + event_data
        )

    def make_separator_event() -> bytes:
        sep_data = b"\x00\x00\x00\x00"
        sep_digest = hashlib.sha256(sep_data).digest()
        return (
            struct.pack("<II", 2, 4)            # EV_SEPARATOR
            + struct.pack("<I", 1)              # Digest count = 1
            + struct.pack("<H", 0x000B)          # TPM_ALG_SHA256
            + sep_digest
            + struct.pack("<I", len(sep_data))
            + sep_data
        )

    ev1 = make_pci_driver_event(1, 0, h1)
    ev2 = make_pci_driver_event(2, 0, h2)
    ev_sep = make_separator_event()

    drivers_info = [
        {"name": "primary_gop", "hash": h1, "pe": pe1, "device_path": "PciRoot(0x0)/Pci(0x1,0x0)"},
        {"name": "secondary_gop", "hash": h2, "pe": pe2, "device_path": "PciRoot(0x0)/Pci(0x2,0x0)"},
    ]
    return hdr_event + ev1 + ev2 + ev_sep, drivers_info


def main() -> None:
    eventlog_bytes, drivers = build_dynamic_mock_eventlog()
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    out_log = fixtures_dir / "tpm2_eventlog.bin"
    out_log.write_bytes(eventlog_bytes)
    print(f"Generated {len(eventlog_bytes)} bytes mock eventlog -> {out_log}")

    for d in drivers:
        efi_file = fixtures_dir / f"{d['name']}.efi"
        efi_file.write_bytes(d["pe"])
        print(f"  {d['name']}: {d['hash']} -> {efi_file} ({len(d['pe'])} bytes)")


if __name__ == "__main__":
    main()
