#!/usr/bin/env python3
import struct
import uuid
import pytest
from pathlib import Path

from secureboot import (
    EFI_CERT_X509_GUID,
    EFI_CERT_SHA256_GUID,
    action_generate_keys,
    action_extract_devices,
    action_sign_variables,
    build_efi_sig_list,
    hash_to_efi_sig_list,
    read_tpm2_pcr2_driver_events,
    parse_tpm2_pcr2_driver_events,
    get_pe_authenticode_hash,
    decode_efi_device_path,
)
from tests.generate_fixture_eventlog import build_dynamic_mock_eventlog, create_minimal_pe


def parse_efi_signature_list(esl_bytes: bytes) -> list[tuple[uuid.UUID, uuid.UUID, bytes]]:
    """Parse raw EFI_SIGNATURE_LIST bytes into (sig_type, owner_guid, sig_data) tuples."""
    offset = 0
    entries = []
    while offset < len(esl_bytes):
        type_guid = uuid.UUID(bytes_le=esl_bytes[offset:offset + 16])
        list_size, hdr_size, sig_size = struct.unpack_from("<III", esl_bytes, offset + 16)
        sig_offset = offset + 28 + hdr_size
        list_end = offset + list_size
        while sig_offset < list_end:
            owner_guid = uuid.UUID(bytes_le=esl_bytes[sig_offset:sig_offset + 16])
            sig_data = esl_bytes[sig_offset + 16:sig_offset + sig_size]
            entries.append((type_guid, owner_guid, sig_data))
            sig_offset += sig_size
        offset = list_end
    return entries


@pytest.fixture
def dynamic_fixtures(tmp_path: Path) -> dict:
    """Generate dynamic tpm2_eventlog.bin and valid .efi binaries in tmp_path."""
    eventlog_bytes, drivers = build_dynamic_mock_eventlog()
    log_path = tmp_path / "tpm2_eventlog.bin"
    log_path.write_bytes(eventlog_bytes)

    efi_files = {}
    for d in drivers:
        efi_path = tmp_path / f"{d['name']}.efi"
        efi_path.write_bytes(d["pe"])
        efi_files[d["name"]] = efi_path

    return {"log_path": log_path, "drivers": drivers, "efi_files": efi_files}


def test_efi_sig_list_helpers():
    owner = uuid.uuid4()
    digest1 = bytes.fromhex("aa" * 32)
    digest2 = bytes.fromhex("bb" * 32)

    esl = build_efi_sig_list(EFI_CERT_SHA256_GUID, [(owner, digest1), (owner, digest2)])
    parsed = parse_efi_signature_list(esl)
    assert len(parsed) == 2
    assert parsed[0] == (EFI_CERT_SHA256_GUID, owner, digest1)
    assert parsed[1] == (EFI_CERT_SHA256_GUID, owner, digest2)

    with pytest.raises(ValueError, match="identical size"):
        build_efi_sig_list(EFI_CERT_SHA256_GUID, [(owner, b"short"), (owner, b"longer_bytes")])


def test_valid_pe_structure_and_authenticode(dynamic_fixtures):
    """Verify both generated EFI binaries have valid PE structure and matching Authenticode hashes."""
    drivers = dynamic_fixtures["drivers"]
    efi_files = dynamic_fixtures["efi_files"]

    assert len(drivers) == 2
    for d in drivers:
        efi_path = efi_files[d["name"]]
        raw_bytes = efi_path.read_bytes()
        assert raw_bytes.startswith(b"MZ")
        assert b"PE\x00\x00" in raw_bytes

        computed_hash = get_pe_authenticode_hash(efi_path)
        assert computed_hash == d["hash"]


def test_gop_verification_match_and_mismatch(dynamic_fixtures, tmp_path: Path):
    """Test verification logic: Authenticode hash of valid PE matches eventlog, tampered PE fails."""
    primary_driver = dynamic_fixtures["drivers"][0]
    valid_efi = dynamic_fixtures["efi_files"][primary_driver["name"]]
    expected_hash = primary_driver["hash"]

    # 1. Authentic PE matches eventlog hash
    assert get_pe_authenticode_hash(valid_efi) == expected_hash

    # 2. Tampered PE (modified byte in payload) produces mismatched hash
    tampered_efi = tmp_path / "tampered.efi"
    tampered_bytes = bytearray(valid_efi.read_bytes())
    tampered_bytes[-1] ^= 0xFF
    tampered_efi.write_bytes(tampered_bytes)

    tampered_hash = get_pe_authenticode_hash(tampered_efi)
    assert tampered_hash != expected_hash


def test_hash_to_efi_sig_list_format():
    owner = uuid.uuid4()
    sample_hash = "e37098375743cc59722e040b3994e4098c14f0288c42a1f0edaf1db8aa55c9bd"
    esl = hash_to_efi_sig_list(sample_hash, owner)
    parsed = parse_efi_signature_list(esl)
    assert len(parsed) == 1
    assert parsed[0][0] == EFI_CERT_SHA256_GUID
    assert parsed[0][1] == owner
    assert parsed[0][2] == bytes.fromhex(sample_hash)


def test_decode_efi_device_path():
    # Text path is passed through unmodified
    assert decode_efi_device_path("PciRoot(0x0)/Pci(0x1,0x0)") == "PciRoot(0x0)/Pci(0x1,0x0)"
    # Binary hex representation is decoded into standard string
    hex_dev1 = "02010c00d041030a000000000101060000017fff0400"
    assert decode_efi_device_path(hex_dev1) == "PciRoot(0x0)/Pci(0x1,0x0)"
    hex_dev2 = "02010c00d041030a000000000101060000027fff0400"
    assert decode_efi_device_path(hex_dev2) == "PciRoot(0x0)/Pci(0x2,0x0)"
    # Empty or non-hex string passthrough
    assert decode_efi_device_path("") == ""
    assert decode_efi_device_path("not_hex") == "not_hex"


def test_extract_mock_eventlog(dynamic_fixtures):
    log_path = dynamic_fixtures["log_path"]
    drivers = dynamic_fixtures["drivers"]

    pcr2_events = read_tpm2_pcr2_driver_events(log_path)
    # The fixture contains 2 GOP driver events and 1 EV_SEPARATOR.
    # Only the 2 GOP driver events should be extracted.
    assert len(pcr2_events) == 2
    assert pcr2_events[0]["sha256"] == drivers[0]["hash"]
    assert pcr2_events[1]["sha256"] == drivers[1]["hash"]
    assert "Pci(0x1,0x0)" in pcr2_events[0]["device_path"]
    assert "Pci(0x2,0x0)" in pcr2_events[1]["device_path"]


def test_parse_tpm2_pcr2_edge_cases():
    # Truncated or empty data returns empty list gracefully
    assert parse_tpm2_pcr2_driver_events(b"") == []
    assert parse_tpm2_pcr2_driver_events(b"\x00" * 20) == []
    assert parse_tpm2_pcr2_driver_events(b"\x00" * 32) == []


def test_full_pipeline_multi_gop(tmp_path: Path, dynamic_fixtures):
    log_path = dynamic_fixtures["log_path"]
    drivers = dynamic_fixtures["drivers"]
    custom_dir = tmp_path / "custom_config"
    firmware_dir = tmp_path / "firmware_config"
    signed_dir = tmp_path / "signed_config"

    expected_hashes = {d["hash"] for d in drivers}

    # Step 1: Generate keys
    action_generate_keys(cn_prefix="TestSecureBoot", days=365, output_dir=custom_dir)
    assert (custom_dir / "uuid.txt").is_file()
    assert (custom_dir / "dbx.esl").stat().st_size == 0
    for key in ("PK", "KEK", "db"):
        assert (custom_dir / f"{key}.key").is_file()
        assert (custom_dir / f"{key}.crt").is_file()
        assert (custom_dir / f"{key}.cer").is_file()
        assert (custom_dir / f"{key}.esl").is_file()

    db_cer_bytes = (custom_dir / "db.cer").read_bytes()

    # Step 2: Extract devices from dynamic eventlog
    action_extract_devices(eventlog_path=log_path, firmware_dir=firmware_dir, custom_dir=custom_dir)
    for d in drivers:
        assert (firmware_dir / f"{d['hash']}.esl").is_file()

    # Step 3: Sign variables (merging db.esl and creating .auth files)
    action_sign_variables(custom_dir=custom_dir, firmware_dir=firmware_dir, signed_dir=signed_dir)

    # Step 4: Verify merged db.esl contains db.cert and BOTH genuine GOP PE hashes
    merged_db_esl = signed_dir / "db.esl"
    assert merged_db_esl.is_file()

    entries = parse_efi_signature_list(merged_db_esl.read_bytes())
    x509_entries = [e for e in entries if e[0] == EFI_CERT_X509_GUID]
    sha256_entries = [e for e in entries if e[0] == EFI_CERT_SHA256_GUID]

    # Exactly 1 X.509 cert matching custom db.cer
    assert len(x509_entries) == 1
    assert x509_entries[0][2] == db_cer_bytes

    # Exactly 2 SHA-256 hashes matching genuine PE hashes
    assert len(sha256_entries) == 2
    extracted_hashes = {e[2].hex() for e in sha256_entries}
    assert extracted_hashes == expected_hashes

    # Step 5: Verify all authenticated update files (.auth) are signed
    for var in ("PK", "KEK", "db", "dbx"):
        auth_file = signed_dir / f"{var}.auth"
        assert auth_file.is_file()
        assert auth_file.stat().st_size > 0

    # dbx.auth should be a signed empty list (typically ~1.2 KB containing PKCS#7 signature)
    assert 1100 <= (signed_dir / "dbx.auth").stat().st_size <= 1400


def test_certificate_generation_parameters(tmp_path: Path):
    """Verify that --cn-prefix and --days are properly reflected in generated X.509 certs."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    custom_dir = tmp_path / "custom_config"
    action_generate_keys(cn_prefix="MyOrgRoot", days=100, output_dir=custom_dir)

    for key_type in ("PK", "KEK", "db"):
        crt_bytes = (custom_dir / f"{key_type}.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(crt_bytes)

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attrs) == 1
        assert cn_attrs[0].value == f"MyOrgRoot ({key_type})"

        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        assert 99 <= validity_days <= 101


def test_cli_interface():
    """Verify CLI help outputs and error handling for unknown actions."""
    import subprocess
    import sys

    for action in ("generate-keys", "extract-devices", "sign-variables"):
        cmd = [sys.executable, "secureboot.py", action, "--help"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert f"usage: secureboot.py {action}" in res.stdout

    res_err = subprocess.run([sys.executable, "secureboot.py", "invalid-action"], capture_output=True, text=True)
    assert res_err.returncode != 0

