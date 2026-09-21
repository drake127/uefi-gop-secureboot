#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import datetime
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import uuid

from collections.abc import Sequence
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pathlib import Path


# Standard UEFI GUIDs
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
EFI_IMAGE_SECURITY_DATABASE_GUID = uuid.UUID("605dab50-e046-4300-abb6-3dd810dd8b23")

# Default directory layout & constants
CUSTOM_DIR = Path("custom_config")
FIRMWARE_DIR = Path("firmware_config")
SIGNED_DIR = Path("signed_config")
TOOLS_DIR = Path(__file__).resolve().parent / "tools"

KEY_TYPES = ("PK", "KEK", "db")
DEFAULT_VALIDITY_DAYS = 365 * 20
DEFAULT_EVENTLOG_PATH = Path("/sys/kernel/security/tpm0/binary_bios_measurements")


# =====================================================================
# 1. Low-level EFI & Cryptographic Helpers
# =====================================================================

def build_efi_sig_list(sig_type: uuid.UUID, signatures: Sequence[tuple[uuid.UUID, bytes]]) -> bytes:
    """Build an EFI Signature List (EFI_SIGNATURE_LIST) containing one or more signatures."""
    if not signatures:
        return b""

    payload_size = len(signatures[0][1])
    if any(len(sig[1]) != payload_size for sig in signatures):
        raise ValueError("All signature payloads in an EFI signature list must have identical size")

    sig_size = 16 + payload_size  # SignatureOwner (16 bytes) + SignatureData
    list_size = 28 + len(signatures) * sig_size  # EFI_SIGNATURE_LIST header (28 bytes) + signatures
    header = sig_type.bytes_le + struct.pack("<III", list_size, 0, sig_size)
    body = b"".join(owner.bytes_le + data for owner, data in signatures)
    return header + body


def cert_to_efi_sig_list(cert: x509.Certificate | bytes, owner_guid: uuid.UUID) -> bytes:
    """Convert an X.509 certificate to an EFI Signature List."""
    if isinstance(cert, x509.Certificate):
        cert_der = cert.public_bytes(serialization.Encoding.DER)
    elif isinstance(cert, bytes):
        cert_der = (
            x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)
            if b"-----BEGIN" in cert else cert
        )
    else:
        raise TypeError(f"Unsupported certificate type: {type(cert)}")
    return build_efi_sig_list(EFI_CERT_X509_GUID, [(owner_guid, cert_der)])


def get_pe_authenticode_hash(efi_path: Path) -> str:
    """Calculate Authenticode SHA-256 hash using pesign -h -i."""
    if not shutil.which("pesign"):
        raise RuntimeError("'pesign' tool not found in PATH")

    res = subprocess.run(["pesign", "-h", "-i", str(efi_path)], capture_output=True, text=True, check=True)
    match = re.search(r"^([0-9a-fA-F]{64})", res.stdout.strip())
    if not match:
        raise ValueError(f"Could not parse pesign output: {res.stdout}")
    return match.group(1).lower()


def decode_efi_device_path(raw_path: bytes | str) -> str:
    """Decode a UEFI binary device path (bytes or hex string) into standard textual representation."""
    if isinstance(raw_path, (bytes, bytearray)):
        data = bytes(raw_path)
    elif isinstance(raw_path, str) and not ("Pci" in raw_path or "/" in raw_path):
        try:
            data = bytes.fromhex(raw_path.strip())
        except ValueError:
            return raw_path
    else:
        return str(raw_path) if raw_path else ""

    nodes: list[str] = []
    idx = 0
    while idx + 4 <= len(data):
        dp_type, dp_subtype = data[idx], data[idx + 1]
        dp_len = struct.unpack_from("<H", data, idx + 2)[0]
        if dp_len < 4 or idx + dp_len > len(data) or dp_type == 0x7F:
            break
        payload = data[idx + 4 : idx + dp_len]
        if dp_type == 0x02 and dp_subtype == 0x01 and len(payload) >= 8:
            hid, uid = struct.unpack_from("<II", payload, 0)
            nodes.append(f"PciRoot({hex(uid)})" if hid in (0x0A0341D0, 0x0A0841D0) else f"Acpi(0x{hid:08x},{hex(uid)})")
        elif dp_type == 0x01 and dp_subtype == 0x01 and len(payload) >= 2:
            nodes.append(f"Pci({hex(payload[1])},{hex(payload[0])})")
        elif dp_type == 0x04 and dp_subtype == 0x08 and len(payload) >= 20:
            start, end = struct.unpack_from("<QQ", payload, 4)
            nodes.append(f"Offset({hex(start)},{hex(end)})")
        idx += dp_len

    return "/".join(nodes) if nodes else (raw_path if isinstance(raw_path, str) else "")


def hash_to_efi_sig_list(
    hashes: bytes | str | Path | Sequence[bytes | str | Path],
    owner_guid: uuid.UUID = EFI_IMAGE_SECURITY_DATABASE_GUID,
) -> bytes:
    """Convert one or more SHA256 hashes (or EFI binary paths) to an EFI Signature List."""
    items = [hashes] if isinstance(hashes, (bytes, str, Path)) else list(hashes)
    digests: list[bytes] = []

    for item in items:
        if isinstance(item, Path) or (isinstance(item, str) and len(item) != 64 and Path(item).is_file()):
            item = get_pe_authenticode_hash(Path(item))
        if isinstance(item, str) and len(item) == 64:
            digests.append(bytes.fromhex(item))
        elif isinstance(item, bytes) and len(item) == 32:
            digests.append(item)
        elif isinstance(item, bytes) and len(item) == 64:
            digests.append(bytes.fromhex(item.decode("ascii")))
        else:
            raise ValueError(f"Invalid SHA256 hash or binary path: {item!r}")

    return build_efi_sig_list(EFI_CERT_SHA256_GUID, [(owner_guid, d) for d in digests])


def write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    """Write an RSA private key to file with 0600 file permissions."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "wb") as f:
        f.write(pem_bytes)


def get_or_create_guid(guid_file: Path) -> uuid.UUID:
    """Read existing GUID from file or generate a new one idempotently."""
    if guid_file.is_file():
        content = guid_file.read_text().strip()
        try:
            guid = uuid.UUID(content)
            logging.info("Using existing GUID from %s: %s", guid_file, guid)
            return guid
        except ValueError:
            logging.warning("Invalid UUID in %s, regenerating", guid_file)

    guid = uuid.uuid4()
    logging.info("Generated new GUID: %s", guid)
    guid_file.write_text(f"{guid}\n")
    return guid


def create_relative_symlink(source_path: Path, target_path: Path) -> None:
    """Create or overwrite a relative symlink target_path pointing to source_path."""
    target_path.unlink(missing_ok=True)
    rel_source = os.path.relpath(source_path, target_path.parent)
    target_path.symlink_to(rel_source)
    logging.debug("Created symlink: %s -> %s", target_path, rel_source)


# =====================================================================
# 2. Action: generate-keys
# =====================================================================

def generate_key_and_cert(
    key_type: str,
    cn_prefix: str,
    days: int = DEFAULT_VALIDITY_DAYS,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a new 2048-bit RSA private key and self-signed X.509 certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn_prefix} ({key_type})")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert


def action_generate_keys(cn_prefix: str, days: int = DEFAULT_VALIDITY_DAYS, output_dir: Path = CUSTOM_DIR) -> None:
    """Generate Secure Boot keys, certificates, and initial EFI signature lists."""
    output_dir.mkdir(parents=True, exist_ok=True)
    guid = get_or_create_guid(output_dir / "uuid.txt")

    for key_type in KEY_TYPES:
        key_path = output_dir / f"{key_type}.key"
        crt_path = output_dir / f"{key_type}.crt"
        cer_path = output_dir / f"{key_type}.cer"
        esl_path = output_dir / f"{key_type}.esl"

        if key_path.is_file() and crt_path.is_file():
            logging.info("Existing key and certificate found for %s, keeping them", key_type)
            cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
        else:
            logging.info("Generating new key and certificate for %s", key_type)
            private_key, cert = generate_key_and_cert(key_type, cn_prefix, days)
            write_private_key(key_path, private_key)
            crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        logging.debug("Writing %s", cer_path)
        cer_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

        logging.debug("Writing %s", esl_path)
        esl_path.write_bytes(cert_to_efi_sig_list(cert, guid))

    dbx_esl = output_dir / "dbx.esl"
    if not dbx_esl.is_file():
        logging.info("Initializing empty %s", dbx_esl)
        dbx_esl.touch()


# =====================================================================
# 3. Action: extract-devices
# =====================================================================

def read_eventlog_bytes(eventlog_path: Path = DEFAULT_EVENTLOG_PATH) -> bytes:
    """Read binary TPM2 eventlog bytes, falling back to 'sudo cat' if unreadable directly."""
    if not eventlog_path.is_file():
        raise FileNotFoundError(f"TPM2 eventlog not found: {eventlog_path}")

    try:
        return eventlog_path.read_bytes()
    except PermissionError:
        logging.info("Permission denied reading %s directly, falling back to 'sudo cat'", eventlog_path)
        res = subprocess.run(["sudo", "cat", str(eventlog_path)], capture_output=True, check=True)
        return res.stdout


def parse_tpm2_pcr2_driver_events(data: bytes) -> list[dict]:
    """Parse TCG TPM 2.0 binary event log stream, extracting PCR 2 driver events."""
    if len(data) < 32:
        return []
    event_size = struct.unpack_from("<I", data, 28)[0]
    spec_data = data[32 : 32 + event_size]
    offset = 32 + event_size

    num_algos = struct.unpack_from("<I", spec_data, 24)[0] if len(spec_data) >= 28 else 0
    algo_sizes = {0x0004: 20, 0x000B: 32, 0x000C: 48, 0x000D: 64, 0x0012: 32}
    algo_sizes.update(
        struct.unpack_from("<HH", spec_data, 28 + i * 4)
        for i in range(num_algos) if 28 + (i + 1) * 4 <= len(spec_data)
    )

    extracted, event_num = [], 0
    while offset + 12 <= len(data):
        event_num += 1
        pcr_index, event_type, digest_count = struct.unpack_from("<III", data, offset)
        offset += 12

        digests: dict[int, str] = {}
        for _ in range(digest_count):
            if offset + 2 > len(data):
                break
            algo_id = struct.unpack_from("<H", data, offset)[0]
            dig_size = algo_sizes.get(algo_id, 32)
            digests[algo_id] = data[offset + 2 : offset + 2 + dig_size].hex()
            offset += 2 + dig_size

        if offset + 4 > len(data):
            break
        event_size = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        ev_data = data[offset : offset + event_size]
        offset += event_size

        if pcr_index == 2 and event_type in (0x80000004, 0x80000005) and 0x000B in digests:
            dplen = struct.unpack_from("<Q", ev_data, 24)[0] if len(ev_data) >= 32 else 0
            extracted.append({
                "event_num": event_num,
                "event_type": (
                    "EV_EFI_BOOT_SERVICES_DRIVER" if event_type == 0x80000004 else "EV_EFI_RUNTIME_SERVICES_DRIVER"
                ),
                "sha256": digests[0x000B],
                "device_path": decode_efi_device_path(ev_data[32 : 32 + dplen]),
            })

    return extracted


def read_tpm2_pcr2_driver_events(eventlog_path: Path = DEFAULT_EVENTLOG_PATH) -> list[dict]:
    """Read binary TPM2 eventlog and extract PCR 2 driver events."""
    logging.info("Reading TPM2 binary eventlog from %s", eventlog_path)
    data = read_eventlog_bytes(eventlog_path)
    return parse_tpm2_pcr2_driver_events(data)


def resolve_pci_device(device_path: str) -> Path | None:
    """Resolve a UEFI DevicePath (PciRoot / Pci nodes) to a sysfs PCI device path."""
    root_match = re.search(r"PciRoot\((0x[0-9a-fA-F]+|\d+)\)", device_path)
    pci_nodes = re.findall(r"Pci\((0x[0-9a-fA-F]+|\d+),\s*(0x[0-9a-fA-F]+|\d+)\)", device_path)

    if not pci_nodes:
        return None

    root_num = int(root_match.group(1), 0) if root_match else 0
    curr = Path(f"/sys/devices/pci0000:{root_num:02x}")
    if not curr.is_dir():
        logging.warning("PCI root directory not found: %s", curr)
        return None

    for dev_str, fn_str in pci_nodes:
        dev_num = int(dev_str, 0)
        fn_num = int(fn_str, 0)
        suffix = f":{dev_num:02x}.{fn_num:x}"
        try:
            candidates = [p for p in curr.iterdir() if p.name.endswith(suffix)]
        except OSError as e:
            logging.warning("Failed to inspect %s: %s", curr, e)
            return None

        if not candidates:
            logging.warning("Child device ending with '%s' not found in %s", suffix, curr)
            return None
        curr = candidates[0]

    return curr


def dump_pci_rom(bdf: str, dest_path: Path) -> bool:
    """Dump expansion ROM for PCI device using sudo and sysfs rom enable toggle."""
    rom_file = Path(f"/sys/bus/pci/devices/{bdf}/rom")
    logging.info("Dumping PCI ROM from %s", rom_file)

    sh_cmd = f"echo 1 > '{rom_file}' && cat '{rom_file}'; echo 0 > '{rom_file}'"
    try:
        res = subprocess.run(["sudo", "sh", "-c", sh_cmd], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.warning("Failed to dump ROM for %s: %s", bdf, e)
        return False

    if not res.stdout:
        logging.warning("Extracted ROM for %s is empty", bdf)
        return False

    dest_path.write_bytes(res.stdout)
    logging.info("Successfully dumped %d bytes to %s", len(res.stdout), dest_path)
    return True


def find_uefi_rom_extract() -> Path | None:
    """Find UEFIRomExtract binary in standard build or root directory."""
    candidates = (
        TOOLS_DIR / "UEFIRomExtract" / "UEFIRomExtract",
        TOOLS_DIR / "UEFIRomExtract" / "build" / "UEFIRomExtract",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def extract_gop_with_uefiextract(rom_path: Path, efi_path: Path) -> bool:
    """Extract UEFI GOP image from ROM binary using UEFIRomExtract."""
    extractor_bin = find_uefi_rom_extract()
    if not extractor_bin:
        logging.error("UEFIRomExtract binary not found in %s", TOOLS_DIR / "UEFIRomExtract")
        return False

    logging.info("Extracting UEFI driver from %s using %s", rom_path, extractor_bin.name)
    res = subprocess.run([str(extractor_bin), str(rom_path), str(efi_path)], capture_output=True, text=True)
    if res.returncode != 0:
        logging.warning("UEFIRomExtract failed (exit code %d): %s", res.returncode, res.stdout or res.stderr)
        return False

    logging.debug("UEFIRomExtract output:\n%s", res.stdout.strip())
    return efi_path.is_file() and efi_path.stat().st_size > 0


def action_extract_devices(
    eventlog_path: Path = DEFAULT_EVENTLOG_PATH,
    firmware_dir: Path = FIRMWARE_DIR,
    custom_dir: Path = CUSTOM_DIR,
) -> None:
    """Extract device GOP firmware and hashes from TPM2 eventlog and generate ESLs."""
    firmware_dir.mkdir(parents=True, exist_ok=True)

    guid_file = custom_dir / "uuid.txt"
    owner_guid = get_or_create_guid(guid_file) if guid_file.is_file() else EFI_IMAGE_SECURITY_DATABASE_GUID

    pcr2_events = read_tpm2_pcr2_driver_events(eventlog_path)

    if not pcr2_events:
        logging.warning("No PCR 2 driver events found in TPM eventlog")
        return

    logging.info("Found %d driver event(s) in PCR 2", len(pcr2_events))

    for ev in pcr2_events:
        sha256 = ev["sha256"]
        device_path = ev["device_path"]
        logging.info("--- Event #%s: %s ---", ev["event_num"], ev["event_type"])
        logging.info("  TPM2 SHA256 : %s", sha256)
        logging.info("  DevicePath  : %s", device_path or "(none)")

        pci_dir = resolve_pci_device(device_path) if device_path else None
        bdf = pci_dir.name if pci_dir else None

        if bdf:
            logging.info("  Resolved PCI: %s (%s)", bdf, pci_dir)
            base_name = bdf
        else:
            logging.warning("  Could not resolve PCI BDF from DevicePath; using SHA256 as base name")
            base_name = sha256

        # 1. Generate EFI Signature List (ESL)
        esl_bytes = hash_to_efi_sig_list(sha256, owner_guid)
        esl_path = firmware_dir / f"{base_name}.esl"
        esl_path.write_bytes(esl_bytes)
        logging.info("  Wrote ESL   : %s", esl_path)

        # Create symlink with sha256 name if base_name is BDF
        if base_name != sha256:
            hash_symlink = firmware_dir / f"{sha256}.esl"
            hash_symlink.unlink(missing_ok=True)
            hash_symlink.symlink_to(esl_path.name)
            logging.debug("  Created symlink: %s -> %s", hash_symlink, esl_path.name)

        # 2. Extract ROM, run UEFIRomExtract, and verify with pesign
        if bdf:
            rom_path = firmware_dir / f"{base_name}.rom"
            efi_path = firmware_dir / f"{base_name}.efi"
            if dump_pci_rom(bdf, rom_path) and extract_gop_with_uefiextract(rom_path, efi_path):
                pe_hash = get_pe_authenticode_hash(efi_path)
                if pe_hash == sha256.lower():
                    logging.info("  [OK] GOP PE hash matches TPM2 eventlog: %s", pe_hash)
                else:
                    logging.warning("  [MISMATCH] GOP PE hash (%s) != TPM2 log (%s)", pe_hash, sha256)


# =====================================================================
# 4. Action: sign-variables
# =====================================================================

def merge_db_esl(custom_db_esl: Path, firmware_dir: Path, output_db_esl: Path) -> None:
    """Merge custom db.esl with all unique device ESL files from firmware_dir."""
    if not custom_db_esl.is_file():
        raise FileNotFoundError(f"Missing base db.esl at {custom_db_esl}")

    merged_chunks: list[bytes] = [custom_db_esl.read_bytes()]
    seen_paths: set[Path] = {custom_db_esl.resolve()}
    added_count = 0

    if firmware_dir.is_dir():
        for item in sorted(firmware_dir.glob("*.esl")):
            if item.is_symlink():
                continue
            resolved = item.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            logging.info("Merging firmware ESL: %s", item.name)
            merged_chunks.append(item.read_bytes())
            added_count += 1

    logging.info("Writing merged db.esl (base db + %d device signature lists) to %s", added_count, output_db_esl)
    output_db_esl.unlink(missing_ok=True)
    output_db_esl.write_bytes(b"".join(merged_chunks))


def sign_variable(var_name: str, key_path: Path, crt_path: Path, esl_path: Path, auth_path: Path) -> None:
    """Sign an EFI Signature List using sign-efi-sig-list to create an authenticated update (.auth)."""
    cmd = [
        "sign-efi-sig-list",
        "-k", str(key_path),
        "-c", str(crt_path),
        var_name,
        str(esl_path),
        str(auth_path),
    ]
    logging.debug("Running: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    logging.info("Signed %-4s -> %s (%d bytes)", var_name, auth_path, auth_path.stat().st_size)
    if res.stdout:
        logging.debug("sign-efi-sig-list output:\n%s", res.stdout.strip())


def action_sign_variables(
    custom_dir: Path = CUSTOM_DIR,
    firmware_dir: Path = FIRMWARE_DIR,
    signed_dir: Path = SIGNED_DIR,
) -> None:
    """Prepare signed_config by symlinking, merging db, and generating .auth files."""
    if not shutil.which("sign-efi-sig-list"):
        raise RuntimeError("'sign-efi-sig-list' tool not found in PATH (install efitools)")

    signed_dir.mkdir(parents=True, exist_ok=True)

    # 1. Symlink PK, KEK, dbx from custom_config
    for var in ("PK", "KEK", "dbx"):
        src = custom_dir / f"{var}.esl"
        dst = signed_dir / f"{var}.esl"
        if not src.is_file():
            raise FileNotFoundError(f"Required ESL not found: {src}")
        create_relative_symlink(src, dst)
        logging.info("Symlinked %s.esl -> %s", var, dst)

    # 2. Merge custom_config/db.esl and firmware_config/*.esl into signed_config/db.esl
    merge_db_esl(custom_dir / "db.esl", firmware_dir, signed_dir / "db.esl")

    # 3. Sign all four variables
    signing_matrix = [
        ("PK",  custom_dir / "PK.key",  custom_dir / "PK.crt",  signed_dir / "PK.esl",  signed_dir / "PK.auth"),
        ("KEK", custom_dir / "PK.key",  custom_dir / "PK.crt",  signed_dir / "KEK.esl", signed_dir / "KEK.auth"),
        ("db",  custom_dir / "KEK.key", custom_dir / "KEK.crt", signed_dir / "db.esl",  signed_dir / "db.auth"),
        ("dbx", custom_dir / "KEK.key", custom_dir / "KEK.crt", signed_dir / "dbx.esl", signed_dir / "dbx.auth"),
    ]

    for var_name, key_file, crt_file, esl_file, auth_file in signing_matrix:
        sign_variable(var_name, key_file, crt_file, esl_file, auth_file)


# =====================================================================
# 5. CLI Parser & Entry Point
# =====================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified toolkit for custom UEFI Secure Boot keys and hardware Option ROM whitelisting."
    )
    subparsers = parser.add_subparsers(dest="action", required=True, metavar="ACTION")

    # Action: generate-keys
    p_keys = subparsers.add_parser(
        "generate-keys",
        help="Generate custom PK, KEK, and db keys/certificates, plus initial dbx.esl.",
    )
    p_keys.add_argument(
        "--cn-prefix",
        default="SecureBoot",
        help="Common Name prefix for generated certificates (default: %(default)s)",
    )
    p_keys.add_argument(
        "--days",
        type=int,
        default=DEFAULT_VALIDITY_DAYS,
        help="Certificate validity period in days (default: %(default)s)",
    )
    # Action: extract-devices
    p_extract = subparsers.add_parser(
        "extract-devices",
        help="Extract device GOP firmware & hashes from TPM2 eventlog and generate ESLs.",
    )
    p_extract.add_argument(
        "--eventlog",
        type=Path,
        default=DEFAULT_EVENTLOG_PATH,
        help="Path to binary TPM2 eventlog (default: %(default)s)",
    )

    # Action: sign-variables
    subparsers.add_parser(
        "sign-variables",
        help="Merge custom db.esl with device ESLs and sign all variables (PK, KEK, db, dbx) into .auth files.",
    )

    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = parse_args()

    if args.action == "generate-keys":
        action_generate_keys(cn_prefix=args.cn_prefix, days=args.days)
    elif args.action == "extract-devices":
        action_extract_devices(eventlog_path=args.eventlog)
    elif args.action == "sign-variables":
        action_sign_variables()
    else:
        sys.exit(f"Unknown action: {args.action}")


if __name__ == "__main__":
    main()

