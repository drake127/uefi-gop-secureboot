#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import datetime
import logging
import os
import re
import struct
import subprocess
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

OUTPUT_DIR = Path("custom_config")
KEY_TYPES = ("PK", "KEK", "db", "dbx")
DEFAULT_VALIDITY_DAYS = 365 * 20


def build_efi_sig_list(sig_type: uuid.UUID, signatures: Sequence[tuple[uuid.UUID, bytes]]) -> bytes:
    """Build an EFI Signature List (EFI_SIGNATURE_LIST) containing one or more signatures.

    All signature payloads in a single list must have the same length.
    """
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
    """Convert an X.509 certificate (in DER or PEM format, or Certificate object) to an EFI Signature List."""
    if isinstance(cert, x509.Certificate):
        cert_der = cert.public_bytes(serialization.Encoding.DER)
    elif isinstance(cert, bytes):
        if b"-----BEGIN" in cert:
            cert_obj = x509.load_pem_x509_certificate(cert)
            cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        else:
            cert_der = cert
    else:
        raise TypeError(f"Unsupported certificate type: {type(cert)}")

    return build_efi_sig_list(EFI_CERT_X509_GUID, [(owner_guid, cert_der)])


def hash_to_efi_sig_list(
    hashes: bytes | str | Path | Sequence[bytes | str | Path],
    owner_guid: uuid.UUID = EFI_IMAGE_SECURITY_DATABASE_GUID,
) -> bytes:
    """Convert one or more SHA256 hashes (or EFI binaries) to an EFI Signature List."""
    if isinstance(hashes, (bytes, str, Path)):
        items: Sequence[bytes | str | Path] = [hashes]
    else:
        items = list(hashes)

    digests: list[bytes] = []
    for item in items:
        if isinstance(item, Path) or (isinstance(item, str) and Path(item).is_file()):
            # EFI binary path: extract hash using hash-to-efi-sig-list
            res = subprocess.run(["hash-to-efi-sig-list", str(item), "/dev/null"], capture_output=True, text=True, check=True)
            match = re.search(r"HASH IS ([0-9a-fA-F]{64})", res.stdout)
            if not match:
                raise ValueError(f"Could not extract hash from hash-to-efi-sig-list for {item}")
            digests.append(bytes.fromhex(match.group(1)))
        elif isinstance(item, str):
            if len(item) == 64:
                digests.append(bytes.fromhex(item))
            else:
                raise ValueError(f"Expected 64-char hex SHA256 string, got: {item}")
        elif isinstance(item, bytes):
            if len(item) == 32:
                digests.append(item)
            elif len(item) == 64:
                digests.append(bytes.fromhex(item.decode("ascii")))
            else:
                raise ValueError(f"Expected 32-byte digest or 64-byte hex digest, got {len(item)} bytes")
        else:
            raise TypeError(f"Unsupported hash item type: {type(item)}")

    signatures = [(owner_guid, digest) for digest in digests]
    return build_efi_sig_list(EFI_CERT_SHA256_GUID, signatures)


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


def generate_keys(
    cn_prefix: str,
    output_dir: Path = OUTPUT_DIR,
    days: int = DEFAULT_VALIDITY_DAYS,
) -> None:
    """Idempotently generate Secure Boot keys, certificates, and EFI signature lists."""
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Secure Boot keys, certificates, and EFI signature lists.")
    parser.add_argument(
        "--cn-prefix",
        default="SecureBoot",
        help="Common Name prefix for generated certificates (default: %(default)s)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_VALIDITY_DAYS,
        help="Certificate validity period in days (default: %(default)s)",
    )

    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    generate_keys(cn_prefix=args.cn_prefix, days=args.days)
