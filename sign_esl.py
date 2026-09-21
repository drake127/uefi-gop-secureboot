#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import logging
import os
import shutil
import subprocess

from pathlib import Path


CUSTOM_DIR = Path("custom_config")
FIRMWARE_DIR = Path("firmware_config")
SIGNED_DIR = Path("signed_config")


def create_relative_symlink(source_path: Path, target_path: Path) -> None:
    """Create or overwrite a relative symlink target_path pointing to source_path."""
    target_path.unlink(missing_ok=True)
    rel_source = os.path.relpath(source_path, target_path.parent)
    target_path.symlink_to(rel_source)
    logging.debug("Created symlink: %s -> %s", target_path, rel_source)


def merge_db_esl(custom_db_esl: Path, firmware_dir: Path, output_db_esl: Path) -> None:
    """Merge custom db.esl with all unique device ESL files from firmware_dir."""
    if not custom_db_esl.is_file():
        raise FileNotFoundError(f"Missing base db.esl at {custom_db_esl}")

    merged_chunks: list[bytes] = [custom_db_esl.read_bytes()]
    seen_paths: set[Path] = {custom_db_esl.resolve()}
    added_count = 0

    if firmware_dir.is_dir():
        for item in sorted(firmware_dir.glob("*.esl")):
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


def process_signatures() -> None:
    """Prepare signed_config by symlinking, merging db, and generating .auth files."""
    if not shutil.which("sign-efi-sig-list"):
        raise RuntimeError("'sign-efi-sig-list' tool not found in PATH (install efitools)")

    SIGNED_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Symlink PK, KEK, dbx from custom_config
    for var in ("PK", "KEK", "dbx"):
        src = CUSTOM_DIR / f"{var}.esl"
        dst = SIGNED_DIR / f"{var}.esl"
        if not src.is_file():
            raise FileNotFoundError(f"Required ESL not found: {src}")
        create_relative_symlink(src, dst)
        logging.info("Symlinked %s.esl -> %s", var, dst)

    # 2. Merge custom_config/db.esl and firmware_config/*.esl into signed_config/db.esl
    merge_db_esl(CUSTOM_DIR / "db.esl", FIRMWARE_DIR, SIGNED_DIR / "db.esl")

    # 3. Sign all four variables
    # PK  is signed by PK.key
    # KEK is signed by PK.key
    # db  is signed by KEK.key
    # dbx is signed by KEK.key
    signing_matrix = [
        ("PK",  CUSTOM_DIR / "PK.key",  CUSTOM_DIR / "PK.crt",  SIGNED_DIR / "PK.esl",  SIGNED_DIR / "PK.auth"),
        ("KEK", CUSTOM_DIR / "PK.key",  CUSTOM_DIR / "PK.crt",  SIGNED_DIR / "KEK.esl", SIGNED_DIR / "KEK.auth"),
        ("db",  CUSTOM_DIR / "KEK.key", CUSTOM_DIR / "KEK.crt", SIGNED_DIR / "db.esl",  SIGNED_DIR / "db.auth"),
        ("dbx", CUSTOM_DIR / "KEK.key", CUSTOM_DIR / "KEK.crt", SIGNED_DIR / "dbx.esl", SIGNED_DIR / "dbx.auth"),
    ]

    for var_name, key_file, crt_file, esl_file, auth_file in signing_matrix:
        sign_variable(var_name, key_file, crt_file, esl_file, auth_file)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge ESL files and sign Secure Boot variables (PK, KEK, db, dbx) into .auth files."
    )
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    return parser.parse_args()


if __name__ == "__main__":
    parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    process_signatures()

