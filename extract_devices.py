#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import logging
import os
import re
import shutil
import subprocess
import yaml

from pathlib import Path
from generate_keys import hash_to_efi_sig_list, get_or_create_guid, OUTPUT_DIR, EFI_IMAGE_SECURITY_DATABASE_GUID


FIRMWARE_DIR = Path("firmware_config")
DEFAULT_EVENTLOG_PATH = Path("/sys/kernel/security/tpm0/binary_bios_measurements")
TOOLS_DIR = Path(__file__).resolve().parent / "tools"
UEFI_ROM_EXTRACT_BIN = TOOLS_DIR / "UEFIRomExtract" / "UEFIRomExtract"


def run_cmd(cmd: list[str], check: bool = True, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Helper to run a subprocess command."""
    return subprocess.run(cmd, capture_output=capture_output, text=True, check=check)


def read_tpm2_eventlog(eventlog_path: Path = DEFAULT_EVENTLOG_PATH) -> list[dict]:
    """Read and parse TPM2 eventlog YAML via tpm2_eventlog with sudo."""
    if not shutil.which("tpm2_eventlog"):
        raise RuntimeError("'tpm2_eventlog' tool not found in PATH")

    logging.info("Reading TPM2 eventlog from %s", eventlog_path)
    res = run_cmd(["sudo", "tpm2_eventlog", str(eventlog_path)])
    data = yaml.safe_load(res.stdout)
    return data.get("events", []) if isinstance(data, dict) else []


def extract_pcr2_driver_events(events: list[dict]) -> list[dict]:
    """Filter PCR 2 driver events and extract their SHA256 digest and device path."""
    extracted = []
    for ev in events:
        if ev.get("PCRIndex") != 2:
            continue

        event_type = ev.get("EventType", "")
        # Filter out EV_SEPARATOR and other non-driver events
        if event_type not in ("EV_EFI_BOOT_SERVICES_DRIVER", "EV_EFI_RUNTIME_SERVICES_DRIVER"):
            logging.debug("Skipping PCR 2 event with EventType: %s (EventNum %s)", event_type, ev.get("EventNum"))
            continue

        # Find SHA-256 digest
        sha256_digest = None
        for d in ev.get("Digests", []):
            if d.get("AlgorithmId", "").lower() in ("sha256", "sha-256"):
                sha256_digest = d.get("Digest")
                break

        if not sha256_digest:
            logging.warning("No SHA-256 digest found for PCR 2 event %s", ev.get("EventNum"))
            continue

        event_data = ev.get("Event", {})
        device_path = event_data.get("DevicePath", "") if isinstance(event_data, dict) else ""

        extracted.append({
            "event_num": ev.get("EventNum"),
            "event_type": event_type,
            "sha256": sha256_digest,
            "device_path": device_path,
            "event_data": event_data,
        })
    return extracted


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


def get_pe_authenticode_hash(efi_path: Path) -> str | None:
    """Calculate Authenticode SHA-256 hash using pesign -h -i."""
    if not shutil.which("pesign"):
        logging.warning("'pesign' tool not found, skipping hash verification")
        return None

    res = run_cmd(["pesign", "-h", "-i", str(efi_path)])
    match = re.search(r"^([0-9a-fA-F]{64})", res.stdout.strip())
    if not match:
        logging.warning("Could not parse pesign output: %s", res.stdout)
        return None
    return match.group(1).lower()


def process_devices() -> None:
    """Main extraction and verification pipeline."""
    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)

    guid_file = OUTPUT_DIR / "uuid.txt"
    owner_guid = get_or_create_guid(guid_file) if guid_file.is_file() else EFI_IMAGE_SECURITY_DATABASE_GUID

    events = read_tpm2_eventlog()
    pcr2_events = extract_pcr2_driver_events(events)

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
        esl_path = FIRMWARE_DIR / f"{base_name}.esl"
        esl_path.write_bytes(esl_bytes)
        logging.info("  Wrote ESL   : %s", esl_path)

        # Create symlink with sha256 name if base_name is BDF
        if base_name != sha256:
            hash_symlink = FIRMWARE_DIR / f"{sha256}.esl"
            hash_symlink.unlink(missing_ok=True)
            hash_symlink.symlink_to(esl_path.name)
            logging.debug("  Created symlink: %s -> %s", hash_symlink, esl_path.name)

        # 2. Bonus: Extract ROM, run UEFIRomExtract, and verify with pesign
        if bdf:
            rom_path = FIRMWARE_DIR / f"{base_name}.rom"
            efi_path = FIRMWARE_DIR / f"{base_name}.efi"

            if dump_pci_rom(bdf, rom_path):
                if extract_gop_with_uefiextract(rom_path, efi_path):
                    pe_hash = get_pe_authenticode_hash(efi_path)
                    if pe_hash:
                        if pe_hash.lower() == sha256.lower():
                            logging.info("  [OK] GOP PE hash matches TPM2 eventlog: %s", pe_hash)
                        else:
                            logging.warning("  [MISMATCH] GOP PE hash (%s) != TPM2 log (%s)", pe_hash, sha256)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract device GOP firmware and hashes from TPM2 eventlog and generate ESL."
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
    process_devices()
