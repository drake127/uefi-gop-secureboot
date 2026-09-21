# Custom UEFI Secure Boot with Hardware Option ROM (GOP) Whitelisting

A set of scripts to configure a custom UEFI Secure Boot key hierarchy (`PK`, `KEK`, `db`, `dbx`) without enrolling or trusting the default Microsoft Third-Party UEFI Certificate Authority.

---

> [!CAUTION]
> ### Critical Warning: Risk of Losing Display and BIOS Setup Access
> If you enable Secure Boot with custom keys that do **not** trust your discrete GPU's Option ROM, the motherboard UEFI firmware will refuse to execute the GPU GOP driver during POST.
>
> * **Symptom**: Black screen immediately upon powering on. No BIOS splash screen, no boot menu, and no video output.
> * **Impact**: On desktop systems with CPUs lacking integrated graphics (e.g. AMD Ryzen desktop X-series, Intel F-series), you **will not be able to see or enter the BIOS Setup utility** to turn Secure Boot back off.
> * **When does the GOP hash change? Always disable Secure Boot beforehand when**:
>   * **Replacing or upgrading the graphics card** (a different GPU model or unit has a different firmware hash).
>   * **Flashing a new vBIOS** to your existing graphics card.
>   * **Updating the motherboard UEFI BIOS** (firmware updates can alter internal GOP blobs, iGPU drivers, or bus initialization).
> * **Motherboard recovery behaviors differ significantly**:
>   * **Gigabyte**: A CMOS reset (jumper or battery removal) **often does not** clear custom Secure Boot keys back to factory defaults. On these boards, recovery typically requires **Q-Flash Plus** (blind flashing the BIOS firmware using the motherboard's rear button and a formatted USB drive).
>   * **ASUS**: Some boards detect failed GOP execution and automatically fall back to CSM (Compatibility Support Module), restoring display output.
>   * **General rule**: Ensure you know how to perform a **headless BIOS reflash** (USB BIOS Flashback / Q-Flash Plus) for your specific motherboard model before enrolling custom keys.

---

## Background & Rationale

Consumer motherboards ship with factory Secure Boot keys dominated by Microsoft:
1. **Microsoft Corporation KEK CA**
2. **Microsoft Windows Production PCA** (for Windows)
3. **Microsoft Corporation UEFI CA 2011 / 2026** (for third-party hardware, Linux distributions, and boot shims)

Trusting the Microsoft Third-Party CA means trusting thousands of third-party binaries, including older bootloaders with known vulnerabilities (such as GRUB shims vulnerable to Boothole).

### The Option ROM Dilemma
Replacing factory keys with your own custom `PK`, `KEK`, and `db` means your firmware enforces signatures on all pre-boot code. Discrete GPUs (AMD Radeon, NVIDIA GeForce, Intel Arc) contain an Option ROM with a **Graphics Output Protocol (GOP)** UEFI driver signed by the hardware vendor using Microsoft's Third-Party UEFI CA.

If the Microsoft Third-Party CA is removed from `db`, the motherboard refuses to load the GPU driver during POST, leaving the system without video output.

### The Targeted Hash Solution
Instead of trusting the broad Microsoft CA, UEFI allows whitelisting the **exact SHA-256 Authenticode hash** of individual binaries in `db`. By whitelisting only the specific GOP hash of your installed graphics card, the GPU initializes normally while maintaining a strict custom Secure Boot policy.

```text
               ┌────────────────────────────────────────────────────────┐
               │              UEFI POST / Firmware Boot                 │
               │  Executes GPU Option ROM & measures into TPM2 PCR 2    │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ extract_devices.py                                                                │
│                                                                                   │
│  1. Parses /sys/kernel/security/tpm0/binary_bios_measurements via tpm2_eventlog   │
│  2. Extracts SHA-256 digest of EV_EFI_BOOT_SERVICES_DRIVER events in PCR 2        │
│  3. Resolves UEFI DevicePath (PciRoot/Pci nodes) to sysfs /sys/devices/pci...     │
│  4. Reads expansion ROM from /sys/bus/pci/devices/<bdf>/rom                       │
│  5. Decompresses GOP with tools/UEFIRomExtract & calculates hash with pesign -h   │
│  6. Validates: pesign hash == TPM eventlog hash                                   │
│  7. Generates firmware_config/<bdf>.esl (EFI_SIGNATURE_LIST)                      │
└──────────────────────────────────────────┬────────────────────────────────────────┘
                                           │
                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ sign_esl.py                                                                       │
│                                                                                   │
│  1. Merges custom_config/db.esl + firmware_config/*.esl -> signed_config/db.esl   │
│  2. Symlinks PK.esl, KEK.esl, dbx.esl into signed_config/                         │
│  3. Generates signed authenticated variable updates (.auth) via sign-efi-sig-list │
│     - PK.auth  (signed by PK.key)                                                 │
│     - KEK.auth (signed by PK.key)                                                 │
│     - db.auth  (signed by KEK.key)                                                │
│     - dbx.auth (signed by KEK.key)                                                │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

* **Hardware**: x86_64 UEFI motherboard with TPM 2.0 enabled in firmware (`/sys/kernel/security/tpm0/binary_bios_measurements`).
* **Python 3.10+**: with `cryptography` and `pyyaml`.
* **System packages**:
  * `tpm2-tools` (provides `tpm2_eventlog`)
  * `efitools` (provides `sign-efi-sig-list`, `hash-to-efi-sig-list`, `sig-list-to-certs`)
  * `pesign` (provides Authenticode PE hashing `pesign -h -i`)
  * `cmake`, `make`, `gcc` (to compile the `tools/UEFIRomExtract` submodule)

---

## Workflow

### 1. Clone Repository & Build Submodule
```bash
git clone --recurse-submodules https://github.com/drake127/secureboot.git
cd secureboot
cmake -B tools/UEFIRomExtract/build tools/UEFIRomExtract
cmake --build tools/UEFIRomExtract/build
```

---

### 2. Generate Custom Keys
Run [generate_keys.py](file:///home/drake127/Projects/gentoo/secureboot/generate_keys.py) to create RSA-2048 private keys, self-signed X.509 certificates, and initial `.esl` files in `custom_config/`:

```bash
./generate_keys.py
```

Optional arguments:
* `--cn-prefix`: Prefix for the certificate Common Name (default: `"SecureBoot"`).
* `--days`: Validity period in days (default: 20 years).

Output files in `custom_config/`:
* `uuid.txt` (Owner GUID)
* `PK.key`, `PK.crt`, `PK.cer`, `PK.esl`
* `KEK.key`, `KEK.crt`, `KEK.cer`, `KEK.esl`
* `db.key`, `db.crt`, `db.cer`, `db.esl`
* `dbx.esl` (initialized as empty revocation list)

> [!NOTE]
> The `custom_config/`, `firmware_config/`, and `signed_config/` directories are excluded from version control. Ensure you keep a secure offline backup of your private keys (`PK.key`, `KEK.key`).

---

### 3. Extract and Verify Hardware Option ROMs
Run [extract_devices.py](file:///home/drake127/Projects/gentoo/secureboot/extract_devices.py) as a regular user (it calls `sudo` internally when privileged access to securityfs and sysfs ROM files is needed):

```bash
./extract_devices.py
```

#### Why check both TPM event log and PCI ROM?
The script performs a dual-verification pass:
1. **TPM 2.0 PCR 2 Eventlog**: Contains the cryptographic measurement of what the UEFI firmware *actually loaded and executed* during the most recent POST (`EV_EFI_BOOT_SERVICES_DRIVER`). This represents the exact binary runtime state.
2. **Direct ROM Dump & pesign**: Dumps the physical Option ROM from `/sys/bus/pci/devices/<bdf>/rom`, uncompresses the UEFI GOP executable using `UEFIRomExtract`, and computes its PE Authenticode hash using `pesign -h -i`.

Cross-referencing both confirms that the extracted offline binary matches the runtime measurement made by the motherboard before enrolling it into the signature list.

*This workflow has been tested and verified on an **AMD Radeon RX 9070 XT**.*

Generated files in `firmware_config/`:
* `<bdf>.esl` (and `<sha256>.esl` symlink) – `EFI_SIGNATURE_LIST` ready for `db`.
* `<bdf>.rom` – raw dumped expansion ROM.
* `<bdf>.efi` – extracted GOP driver binary.

---

### 4. Merge and Sign Variable Updates
Run [sign_esl.py](file:///home/drake127/Projects/gentoo/secureboot/sign_esl.py):

```bash
./sign_esl.py
```

This step:
1. Symlinks `PK.esl`, `KEK.esl`, and `dbx.esl` into `signed_config/`.
2. Merges `custom_config/db.esl` with all unique device signature lists from `firmware_config/*.esl` into `signed_config/db.esl`.
3. Creates signed authenticated variable updates (`.auth`) via `sign-efi-sig-list`:
   * `PK.auth` (signed with `PK.key`)
   * `KEK.auth` (signed with `PK.key`)
   * `db.auth` (signed with `KEK.key`)
   * `dbx.auth` (signed with `KEK.key`)

---

### 5. Enrolling Keys into UEFI Firmware

All prepared `.esl` and signed `.auth` update files are located in **`signed_config/`**.

For detailed step-by-step instructions on putting your firmware into Setup Mode and enrolling custom keys (either through the BIOS setup interface or directly from Linux via `efivarfs` / `efi-updatevar`), refer to the [Gentoo Wiki Secure Boot Guide](https://wiki.gentoo.org/wiki/Secure_Boot).

---

### 6. Operating System Considerations: Kernel & Module Signing

> [!WARNING]
> Before rebooting with Secure Boot enforced, ensure your OS installation is ready:
> * **Bootloader & Kernel**: Your EFI bootloader (e.g. systemd-boot, GRUB) or Unified Kernel Image (UKI) must be signed with `custom_config/db.key`.
> * **Kernel Modules**: In Secure Boot mode, the Linux kernel automatically enables **kernel lockdown**, enforcing signature verification on all loadable kernel modules. Any unsigned or out-of-tree kernel modules (such as NVIDIA proprietary drivers, ZFS, VirtualBox, etc.) will fail to load unless signed with a trusted key or built directly into the kernel.

---

## Directory Structure

```text
├── custom_config/         # Generated private keys, certificates, base ESLs (ignored by git)
├── firmware_config/       # Device GOP binaries, ROM dumps, SHA256 ESLs (ignored by git)
├── signed_config/         # Merged db.esl and signed .auth updates (ignored by git)
├── tools/
│   └── UEFIRomExtract/    # Git submodule: PCI expansion ROM extractor
├── extract_devices.py     # TPM2 eventlog parser & ROM verification script
├── generate_keys.py       # Key and certificate generation script
├── sign_esl.py            # ESL merger & authentication update signer
├── .gitmodules            # Submodule configuration
└── LICENSE                # GNU General Public License v3.0
```

---

## License

This project is licensed under the **GNU General Public License v3.0** (GPLv3). See [LICENSE](file:///home/drake127/Projects/gentoo/secureboot/LICENSE) for details.
