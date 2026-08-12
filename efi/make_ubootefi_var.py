#!/usr/bin/env python3
"""Generate a U-Boot ``ubootefi.var`` seed file offline.

This builds the binary consumed by U-Boot's ``CONFIG_EFI_VAR_SEED_FILE``
(``CONFIG_EFI_VARIABLES_PRESEED``) without needing to run U-Boot.

Verified against U-Boot v2025.01:
  - include/efi_variable.h        (struct layout + EFI_VAR_FILE_MAGIC)
  - lib/efi_loader/efi_var_file.c (efi_var_restore: reserved/magic/crc32 only,
                                   entries inserted verbatim -- no signature
                                   verification on the preseed)

Because the preseed path does not verify signatures, secure-boot variables
(PK/KEK/db/dbx) are stored as raw EFI Signature Lists (ESLs), not signed
".auth" blobs.

On-disk format (little-endian):

  struct efi_var_file {          # 24-byte header
      u64 reserved;              # 0
      u64 magic;                 # EFI_VAR_FILE_MAGIC
      u32 length;                # total size including this header
      u32 crc32;                 # zlib CRC32 of everything after the header
  }
  struct efi_var_entry {         # repeated, each padded to 8 bytes
      u32 length;                # size of the variable data
      u32 attr;                  # EFI variable attributes
      u64 time;                  # authentication time (epoch seconds)
      efi_guid_t guid;           # 16-byte vendor GUID (mixed-endian)
      u16 name[];                # NUL-terminated UTF-16LE name
      u8 data[length];           # variable value (an ESL for PK/KEK/db/dbx)
  }

Example:

  ./make_ubootefi_var.py \
      --pk PK.crt --kek KEK.crt --db db.crt \
      --owner 11111111-2222-3333-4444-555555555555 \
      -o ubootefi.var
"""

import argparse
import struct
import sys
import uuid
from binascii import crc32

EFI_VAR_FILE_MAGIC = 0x0161566966456255

# EFI variable attributes.
NV = 0x01  # NON_VOLATILE
BS = 0x02  # BOOTSERVICE_ACCESS
RT = 0x04  # RUNTIME_ACCESS
AT = 0x20  # TIME_BASED_AUTHENTICATED_WRITE_ACCESS

# Attributes U-Boot expects for the authenticated key databases.
AUTH_ATTR = NV | BS | RT | AT  # 0x27

# Well-known vendor GUIDs (see lib/efi_loader/efi_var_common.c).
GLOBAL_VARIABLE_GUID = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")  # PK, KEK
IMAGE_SECURITY_DB_GUID = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")  # db, dbx

# EFI signature-list type GUIDs.
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")


def read_cert_der(path: str) -> bytes:
    """Read an X.509 certificate, converting PEM to DER if necessary."""
    raw = open(path, "rb").read()
    if raw.lstrip().startswith(b"-----BEGIN"):
        import ssl

        return ssl.PEM_cert_to_DER_cert(raw.decode())
    return raw


def esl_x509(cert_der: bytes, owner: uuid.UUID) -> bytes:
    """Wrap an X.509 DER certificate in a single-entry EFI_SIGNATURE_LIST."""
    sig = owner.bytes_le + cert_der  # EFI_SIGNATURE_DATA
    # EFI_SIGNATURE_LIST header is 28 bytes; SignatureHeaderSize is 0.
    return (
        struct.pack(
            "<16sIII",
            EFI_CERT_X509_GUID.bytes_le,
            28 + len(sig),  # SignatureListSize
            0,  # SignatureHeaderSize
            len(sig),  # SignatureSize
        )
        + sig
    )


def esl_sha256(hashes: list[bytes], owner: uuid.UUID) -> bytes:
    """Build an EFI_SIGNATURE_LIST of SHA-256 hashes (typical for dbx)."""
    sig_size = 16 + 32  # owner GUID + digest
    body = b"".join(owner.bytes_le + h for h in hashes)
    return (
        struct.pack(
            "<16sIII",
            EFI_CERT_SHA256_GUID.bytes_le,
            28 + len(body),
            0,
            sig_size,
        )
        + body
    )


def make_entry(
    name: str, guid: uuid.UUID, attr: int, data: bytes, time: int = 0
) -> bytes:
    """Serialize one struct efi_var_entry, padded to an 8-byte boundary."""
    name16 = name.encode("utf-16-le") + b"\x00\x00"  # NUL-terminated
    entry = struct.pack("<IIQ16s", len(data), attr, time, guid.bytes_le)
    entry += name16 + data
    return entry + b"\x00" * (-len(entry) % 8)


def build(entries: bytes) -> bytes:
    """Prepend the struct efi_var_file header and compute the CRC32."""
    header = struct.pack(
        "<QQII",
        0,  # reserved
        EFI_VAR_FILE_MAGIC,  # magic
        24 + len(entries),  # length (incl. header)
        crc32(entries) & 0xFFFFFFFF,  # crc32 over the entries only
    )
    return header + entries


def parse_hash(value: str) -> bytes:
    digest = bytes.fromhex(value.strip())
    if len(digest) != 32:
        raise argparse.ArgumentTypeError("SHA-256 hash must be 32 bytes (64 hex chars)")
    return digest


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--pk", metavar="CERT", help="Platform Key certificate (PEM or DER)")
    p.add_argument("--kek", metavar="CERT", help="Key Exchange Key certificate")
    p.add_argument(
        "--db",
        metavar="CERT",
        action="append",
        default=[],
        help="Signature database certificate (repeatable)",
    )
    p.add_argument(
        "--all",
        metavar="CERT",
        dest="all_cert",
        help="Use one certificate as PK, KEK and db (snakeoil-style). "
        "Explicit --pk/--kek override it; the cert is added to db.",
    )
    p.add_argument(
        "--dbx-hash",
        metavar="SHA256",
        type=parse_hash,
        action="append",
        default=[],
        help="Forbidden SHA-256 hash for dbx (repeatable)",
    )
    p.add_argument(
        "--dbx-esl",
        metavar="FILE",
        help="Pre-built EFI Signature List (ESL) to store verbatim as dbx",
    )
    p.add_argument(
        "--owner",
        type=uuid.UUID,
        default=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        help="Signature owner GUID stored inside each ESL",
    )
    p.add_argument(
        "-o",
        "--output",
        default="ubootefi.var",
        help="Output path (default: ubootefi.var)",
    )
    args = p.parse_args()

    pk = args.pk or args.all_cert
    kek = args.kek or args.all_cert
    db = list(args.db)
    if args.all_cert:
        db.append(args.all_cert)

    blob = b""
    if pk:
        blob += make_entry(
            "PK",
            GLOBAL_VARIABLE_GUID,
            AUTH_ATTR,
            esl_x509(read_cert_der(pk), args.owner),
        )
    if kek:
        blob += make_entry(
            "KEK",
            GLOBAL_VARIABLE_GUID,
            AUTH_ATTR,
            esl_x509(read_cert_der(kek), args.owner),
        )
    if db:
        db_esl = b"".join(esl_x509(read_cert_der(c), args.owner) for c in db)
        blob += make_entry("db", IMAGE_SECURITY_DB_GUID, AUTH_ATTR, db_esl)

    dbx = b""
    if args.dbx_hash:
        dbx += esl_sha256(args.dbx_hash, args.owner)
    if args.dbx_esl:
        dbx += open(args.dbx_esl, "rb").read()
    if dbx:
        blob += make_entry("dbx", IMAGE_SECURITY_DB_GUID, AUTH_ATTR, dbx)

    if not blob:
        p.error(
            "nothing to do: supply at least one of "
            "--all/--pk/--kek/--db/--dbx-hash/--dbx-esl"
        )

    with open(args.output, "wb") as f:
        f.write(build(blob))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
