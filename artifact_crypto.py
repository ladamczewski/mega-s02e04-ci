"""Authenticated CMS envelopes; private keys never leave the coordinator."""

import io
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


MAX_BYTES = 32 * 1024 * 1024
MEMBERS = {"job-1-result.json", "audit.jsonl"}


def openssl(arguments, data):
    process = subprocess.run(["openssl", *arguments], input=data,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=60, check=False)
    if process.returncode:
        raise ValueError("Artifact cryptography failed; no plaintext was published")
    return process.stdout


def encrypt_artifact(source, certificate, destination):
    source, destination = Path(source), Path(destination)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(MEMBERS):
            path = source / name
            if path.exists():
                if path.is_symlink() or path.stat().st_size > MAX_BYTES:
                    raise ValueError("Unsafe artifact input")
                archive.writestr(name, path.read_bytes())
    encrypted = openssl(["cms", "-encrypt", "-binary", "-outform", "DER",
                         "-aes-256-gcm", str(certificate)], buffer.getvalue())
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Replace a prior encrypted checkpoint only after a complete envelope exists.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".cms-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encrypted)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def decrypt_artifact(encrypted, private_key):
    if len(encrypted) > MAX_BYTES:
        raise ValueError("Artifact exceeds size limit")
    plaintext = openssl(["cms", "-decrypt", "-binary", "-inform", "DER",
                         "-inkey", str(private_key)], encrypted)
    if len(plaintext) > MAX_BYTES:
        raise ValueError("Decrypted archive exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not set(names) <= MEMBERS:
            raise ValueError("Unexpected artifact members")
        if sum(info.file_size for info in archive.infolist()) > MAX_BYTES:
            raise ValueError("Expanded artifact exceeds size limit")
        return {name: archive.read(name) for name in names}
