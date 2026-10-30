#!/usr/bin/env python3
"""Regenerate the starter seeds under mayhem/<target>/testsuite/ (run once by hand; the output is committed).

Usage: mayhem/gen_seeds.py <u-boot build dir>   (needs openssl, gzip, bzip2, xz on PATH)
"""
import os, struct, subprocess, sys, tempfile, zlib

build = os.path.abspath(sys.argv[1])
root = os.path.dirname(os.path.abspath(__file__))
text = (b"U-Boot sandbox seed data, repeated for the compressors. " * 12)


os.environ["PATH"] = os.path.join(build, "scripts/dtc") + os.pathsep + os.environ["PATH"]
os.environ["ASAN_OPTIONS"] = "detect_leaks=0"


def put(target, name, data):
    d = os.path.join(root, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(data)


def rd(path):
    return open(os.path.join(build, path), "rb").read()


def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw).stdout


# fdt / overlay
base = rd("test/fdt_overlay/test-fdt-base.dtb")
ovl = rd("test/fdt_overlay/test-fdt-overlay.dtbo")
stacked = rd("test/fdt_overlay/test-fdt-overlay-stacked.dtbo")
other = rd("arch/sandbox/dts/other.dtb")
put("fuzz_fdt", "base.dtb", base)
put("fuzz_fdt", "other.dtb", other)
put("fuzz_fdt", "overlay.dtbo", ovl)
put("fuzz_fdt_overlay", "base_overlay", struct.pack(">I", len(base)) + base + ovl)
put("fuzz_fdt_overlay", "base_stacked", struct.pack(">I", len(base)) + base + stacked)

# FIT
mkimage = os.path.join(build, "tools/mkimage")
with tempfile.TemporaryDirectory() as td:
    open(f"{td}/kernel.bin", "wb").write(text)
    open(f"{td}/base.dtb", "wb").write(base)
    its = """/dts-v1/;
/ {
    description = "seed"; #address-cells = <1>;
    images {
        kernel-1 { description = "k"; data = /incbin/("kernel.bin"); type = "kernel"; arch = "sandbox";
                   os = "linux"; compression = "none"; load = <0x1000>; entry = <0x1000>;
                   hash-1 { algo = "sha256"; }; hash-2 { algo = "crc32"; }; };
        fdt-1 { description = "f"; data = /incbin/("base.dtb"); type = "flat_dt"; arch = "sandbox";
                compression = "none"; hash-1 { algo = "sha1"; }; };
    };
    configurations { default = "conf-1";
        conf-1 { description = "c"; kernel = "kernel-1"; fdt = "fdt-1"; hash-1 { algo = "sha256"; }; }; };
};
"""
    open(f"{td}/s.its", "w").write(its)
    run(mkimage, "-f", f"{td}/s.its", f"{td}/s.itb", cwd=td)
    put("fuzz_fit", "basic.itb", open(f"{td}/s.itb", "rb").read())

    # x509 / pkcs7
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{td}/k.pem", "-out", f"{td}/c.pem",
        "-days", "3650", "-subj", "/CN=seed/O=u-boot", "-sha256")
    put("fuzz_x509", "rsa.der", run("openssl", "x509", "-in", f"{td}/c.pem", "-outform", "DER"))
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", f"{td}/ek.pem", "-out", f"{td}/ec.pem", "-days", "3650", "-subj", "/CN=ec")
    put("fuzz_x509", "ec.der", run("openssl", "x509", "-in", f"{td}/ec.pem", "-outform", "DER"))
    open(f"{td}/data", "wb").write(b"payload\n")
    put("fuzz_pkcs7", "signed.der", run("openssl", "smime", "-sign", "-binary", "-noattr", "-outform", "DER",
        "-signer", f"{td}/c.pem", "-inkey", f"{td}/k.pem", "-in", f"{td}/data"))
    put("fuzz_pkcs7", "signed_attr.der", run("openssl", "smime", "-sign", "-binary", "-outform", "DER",
        "-signer", f"{td}/c.pem", "-inkey", f"{td}/k.pem", "-in", f"{td}/data"))

# gzip: plain, with name/extra/comment header fields
put("fuzz_gzip", "plain.gz", run("gzip", "-9", "-n", "-c", input=text))
co = zlib.compressobj(9, zlib.DEFLATED, -15)
raw = co.compress(text) + co.flush()
hdr = b"\x1f\x8b\x08" + bytes([0x1c]) + b"\0\0\0\0\0\x03" + struct.pack("<H", 4) + b"ABCD" + b"name\0" + b"comment\0"
put("fuzz_gzip", "fields.gz", hdr + raw + struct.pack("<II", zlib.crc32(text), len(text)))

put("fuzz_bzip2", "plain.bz2", b"\x00" + run("bzip2", "-9", "-c", input=text))
put("fuzz_bzip2", "small.bz2", b"\x01" + run("bzip2", "-1", "-c", input=text))
put("fuzz_lzma", "plain.lzma", run("xz", "--format=lzma", "-9", "-c", input=text))


def xxh32(data, seed=0):
    P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    M = 0xFFFFFFFF
    rol = lambda x, r: ((x << r) | (x >> (32 - r))) & M
    n, i = len(data), 0
    if n >= 16:
        v = [(seed + P1 + P2) & M, (seed + P2) & M, seed, (seed - P1) & M]
        while i <= n - 16:
            for k in range(4):
                v[k] = (rol((v[k] + struct.unpack_from("<I", data, i)[0] * P2) & M, 13) * P1) & M
                i += 4
        h = (rol(v[0], 1) + rol(v[1], 7) + rol(v[2], 12) + rol(v[3], 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i + 4 <= n:
        h = (rol((h + struct.unpack_from("<I", data, i)[0] * P3) & M, 17) * P4) & M
        i += 4
    while i < n:
        h = (rol((h + data[i] * P5) & M, 11) * P1) & M
        i += 1
    h ^= h >> 15; h = (h * P2) & M; h ^= h >> 13; h = (h * P3) & M; h ^= h >> 16
    return h


flg, bd = 0x60, 0x40
lz4 = b"\x04\x22\x4d\x18" + bytes([flg, bd, (xxh32(bytes([flg, bd])) >> 8) & 0xFF])
lz4 += struct.pack("<I", 0x80000000 | len(text)) + text + struct.pack("<I", 0)
put("fuzz_lz4", "raw_block.lz4", lz4)
# lz4 compressed block: literal 'abcd' then a 16-byte overlapped match
blk = bytes([0x4C]) + b"abcd" + struct.pack("<H", 4) + bytes([0x50]) + b"hello"
lz4c = b"\x04\x22\x4d\x18" + bytes([flg, bd, (xxh32(bytes([flg, bd])) >> 8) & 0xFF])
lz4c += struct.pack("<I", len(blk)) + blk + struct.pack("<I", 0)
put("fuzz_lz4", "match.lz4", lz4c)

lit = text[:100]
put("fuzz_lzo", "literal.lzo", bytes([17 + len(lit)]) + lit + b"\x11\x00\x00")
put("fuzz_lzo", "match.lzo", bytes([17 + 4]) + b"abcd" + bytes([0x20 | 0x01, 0x03, 0x00]) + b"\x11\x00\x00")

zraw = b"\x28\xb5\x2f\xfd" + bytes([0x60]) + struct.pack("<H", len(text) - 256) + struct.pack("<I", (len(text) << 3) | 1)[:3] + text
put("fuzz_zstd", "raw_block.zst", zraw)
zrle = b"\x28\xb5\x2f\xfd" + bytes([0x20, 64]) + struct.pack("<I", (64 << 3) | 3 | 1)[:3] + b"x"
put("fuzz_zstd", "rle_block.zst", zrle)

put("fuzz_env", "newline", b"\x01bootcmd=run bootm\nbootargs=console=ttyS0 root=/dev/sda\nfoo=bar\nempty=\n")
put("fuzz_env", "nul", b"\x00bootdelay=3\x00baudrate=115200\x00foo=bar\x00\x00")
put("fuzz_env", "forced", b"\x0d\xffloadaddr=0x1000\n\\\nmulti=line\\\ncont\n")

put("fuzz_charset", "utf8", b"\x00h\xc3\xa9llo w\xc3\xb6rld \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xf0\x9f\x98\x80")
put("fuzz_charset", "utf16", b"\x01" + "héllo 日本 \U0001F600".encode("utf-16-le"))
