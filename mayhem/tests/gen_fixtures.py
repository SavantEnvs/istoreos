#!/usr/bin/env python3
"""Generate the istoreos test fixtures and fuzz seeds (run once by hand; the
outputs are committed, build.sh/test.sh never run this).

    python3 mayhem/tests/gen_fixtures.py            # from the repo root

Writes mayhem/tests/fixtures/* and mayhem/<target>/testsuite/*.
"""
import hashlib
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")


def put(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def seed(target, name, data):
    put(os.path.join(ROOT, target, "testsuite", name), data)


# ---------------------------------------------------------------- bcm4908img
def jffs2_dirent(name, ino):
    nb = name.encode()
    body = struct.pack("<IIII", 1, 1, ino, 0) + bytes([len(nb), 8, 0, 0]) + struct.pack("<II", 0, 0) + nb
    totlen = 12 + len(body)
    node = struct.pack("<HHII", 0x1985, 0xE001, totlen, 0) + body
    node += b"\x00" * ((-len(node)) % 4)
    return node


def bcm4908img(names, rootfs_payload, pad_blocks=0):
    # the parser reads 256 bytes at each 128 KiB step looking for UBI, so keep rootfs >= 256 B
    bootfs = b"".join(jffs2_dirent(n, i + 2) for i, n in enumerate(names))
    bootfs += b"\xff" * (0x20000 * (1 + pad_blocks) - len(bootfs))
    rootfs = struct.pack(">I", 0x55424923) + rootfs_payload
    data = bootfs + rootfs
    crc = zlib.crc32(data) ^ 0xFFFFFFFF
    tail = struct.pack("<IIIII", crc, 0x5732, 0x4908, 2, 0)
    return data + tail


img = bcm4908img(["cferom.000", "vmlinux.lz", "dtb"], b"rootfs-payload" * 20)
put(os.path.join(FIX, "bcm4908.img"), img)
seed("bcm4908img", "standard.img", img)
seed("bcm4908img", "padded.img", bcm4908img(["cferom.000"], b"x" * 300, pad_blocks=1))

# --------------------------------------------------------------- osafeloader
SALT = bytes([0x7a, 0x2b, 0x15, 0xed, 0x9b, 0x98, 0x59, 0x6d,
              0xe5, 0x04, 0xab, 0x44, 0xac, 0x2a, 0x9f, 0x4e])


def safeloader(parts):
    # parts: list of (name, bytes); data area follows the partition table
    table_len = 0x200
    blobs, table, off = b"", b"", table_len
    for name, blob in parts:
        table += b"fwup-ptn %s base 0x%05x size 0x%05x\t\r\n" % (name.encode(), off, len(blob))
        blobs += blob
        off += len(blob)
    table = table + b"\x00" * (table_len - len(table))
    body = b"\x00" * 0x1000 + table + blobs  # vendor info, partition table, data
    md5 = hashlib.md5(SALT + body).digest()
    return struct.pack(">I", len(body)) + md5 + body


sl = safeloader([("partition-table", b"PT" * 8), ("os-image", b"OSIMAGE-" * 8),
                 ("file-system", b"ROOTFS" * 4)])
put(os.path.join(FIX, "safeloader.bin"), sl)
seed("osafeloader", "three-partitions.bin", sl)
seed("osafeloader", "one-partition.bin", safeloader([("os-image", b"K" * 32)]))

# ------------------------------------------------------------ fritz_tffs_read
def tffs(pairs, swap=False):
    e = ">" if swap else "<"
    names = b""
    for kid, name, _ in pairs:
        nb = name.encode() + b"\x00"
        nb += b"\x00" * ((-len(nb)) % 4)
        names += struct.pack(e + "I", kid) + nb

    def entry(eid, val):
        out = struct.pack(e + "HH", eid, len(val)) + val
        return out + b"\x00" * ((-len(out)) % 4)

    data = entry(0x01FF, names)
    for kid, _, val in pairs:
        data += entry(kid & 0xFFFF, val.encode())
    data += struct.pack(e + "HH", 0xFFFF, 0)
    return data


pairs = [(0x0100, "maca", "00:11:22:33:44:55"), (0x0101, "serialnumber", "SN0042"),
         (0x0102, "HWRevision", "194")]
t = tffs(pairs)
put(os.path.join(FIX, "tffs.bin"), t)
seed("fritz_tffs_read", "le.bin", t)
seed("fritz_tffs_read", "be.bin", tffs(pairs, swap=True))

# ---------------------------------------------------------- fritz_cal_extract
CAL_PAYLOAD = b"calibration-data:" + bytes(range(64))


def caldump(entries):
    out = b""
    for eid, blob in entries:
        out += struct.pack(">HH", eid, len(blob)) + blob
    return out + struct.pack(">HH", 0xFFFF, 0)


cal = caldump([(0x0003, b"\x00" * 8), (0x0007, zlib.compress(CAL_PAYLOAD))])
put(os.path.join(FIX, "cal.bin"), cal)
put(os.path.join(FIX, "cal.expected"), CAL_PAYLOAD)
# harness input: byte0 = entry id, byte1 = flags (bit0 -r, bit1 -l 4096, bit2 -s <byte2>,
# bit3 -i <byte3>), byte2 = seek offset, byte3 = skip count, then the flash dump
seed("fritz_cal_extract", "entry7.bin", b"\x07\x00\x00\x00" + cal)
seed("fritz_cal_extract", "entry7-reverse-limit.bin", b"\x07\x03\x00\x00" + cal)
# -s 12 seeks past entry 3 (4-byte entry header + 8-byte blob); -i 17 skips "calibration-data:"
seed("fritz_cal_extract", "entry7-seek-skip.bin", b"\x07\x0c\x0c\x11" + cal)

# --------------------------------------------------------------------- nvram
def nvram(pairs, size=0x8000):
    kv = b"".join(b"%s=%s\x00" % (k.encode(), v.encode()) for k, v in pairs) + b"\x00"
    hdr = struct.pack("<IIIII", 0x48534C46, 20 + len(kv), 0x12345600, 0x0419_8000, 0x00000062)
    blob = hdr + kv
    return blob + b"\x00" * (size - len(blob))


nv = nvram([("boardtype", "0x0646"), ("lan_ipaddr", "192.168.1.1"), ("wl0_ssid", "OpenWrt")])
put(os.path.join(FIX, "nvram.bin"), nv)
seed("nvram", "nvram.bin", nv.rstrip(b"\x00") + b"\x00\x00")

# ----------------------------------------------------------------------- ead
EAD_MAGIC = 3671771902
EAD_PORT = 56026


def ead_frame(mtype, payload=b"", sid=0, msg_len=None):
    if msg_len is None:
        msg_len = len(payload)
    msg = struct.pack(">IIIHHI", EAD_MAGIC, msg_len, mtype, 0xFFFF, sid, 0x0A000002) + payload
    udp = struct.pack(">HHHH", 40000, EAD_PORT, 8 + len(msg), 0)
    ip = bytes([0x45, 0]) + struct.pack(">HHH", 20 + 8 + len(msg), 0, 0) + bytes([64, 17]) + b"\x00\x00" \
        + bytes([10, 0, 0, 2]) + bytes([255, 255, 255, 255])
    eth = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip + udp + msg


def frames(*fs):
    return b"".join(struct.pack(">H", len(f)) + f for f in fs)


user = ead_frame(2, b"root".ljust(32, b"\x00"))
prime = ead_frame(4)
A = bytes([0x5A]) * 64
send_a = ead_frame(6, b"\x00" + A)
auth = ead_frame(8, b"\x11" * 20)
# A successful username lookup ("root") currently crashes ead (prepare_password() writes the
# `static const` password buffer), so the shipped seeds stop short of it.
seed("ead", "ping.bin", frames(ead_frame(0)))
seed("ead", "unknown-user.bin", frames(ead_frame(0), ead_frame(2, b"admin".ljust(32, b"\x00")), prime,
                                       send_a, auth))

# --------------------------------------------------------- jboot_config_read
def jboot_checksum(data):
    c = 0
    for i in range(0, len(data) - 1, 2):
        c += struct.unpack_from("<H", data, i)[0]
        while c >> 16:
            c = (c & 0xFFFF) + (c >> 16)
    return c


def jboot(headers):
    stag = bytearray(struct.pack("<BBHIIHH", 2, 2, 0x2B24, 0, 0, 0, 0))
    struct.pack_into("<H", stag, 14, (~jboot_checksum(bytes(stag[:14]))) & 0xFFFF)
    body = b"".join(struct.pack("<BBHH", i, t, 0x8000, n) + d for i, t, n, d in headers)
    csxf = bytearray(struct.pack("<HHIB3sI", 0x5343, 0, len(body), 0, b"\0\0\0", len(body)))
    struct.pack_into("<H", csxf, 2, (~jboot_checksum(bytes(csxf) + body)) & 0xFFFF)
    return bytes(stag) + bytes(csxf) + body


# The last header's length runs past the end of the file on purpose: find_header()'s scan
# reads a header at every offset up to and including buf_size, so a config whose last header
# ends exactly at EOF is read out of bounds (a real defect the target reports).
jb = jboot([(0x30, 0x42, 6, bytes([0, 0x11, 0x22, 0x33, 0x44, 0x55])),
            (0x00, 0xF5, 4, b"\xca\xfe\xba\xbe"),
            (0x01, 0x42, 0x100, b"tail")])
seed("jboot_config_read", "mac-and-eeprom.bin", jb)
