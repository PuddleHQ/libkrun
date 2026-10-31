#!/usr/bin/env python3
"""Writes the named seed inputs under corpus/<target>/. Run once; the files are checked in."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
NEXT, WRITE = 1, 2


def put(target, name, data):
    d = os.path.join(HERE, "corpus", target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(bytes(data))


def desc(addr, length, flags, nxt):
    return struct.pack("<QIHH", addr, length, flags, nxt)


def ring_image(descs, avail=(), used_idx=0):
    """A queue's memory: descriptor table at 0, available ring at 0x1000."""
    img = bytearray(0x1010)
    for i, d in enumerate(descs):
        img[16 * i:16 * i + 16] = d
    img[0x1002:0x1004] = struct.pack("<H", len(avail))
    for i, head in enumerate(avail):
        img[0x1004 + 2 * i:0x1006 + 2 * i] = struct.pack("<H", head)
    return bytes(img)


# ---- virtqueue_chain: 12 bytes of setup (size selector 3 = 8 entries), then memory.
def chain_seed(name, descs, avail, size_sel=3, flags=0, pops=3):
    cfg = bytes([size_sel, flags, pops, 0]) + bytes(8)
    put("virtqueue_chain", name, cfg + ring_image(descs, avail))


chain_seed("read-then-write", [desc(0x3000, 64, NEXT, 1), desc(0x3100, 64, WRITE, 0)], [0])
chain_seed("write-only", [desc(0x3000, 4096, WRITE, 0)], [0, 0])
chain_seed("three-readable", [desc(0x3000, 16, NEXT, 1), desc(0x3010, 16, NEXT, 2), desc(0x3020, 16, 0, 0)], [0])
chain_seed("loop-on-itself", [desc(0x3000, 16, NEXT, 0)], [0])
chain_seed("two-descriptor-cycle", [desc(0x3000, 16, NEXT, 1), desc(0x3010, 16, NEXT, 0)], [0])
chain_seed("address-past-memory", [desc(0xffff_ffff_ffff_f000, 64, 0, 0)], [0])
chain_seed("address-in-hole", [desc(0x4_0000, 64, WRITE, 0)], [0])
chain_seed("length-crosses-hole", [desc(0x3_ff00, 0x400, 0, 0)], [0])
chain_seed("zero-length", [desc(0x3000, 0, NEXT, 1), desc(0x3000, 0, WRITE, 0)], [0])
chain_seed("head-past-size", [desc(0x3000, 16, 0, 0)], [200])
chain_seed("event-idx", [desc(0x3000, 16, 0, 0)], [0], flags=1)
chain_seed("max-length", [desc(0x3000, 0xffff_ffff, 0, 0)], [0])
# Scattered rings: the addresses come from the setup bytes (flag 0x80).
put("virtqueue_chain", "scattered-misaligned",
    bytes([3, 0x80, 1, 0]) + struct.pack("<HHH", 0x10, 0x801, 0x1001) + bytes(2) + ring_image([desc(0x3000, 16, 0, 0)], [0]))
put("virtqueue_chain", "scattered-in-hole",
    bytes([3, 0x80, 1, 0]) + struct.pack("<HHH", 0x4000, 0x4400, 0x4800) + bytes(2) + ring_image([desc(0x3000, 16, 0, 0)], [0]))
put("virtqueue_chain", "queue-size-zero", bytes([9, 0, 1, 0]) + bytes(8) + ring_image([desc(0x3000, 16, 0, 0)], [0]))


# ---- balloon_queues: 4 setup bytes, then a 16-bit length and ring memory for each of 5 queues.
def balloon_seed(name, queues, features=0x20, size_sel=3):
    out = bytes([features, size_sel, 0, 1])
    for q in range(5):
        img = queues.get(q, b"")
        out += struct.pack("<H", len(img)) + img
    put("balloon_queues", name, out)


balloon_seed("report-inside-ram", {4: ring_image([desc(0x1_0000, 0x1000, WRITE, 0)], [0])})
balloon_seed("report-two-pages", {4: ring_image([desc(0x1_0000, 0x1000, WRITE | NEXT, 1), desc(0x2_0000, 0x2000, WRITE, 0)], [0])})
balloon_seed("report-crosses-end-of-region", {4: ring_image([desc(0x3_f000, 0x2000, WRITE, 0)], [0])})
balloon_seed("report-in-hole", {4: ring_image([desc(0x5_0000, 0x1000, WRITE, 0)], [0])})
balloon_seed("report-without-feature", {4: ring_image([desc(0x1_0000, 0x1000, WRITE, 0)], [0])}, features=0)
balloon_seed("report-huge-length", {4: ring_image([desc(0, 0xffff_ffff, WRITE, 0)], [0])})
stat = struct.pack("<HQ", 6, 123456) + struct.pack("<HQ", 1, 7)
balloon_seed("stats-buffer", {2: ring_image([desc(0x1_0000, len(stat), 0, 0)], [0])})
balloon_seed("stats-buffer-oversized", {2: ring_image([desc(0x1_0000, 0x10_0000, 0, 0)], [0])})
balloon_seed("inflate-and-deflate", {0: ring_image([desc(0x1_0000, 64, 0, 0)], [0]), 1: ring_image([desc(0x1_0000, 64, 0, 0)], [0])})
balloon_seed("page-hint", {3: ring_image([desc(0x1_0000, 8, 0, 0)], [0])})


# ---- vsock_packets: flag byte, 44-byte header, 16-bit payload length, payload.
def hdr(src_cid=3, dst_cid=2, src_port=1234, dst_port=5000, length=0, typ=1, op=1, flags=0, buf_alloc=65536, fwd=0):
    return struct.pack("<QQIIIHHIII", src_cid, dst_cid, src_port, dst_port, length, typ, op, flags, buf_alloc, fwd)


REQUEST, RESPONSE, RST, SHUTDOWN, RW, CREDIT_UPDATE, CREDIT_REQUEST = 1, 2, 3, 4, 5, 6, 7


def vsock_seed(name, *records):
    out = b""
    for flags, header, payload in records:
        out += bytes([flags]) + header + struct.pack("<H", len(payload)) + payload
    put("vsock_packets", name, out)


vsock_seed("connect", (0, hdr(op=REQUEST), b""))
vsock_seed("connect-and-send", (0, hdr(op=REQUEST), b""), (0, hdr(op=RW, length=5), b"hello"))
vsock_seed("connect-send-shutdown", (0, hdr(op=REQUEST), b""), (0, hdr(op=RW, length=3), b"abc"), (0, hdr(op=SHUTDOWN, flags=3), b""), (0, hdr(op=RST), b""))
vsock_seed("credit-update", (0, hdr(op=REQUEST), b""), (0x40, hdr(op=CREDIT_UPDATE, fwd=100), b""), (0, hdr(op=CREDIT_REQUEST), b""))
vsock_seed("data-without-connection", (0, hdr(op=RW, length=4), b"data"))
vsock_seed("length-past-payload-descriptor", (0, hdr(op=REQUEST), b""), (0x20, hdr(op=RW, length=16), b"0123456789abcdef"))
vsock_seed("length-over-max", (0, hdr(op=RW, length=0xffff_ffff), b"x"))
vsock_seed("payload-descriptor-missing", (0x10, hdr(op=RW, length=8), b"12345678"))
vsock_seed("payload-descriptor-writable", (0x08, hdr(op=RW, length=8), b"12345678"))
vsock_seed("header-descriptor-short", (0x02, hdr(op=REQUEST), b""))
vsock_seed("header-descriptor-past-memory", (0x06, hdr(op=REQUEST), b""))
vsock_seed("wrong-host-cid", (0, hdr(dst_cid=99, op=REQUEST), b""))
vsock_seed("unknown-op", (0, hdr(op=0x7fff), b""))
vsock_seed("datagram-write", (1, hdr(typ=3, op=RW, dst_port=1024, length=4), b"ping"))
vsock_seed("datagram-to-served-port", (0x81, hdr(typ=3, op=RW, length=4), b"ping"))
vsock_seed("normalised-stream", (0x80, hdr(dst_cid=77, dst_port=1, op=REQUEST), b""), (0x80, hdr(dst_cid=77, dst_port=1, op=RW, length=2), b"hi"))
vsock_seed("answer-on-rx-chain", (0x40, hdr(op=REQUEST), b""), (0x40, hdr(op=REQUEST, dst_port=9), b""))


# ---- fuse_requests: 16-bit length, the request, 16-bit reply size.
ops = dict(LOOKUP=1, FORGET=2, GETATTR=3, SETATTR=4, READLINK=5, SYMLINK=6, MKNOD=8, MKDIR=9, UNLINK=10, RMDIR=11,
           RENAME=12, LINK=13, OPEN=14, READ=15, WRITE=16, STATFS=17, RELEASE=18, FSYNC=20, SETXATTR=21,
           GETXATTR=22, LISTXATTR=23, REMOVEXATTR=24, FLUSH=25, OPENDIR=27, READDIR=28, RELEASEDIR=29,
           FSYNCDIR=30, ACCESS=34, CREATE=35, BATCH_FORGET=42, FALLOCATE=43, READDIRPLUS=44, RENAME2=45,
           LSEEK=46, COPY_FILE_RANGE=47)


def req(op, nodeid=1, body=b"", unique=2, length=None):
    n = 40 + len(body) if length is None else length
    return struct.pack("<IIQQIIII", n, ops[op], unique, nodeid, 0, 0, 0, 0) + body


def fuse_seed(name, *requests, reply=0x1000):
    out = b""
    for r in requests:
        out += struct.pack("<H", len(r)) + r + struct.pack("<H", reply)
    put("fuse_requests", name, out)


def cstr(s):
    return s.encode() + b"\0"


zero16 = bytes(16)
fuse_seed("getattr-root", req("GETATTR", body=zero16))
fuse_seed("lookup-file", req("LOOKUP", body=cstr("file")))
fuse_seed("lookup-escape-names", req("LOOKUP", body=cstr("..")), req("LOOKUP", body=cstr("a/b")), req("LOOKUP", body=cstr("")))
fuse_seed("lookup-without-terminator", req("LOOKUP", body=b"file"))
fuse_seed("lookup-symlink-escape", req("LOOKUP", body=cstr("dir")), req("LOOKUP", nodeid=2, body=cstr("sub")), req("LOOKUP", nodeid=3, body=cstr("escape")))
fuse_seed("open-and-read", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 0, 0)),
          req("READ", nodeid=2, body=struct.pack("<QQIIQII", 1, 0, 4096, 0, 0, 0, 0)))
fuse_seed("read-size-huge", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 0, 0)),
          req("READ", nodeid=2, body=struct.pack("<QQIIQII", 1, 0, 0xffff_ffff, 0, 0, 0, 0)))
fuse_seed("write-file", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 1, 0)),
          req("WRITE", nodeid=2, body=struct.pack("<QQIIQII", 1, 0, 5, 0, 0, 0, 0) + b"hello"))
fuse_seed("write-size-over-body", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 1, 0)),
          req("WRITE", nodeid=2, body=struct.pack("<QQIIQII", 1, 0, 0x10000, 0, 0, 0, 0) + b"hi"))
fuse_seed("readdir", req("OPENDIR", body=struct.pack("<II", 0, 0)), req("READDIR", body=struct.pack("<QQIIQII", 1, 0, 4096, 0, 0, 0, 0)),
          req("READDIRPLUS", body=struct.pack("<QQIIQII", 1, 0, 4096, 0, 0, 0, 0)), req("RELEASEDIR", body=struct.pack("<QIIQ", 1, 0, 0, 0)))
fuse_seed("create-and-unlink", req("CREATE", body=struct.pack("<IIII", 0o102, 0o644, 0o22, 0) + cstr("new")), req("UNLINK", body=cstr("new")))
fuse_seed("mkdir-rmdir", req("MKDIR", body=struct.pack("<II", 0o755, 0o22) + cstr("made")), req("RMDIR", body=cstr("made")))
fuse_seed("symlink-readlink", req("SYMLINK", body=cstr("newlink") + cstr("/etc/passwd")), req("LOOKUP", body=cstr("newlink")), req("READLINK", nodeid=2))
fuse_seed("rename", req("RENAME", body=struct.pack("<Q", 1) + cstr("file") + cstr("moved")))
fuse_seed("rename2-exchange", req("RENAME2", body=struct.pack("<QII", 1, 2, 0) + cstr("file") + cstr("link")))
fuse_seed("link", req("LOOKUP", body=cstr("file")), req("LINK", body=struct.pack("<Q", 2) + cstr("hard")))
fuse_seed("setattr-size", req("LOOKUP", body=cstr("file")), req("SETATTR", nodeid=2, body=struct.pack("<II", 1 << 3, 0) + bytes(8) + struct.pack("<Q", 1 << 40) + bytes(88 - 32)))
fuse_seed("statfs", req("STATFS"))
fuse_seed("xattr", req("LOOKUP", body=cstr("file")), req("SETXATTR", nodeid=2, body=struct.pack("<II", 3, 0) + cstr("user.x") + b"val"),
          req("GETXATTR", nodeid=2, body=struct.pack("<II", 100, 0) + cstr("user.x")), req("LISTXATTR", nodeid=2, body=struct.pack("<II", 100, 0)),
          req("REMOVEXATTR", nodeid=2, body=cstr("user.x")))
fuse_seed("fallocate-huge", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 1, 0)),
          req("FALLOCATE", nodeid=2, body=struct.pack("<QQQII", 1, 0, 1 << 40, 0, 0)))
fuse_seed("lseek", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 0, 0)), req("LSEEK", nodeid=2, body=struct.pack("<QQII", 1, 3, 3, 0)))
fuse_seed("copy-file-range", req("LOOKUP", body=cstr("file")), req("OPEN", nodeid=2, body=struct.pack("<II", 2, 0)),
          req("COPY_FILE_RANGE", nodeid=2, body=struct.pack("<QQQQQQQ", 1, 0, 2, 1, 5, 100, 0)))
fuse_seed("forget-and-batch", req("LOOKUP", body=cstr("file")), req("FORGET", nodeid=2, body=struct.pack("<Q", 1)),
          req("BATCH_FORGET", body=struct.pack("<II", 2, 0) + struct.pack("<QQ", 2, 1) + struct.pack("<QQ", 99, 7)))
fuse_seed("batch-forget-count-huge", req("BATCH_FORGET", body=struct.pack("<II", 0xffff_ffff, 0)))
fuse_seed("header-length-too-big", req("GETATTR", body=zero16, length=0x200000))
fuse_seed("header-length-too-short", req("GETATTR", body=zero16, length=8))
fuse_seed("unknown-opcode", struct.pack("<IIQQIIII", 40, 9999, 1, 1, 0, 0, 0, 0))
fuse_seed("access-and-flush", req("ACCESS", body=struct.pack("<II", 4, 0)), req("FLUSH", body=struct.pack("<QIIQ", 1, 0, 0, 0)))
fuse_seed("reply-buffer-tiny", req("GETATTR", body=zero16), reply=4)
fuse_seed("reply-buffer-zero", req("LOOKUP", body=cstr("file")), reply=0)

# Found by fuse_requests: a read of the virtual init file at or past its end underflowed in the
# Linux passthrough backend. The init file is the inode after the root.
fuse_seed("init-inode-read-past-end", req("READ", nodeid=2, body=struct.pack("<QQIIQII", 1, 1 << 40, 4096, 0, 0, 0, 0)),
          req("READ", nodeid=2, body=struct.pack("<QQIIQII", 1, 0xffff_ffff_ffff_fff0, 0xffff_ffff & 0xfffff, 0, 0, 0, 0)))
