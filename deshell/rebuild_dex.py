#!/usr/bin/env python3
"""把 FART dump 的 rw-anon 区(被抹了 dex\\n magic 的主体 dex)重建成有效 DEX。
用法: python rebuild_dex.py rgn_1.bin rgn_2.bin ...  (每个输出 classes_main_N.dex)"""
import struct, hashlib, zlib, sys
for i, path in enumerate(sys.argv[1:], 1):
    raw = open(path, "rb").read()
    dex = b"dex\n" + raw                       # 易盾删掉了开头 4 字节 "dex\n"，补回
    if dex[:8] != b'dex\n035\x00':
        print(f"[!] {path}: magic 不对({dex[:8]!r})，可能不是该壳的 dex"); continue
    file_size = struct.unpack_from('<I', dex, 0x20)[0]
    body = bytearray(dex[:file_size])
    body[0x0c:0x20] = hashlib.sha1(bytes(body[0x20:])).digest()                     # signature
    struct.pack_into('<I', body, 0x08, zlib.adler32(bytes(body[0x0c:])) & 0xffffffff)  # checksum
    out = f"classes_main_{i}.dex"; open(out, "wb").write(bytes(body))
    print(f"[+] {path} -> {out} ({file_size} bytes)")
