#!/usr/bin/env python3
"""直接解析 DEX 的 class_defs 段，快速列出所有已定义类（不反汇编）。
用法: python3 list_classdefs.py a.dex b.dex ...  -> 打印去重类名(以/分隔)"""
import struct, sys

def classdefs(path):
    d = open(path, 'rb').read()
    # header: string_ids_size@0x38? 用标准偏移
    string_ids_size, string_ids_off = struct.unpack_from('<II', d, 0x38)
    type_ids_size, type_ids_off     = struct.unpack_from('<II', d, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from('<II', d, 0x60)
    # string offsets
    def str_at(idx):
        off = struct.unpack_from('<I', d, string_ids_off + idx*4)[0]
        # uleb128 size then MUTF-8
        p = off
        shift=0; val=0
        while True:
            b=d[p]; p+=1; val |= (b&0x7f)<<shift
            if not (b&0x80): break
            shift+=7
        end=d.index(b'\x00', p)
        return d[p:end].decode('utf-8','replace')
    type_to_str = lambda tidx: struct.unpack_from('<I', d, type_ids_off + tidx*4)[0]
    out=[]
    for i in range(class_defs_size):
        class_idx = struct.unpack_from('<I', d, class_defs_off + i*32)[0]
        sidx = type_to_str(class_idx)
        desc = str_at(sidx)   # like Lcom/foo/Bar;
        if desc.startswith('L') and desc.endswith(';'):
            out.append(desc[1:-1])
    return out

seen=set()
for p in sys.argv[1:]:
    for c in classdefs(p):
        seen.add(c)
for c in sorted(seen):
    print(c)
