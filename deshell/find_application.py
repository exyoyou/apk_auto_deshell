#!/usr/bin/env python3
"""find_application.py — 从脱出的 DEX 里自动找出「真正的 Application 入口类」。

壳会把 AndroidManifest 的 application android:name 改成壳自己的桩 Application。
去壳重打包时必须换回真实的 Application,否则全局静态 context 不初始化 → 运行期崩溃
(本样本上表现为 ORMLite `getHelper(null)` → "context argument is null")。

真实 Application = 继承链能到 android/app/Application、且**没有子类**的那个「叶子」类
(中间类如各种 BaseApp/VApp/Hilt_* 都不是入口)。本脚本解析 class_defs 的
superclass 关系,找出所有 Application 叶子并排序(app 自有包优先)。

用法:  python3 -I find_application.py classes*.dex
输出:  候选入口类 + 完整继承链,第一个通常就是要填进 manifest 的 android:name。
"""
import struct, glob, sys, re


def parse(path):
    """返回 {类描述符: 父类描述符},描述符形如 Lcom/foo/Bar;"""
    d = open(path, 'rb').read()
    string_ids_off = struct.unpack_from('<I', d, 0x3c)[0]
    type_ids_off = struct.unpack_from('<I', d, 0x44)[0]
    class_defs_size, class_defs_off = struct.unpack_from('<II', d, 0x60)

    def str_at(idx):
        off = struct.unpack_from('<I', d, string_ids_off + idx * 4)[0]
        p = off
        while d[p] & 0x80:   # 跳过 uleb128 的 size
            p += 1
        p += 1
        return d[p:d.index(b'\x00', p)].decode('utf-8', 'replace')

    def type_desc(tidx):
        if tidx == 0xffffffff:
            return None
        return str_at(struct.unpack_from('<I', d, type_ids_off + tidx * 4)[0])

    out = {}
    for i in range(class_defs_size):
        cidx, _access, sidx = struct.unpack_from('<III', d, class_defs_off + i * 32)
        out[type_desc(cidx)] = type_desc(sidx)
    return out


def chain(cls, supers):
    """cls 到 Application 的继承链;到不了 Application 返回 None"""
    seen, c, ch = set(), cls, [cls]
    while c and c not in seen:
        seen.add(c)
        sp = supers.get(c)
        if sp is None:
            break
        ch.append(sp)
        if sp == 'Landroid/app/Application;':
            return ch
        c = sp
    return ch if ch and ch[-1] == 'Landroid/app/Application;' else None


def main(paths, app_pkg=None):
    supers = {}
    for p in paths:
        supers.update(parse(p))

    defined = set(supers)
    # 所有能到 Application 的类
    app_classes = {c for c in defined if chain(c, supers)}
    # 叶子 = 没有被别的 Application 类继承的
    parents = {supers[c] for c in app_classes if supers.get(c) in app_classes}
    leaves = sorted(app_classes - parents)

    def dotted(desc):
        return desc[1:-1].replace('/', '.') if desc and desc.startswith('L') else desc

    def score(desc):
        name = dotted(desc)
        # app 自有包优先;明显的框架/SDK Application 靠后
        prefer = 0
        if app_pkg and name.startswith(app_pkg.split('.')[0]):
            prefer -= 2
        if re.search(r'(hilt_|_hilt|^androidx\.|multidex|bugly|mob\.|kwad|bytedance|pangle|baidu|tencent)', name, re.I):
            prefer += 2
        return (prefer, name)

    leaves.sort(key=score)

    print("# 候选真实 Application 入口(叶子类,第一个通常就是要填进 manifest 的):\n")
    for desc in leaves:
        ch = chain(desc, supers)
        pretty = ' -> '.join(dotted(x) for x in ch)
        print(f"  {dotted(desc)}")
        print(f"      链: {pretty}\n")
    if not leaves:
        print("  (没找到能继承到 android.app.Application 的叶子类;dex 可能不完整)")
    return leaves


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    pkg = next((a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--pkg=')), None)
    files = []
    for a in args:
        files += sorted(glob.glob(a)) if any(ch in a for ch in '*?[') else [a]
    if not files:
        print("用法: python3 -I find_application.py [--pkg=com.foo] classes*.dex")
        sys.exit(1)
    main(files, pkg)
