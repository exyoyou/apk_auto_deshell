#!/usr/bin/env python3
"""deploy.py — 一条命令从「选 APK」到「原生可运行的脱壳 APK」。

调度器(本身不含具体壳逻辑):
  装壳版 APK → 各 unpacker 插件 detect 识别壳型 → 选最高分 → unpack(脱壳)
  → repack(重组可运行 APK)→(可选)装机验证。

壳型逻辑都在 unpackers/ 里,每类壳一个插件(见 unpackers/base.py 说明):
  - cgakq : 磁盘缓存型 Flutter 壳(libcgakq 系)
  - fart  : 内存 dump 型 DEX 壳(易盾/papa 系,通用兜底)
加新壳只需在 unpackers/ 下加一个 @register 的插件,无需改本文件。

必须用带 capstone/frida 的解释器跑(本机:frida/.venv/bin/python)。
用法:  .venv/bin/python deshell/deploy.py [--apk x.apk] [-o out] [--no-install]
        [--timeout 40] [--force cgakq|fart] [--keep-inject] [--reuse-analysis]
"""
import argparse
import atexit
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util          # noqa: E402
import analyze       # noqa: E402
import unpackers     # noqa: E402

ZYG = analyze.ZYG_DIR
HERE = os.path.dirname(os.path.abspath(__file__))


def disable_inject():
    """把 ZygiskFrida config.json 重置成 targets:[],关闭注入。
    注册到 atexit:正常结束/sys.exit/异常/Ctrl-C 都会执行,避免中途失败残留注入目标
    (残留会在下次启动触发 app 自带反 frida → 卡死)。自身吞异常,绝不在退出时再抛错。"""
    try:
        with tempfile.NamedTemporaryFile('w', suffix='_off', delete=False) as t:
            t.write('{ "targets": [] }'); off = t.name
        util.place_in_zyg(off, f'{ZYG}/config.json')
        os.unlink(off)
        print('[*] 已关闭注入(config.json → targets:[])')
    except Exception as e:
        print(f'[!] 关注入失败(请手动确认 {ZYG}/config.json 为 targets:[]): {e}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', help='加壳 APK;不给就在 --apks-dir 交互选')
    ap.add_argument('--apks-dir', default='apks')
    ap.add_argument('-o', '--out', default='out')
    ap.add_argument('--timeout', type=int, default=40, help='等落盘/等 dump 的秒数')
    ap.add_argument('--no-install', action='store_true', help='不装机验证')
    ap.add_argument('--user', default='0', help="adb install 目标用户(默认 0;'all'=全用户)")
    ap.add_argument('--force', help='强制用指定插件(cgakq/fart/…),跳过自动识别')
    ap.add_argument('--keep-inject', action='store_true', help='结束不关注入(默认关)')
    ap.add_argument('--reuse-analysis', action='store_true', help='复用已有分析产物(fart)')
    args = ap.parse_args()

    try:
        import capstone  # noqa: F401
    except ImportError:
        sys.exit('[!] 需要 capstone:用 frida/.venv/bin/python 跑')
    if not util.device_online() or not util.has_root():
        sys.exit('[!] 需要在线的 root 设备')

    apk = os.path.abspath(util.pick_apk(args.apks_dir, args.apk))
    pkg = util.get_pkg(apk)
    if not pkg:
        sys.exit('[X] 读不出包名(aapt?)')
    out = os.path.abspath(os.path.join(args.out, pkg))
    os.makedirs(out, exist_ok=True)
    print(f'[*] APK: {apk}\n[*] 包名: {pkg}\n[*] 输出: {out}')

    ctx = unpackers.Context(apk=apk, pkg=pkg, out=out, here=HERE, timeout=args.timeout,
                            install=not args.no_install, user=args.user,
                            keep_inject=args.keep_inject, reuse_analysis=args.reuse_analysis)

    # ① 确保设备上装的是加壳版(分析/落盘/dump 都要扫它;上次验证可能已换成脱壳版)
    print(f'\n[*] 安装加壳版 APK(供识别 + 脱壳,user={args.user})')
    util.adb('uninstall', pkg)
    r = util.install_apk(apk, user=args.user)
    if not util.install_ok(r):
        sys.exit(f'[X] 装加壳版失败: {r.stdout}{r.stderr}')

    # 任何会开注入的插件,结束都兜底关注入
    if not args.keep_inject:
        atexit.register(disable_inject)

    # ② 识别壳型 → 选插件
    if args.force:
        up = next((u for u in unpackers.REGISTRY if u.name == args.force), None)
        if not up:
            sys.exit(f'[X] 没有插件叫 {args.force};可用: {[u.name for u in unpackers.REGISTRY]}')
        print(f'[*] --force 指定插件: {up.name}')
    else:
        up = unpackers.pick(ctx)
        if not up:
            sys.exit('[X] 没有插件认领这个 APK')
    print(f'\n========== 用插件 [{up.name}] 脱壳 ==========')

    # ③ 脱壳 → 重组
    artifacts = up.unpack(ctx)
    signed = up.repack(ctx, artifacts)
    print(f'\n[✓] 脱壳原生 APK: {os.path.abspath(signed)}')

    # ④ 验证
    if ctx.install:
        up.verify(ctx, signed)
    uflag = '' if args.user == 'all' else f' --user {args.user}'
    print(f'\n安装:\n    adb uninstall {pkg}\n    adb install -r{uflag} {signed}')


if __name__ == '__main__':
    main()
