#!/usr/bin/env python3
"""repack.py — 去壳重打包:把脱出的真 DEX 塞回原 APK,换掉壳 Application 入口,重签名出可安装 APK。

流程:
  1) apktool d -s  原 APK        —— 保留原 dex、不反编 smali(不重编译、只重打资源+manifest)
  2) 改 AndroidManifest 的 application android:name = 真实 Application(--app 指定,或 --auto 自动找)
  3) apktool b                    —— 重建(aapt2 重打资源 + 改后的 manifest,原 dex 原样带入)
  4) 用真 DEX 替换壳 classes.dex  —— classes.dex / classes2.dex / … (ART 原生 multidex 全加载)
  5) uber-apk-signer 对齐 + 重签名(自动建 debug key,出 v1/v2/v3)

依赖(路径可用环境变量或参数覆盖):
  APKTOOL_JAR   默认 ~/.apklab/apktool_3.0.3.jar
  SIGNER_JAR    默认 ~/.apklab/uber-apk-signer-1.3.0.jar
  java          在 PATH 里

用法:
  python3 repack.py --apk 原.apk --dex-dir 脱出的dex目录 --auto -o 输出目录
  python3 repack.py --apk 原.apk --dex a.dex,b.dex --app com.MApplication -o out
"""
import argparse, os, re, shutil, subprocess, sys, glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util  # noqa: E402

HOME = os.path.expanduser('~')
APKTOOL = os.environ.get('APKTOOL_JAR', f'{HOME}/.apklab/apktool_3.0.3.jar')
SIGNER = os.environ.get('SIGNER_JAR', f'{HOME}/.apklab/uber-apk-signer-1.3.0.jar')


def run(cmd, **kw):
    print('  $', ' '.join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def collect_dexes(dex_dir, dex_list):
    files = []
    if dex_dir:
        files = sorted(glob.glob(os.path.join(dex_dir, '*.dex')),
                       key=lambda p: (len(os.path.basename(p)), p))  # 名短的在前,稳定顺序
    if dex_list:
        files = [p.strip() for p in dex_list.split(',') if p.strip()]
    if not files:
        sys.exit('[!] 没找到任何 dex,检查 --dex-dir / --dex')
    return files


def detect_app(dex_files, pkg):
    here = os.path.dirname(os.path.abspath(__file__))
    out = subprocess.run([sys.executable, '-I', os.path.join(here, 'find_application.py')]
                         + (['--pkg=' + pkg] if pkg else []) + dex_files,
                         capture_output=True, text=True)
    print(out.stdout)
    m = re.search(r'^  ([A-Za-z][\w.]+)$', out.stdout, re.M)
    if not m:
        sys.exit('[!] 自动识别 Application 失败,请用 --app 手动指定')
    return m.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', help='原始(加壳)APK;不给就在 --apks-dir 里交互选')
    ap.add_argument('--apks-dir', default='apks', help='APK 目录(默认 apks/,--apk 未给时用)')
    ap.add_argument('--dex-dir', help='脱出的真 DEX 所在目录(取其中所有 *.dex)')
    ap.add_argument('--dex', help='或直接逗号分隔的 dex 列表(覆盖 --dex-dir)')
    ap.add_argument('--app', help='真实 Application 全名(如 com.MApplication)')
    ap.add_argument('--auto', action='store_true', help='自动从 dex 识别真实 Application')
    ap.add_argument('--pkg', help='app 包名(辅助 --auto 排序)')
    ap.add_argument('-o', '--out', default='deshell_out', help='输出目录')
    ap.add_argument('--keep-shell-lib', help='逗号分隔:要从 APK 删除的壳 so basename(如 libvuoum.so),默认不删')
    args = ap.parse_args()

    for jar, name in [(APKTOOL, 'apktool'), (SIGNER, 'uber-apk-signer')]:
        if not os.path.exists(jar):
            sys.exit(f'[!] 找不到 {name}: {jar}(用环境变量 APKTOOL_JAR / SIGNER_JAR 指定)')

    args.apk = util.pick_apk(args.apks_dir, args.apk)   # --apk 未给则终端选
    print(f'[*] 原始 APK: {args.apk}')
    dex_files = collect_dexes(args.dex_dir, args.dex)
    pkg = args.pkg or util.get_pkg(args.apk)       # 没传 --pkg 就用 aapt 从 APK 读(辅助 --auto 排序)
    if pkg and not args.pkg:
        print(f'[*] 包名(aapt 自动识别): {pkg}')
    app = args.app or (detect_app(dex_files, pkg) if args.auto else None)
    if not app:
        sys.exit('[!] 必须用 --app 指定真实 Application,或用 --auto 自动识别')
    print(f'[*] 真实 Application 入口: {app}')
    print(f'[*] 真 DEX {len(dex_files)} 个: {", ".join(os.path.basename(x) for x in dex_files)}')

    args.apk = os.path.abspath(args.apk)
    args.out = os.path.abspath(args.out)          # 后面 zip 用 cwd=stage,路径必须绝对
    os.makedirs(args.out, exist_ok=True)
    work = os.path.join(args.out, 'work')
    unsigned = os.path.join(args.out, 'unsigned.apk')
    if os.path.exists(work):
        shutil.rmtree(work)

    # 1) 解包(-s 保留原 dex)
    run(['java', '-jar', APKTOOL, 'd', '-s', '-f', args.apk, '-o', work])

    # 2) 改 manifest 入口 Application
    mf = os.path.join(work, 'AndroidManifest.xml')
    xml = open(mf, encoding='utf-8').read()
    m = re.search(r'(<application\b[^>]*?\bandroid:name=")([^"]+)(")', xml)
    if not m:
        sys.exit('[!] manifest 里没找到 <application android:name=...>')
    old = m.group(2)
    xml = xml[:m.start(2)] + app + xml[m.end(2):]
    open(mf, 'w', encoding='utf-8').write(xml)
    print(f'[*] 入口 Application: {old}  ->  {app}')

    # 兜底:aapt 没拿到时从 manifest 读包名(用于安装提示)
    if not pkg:
        pm = re.search(r'\bpackage="([^"]+)"', xml)
        pkg = pm.group(1) if pm else None
        if pkg:
            print(f'[*] 包名(manifest 自动识别): {pkg}')

    # 3) 重建
    run(['java', '-jar', APKTOOL, 'b', work, '-o', unsigned])

    # 4) 换真 dex:删原 classes.dex,加 classes.dex/classes2.dex/...
    stage = os.path.join(args.out, 'dex_stage')
    if os.path.exists(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    names = []
    for i, src in enumerate(dex_files, 1):
        name = 'classes.dex' if i == 1 else f'classes{i}.dex'
        shutil.copy(src, os.path.join(stage, name))
        names.append(name)
    # 删壳 classes.dex(原 APK 通常只有一个);用 zip 删除再加入
    subprocess.run(['zip', '-q', '-d', unsigned, 'classes.dex'],
                   cwd=stage)  # 原 APK 若有 classes2+ 也应删,见下
    # 删掉原包里残留的 classesN.dex(壳的 multidex),避免和真 dex 冲突
    existing = subprocess.run(['unzip', '-Z1', unsigned], capture_output=True, text=True).stdout.split()
    stale = [n for n in existing if re.fullmatch(r'classes\d*\.dex', n) and n not in names]
    if stale:
        subprocess.run(['zip', '-q', '-d', unsigned] + stale, cwd=stage)
    run(['zip', '-q', '-X', unsigned] + names, cwd=stage)

    # (可选)删壳 so
    if args.keep_shell_lib:
        libs = [x.strip() for x in args.keep_shell_lib.split(',') if x.strip()]
        paths = [n for n in subprocess.run(['unzip', '-Z1', unsigned], capture_output=True, text=True).stdout.split()
                 if any(n.endswith('/' + l) for l in libs)]
        if paths:
            subprocess.run(['zip', '-q', '-d', unsigned] + paths)
            print(f'[*] 已删壳 so: {paths}')

    # 5) 对齐 + 重签名
    run(['java', '-jar', SIGNER, '--apks', unsigned, '--allowResign', '-o', os.path.join(args.out, 'signed')])

    signed = glob.glob(os.path.join(args.out, 'signed', '*-debugSigned.apk'))
    print('\n[✓] 完成。可安装 APK:')
    for s in signed:
        print('   ', os.path.abspath(s))
    print('\n安装(签名不同,先卸原版;脱壳版可装在未 root 的机器上):')
    print(f'    adb uninstall {pkg or "<包名>"}')
    print(f'    adb install -r {signed[0] if signed else "<signed.apk>"}')


if __name__ == '__main__':
    main()
