#!/usr/bin/env python3
"""deploy.py — 一条命令从「选 APK」到「可安装脱壳 APK」。

串起:analyze(没跑过就自动跑) → 推配置/脚本到 ZygiskFrida → 杀透重启 app →
轮询拉 dump 的 DEX → rebuild_dex → repack 重签名 →(可选)装机验证。

这个壳首轮扫描(~5s,隐私弹窗阶段)就能抓全已解密 DEX(早于守护进程的 signal-9),
所以整个 dump 全自动、不用点屏。若 0 产出,会自动找「加载了壳 so 的守护进程」补进 config 重试一次。

必须用带 capstone/frida 的解释器跑(本机:frida/.venv/bin/python)。
用法:  .venv/bin/python deshell/deploy.py [--apk x.apk] [-o out] [--install] [--timeout 25]
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util          # noqa: E402
import analyze       # noqa: E402

ZYG = analyze.ZYG_DIR
HERE = os.path.dirname(os.path.abspath(__file__))


def sh(cmd):
    print('  $', cmd if isinstance(cmd, str) else ' '.join(cmd))
    return subprocess.run(cmd, shell=isinstance(cmd, str))


def kill_app(pkg):
    last = pkg.split('.')[-1]
    for _ in range(8):
        util.adb('shell', 'am', 'force-stop', pkg)
        util.su(f'pkill -9 -f {last}')
        time.sleep(1.2)
        if not analyze.running_app_procs(pkg):
            return True
    return not analyze.running_app_procs(pkg)


def push_configs(cfg_json, dump_js):
    """把 ZygiskFrida config.json + dump 脚本 + script 模式 gadget 配置推上去(SELinux 安全)。"""
    # gadget script 模式配置(指向 config.json.example)
    import tempfile
    gcfg = '{ "interaction": { "type": "script", "path": "%s/config.json.example", "on_change": "ignore" } }' % ZYG
    with tempfile.NamedTemporaryFile('w', suffix='_gcfg', delete=False) as t:
        t.write(gcfg); gcfg_local = t.name
    for local, remote in [(cfg_json, f'{ZYG}/config.json'),
                          (dump_js, f'{ZYG}/config.json.example'),
                          (gcfg_local, f'{ZYG}/libgadget.config.so')]:
        ok, out = util.place_in_zyg(local, remote)
        print(f'    [{"✓" if ok else "X"}] {os.path.basename(remote)}' + ('' if ok else f'  {out.strip()}'))
    os.unlink(gcfg_local)


def count_dumps(pkg):
    out = util.su(f'ls {data_dir(pkg)}/zf_mdex_*.bin 2>/dev/null | wc -l').strip()
    return int(out) if out.isdigit() else 0


def data_dir(pkg):
    return f'/data/data/{pkg}'


def wait_for_dumps(pkg, timeout):
    """轮询直到 dump 数量稳定或超时。"""
    last, stable = -1, 0
    t0 = time.time()
    while time.time() - t0 < timeout:
        n = count_dumps(pkg)
        if n and n == last:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
        last = n
        print(f'    …已抓到 {n} 个 dex({int(time.time()-t0)}s)')
        time.sleep(3)
    return count_dumps(pkg)


def pull_dumps(pkg, dst):
    os.makedirs(dst, exist_ok=True)
    names = util.su(f'ls {data_dir(pkg)}/zf_mdex_*.bin 2>/dev/null').split()
    got = []
    for rp in names:
        base = os.path.basename(rp)
        lp = os.path.join(dst, base)
        data = subprocess.run(['adb', 'exec-out', 'su', '-c', f'cat {rp}'], capture_output=True).stdout
        if data[:4] == b'\x30\x33\x35\x00':
            open(lp, 'wb').write(data)
            got.append(lp)
    return got


def suicide_lib_from_js(dump_js):
    m = re.search(r"SUICIDE_LIB:\s*'([^']*)'", open(dump_js, encoding='utf-8').read())
    return m.group(1) if m else ''


def escalate_guardians(pkg, cfg_json, lib):
    """找当前在跑、加载了壳 so、但还没进 config 的进程,补进 config.json。返回是否有新增。"""
    import json
    cfg = json.load(open(cfg_json, encoding='utf-8'))
    have = {t['app_name'] for t in cfg['targets']}
    added = []
    for name, pid in analyze.running_app_procs(pkg):
        if name not in have and analyze.proc_has_lib(pid, lib):
            added.append(name)
    if added:
        for name in added:
            cfg['targets'].append({'app_name': name, 'enabled': True,
                                   'start_up_delay_ms': 500,
                                   'injected_libraries': [{'path': analyze.GADGET_PATH}]})
        json.dump(cfg, open(cfg_json, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
        print(f'    发现未patch的壳进程,补入 config: {added}')
    return bool(added)


def run_analyze(apk, out, reuse):
    """跑 analyze(加壳版此时应已装好,用 --no-install)。reuse=True 且已有产物就复用。"""
    pkg = util.get_pkg(apk)
    dump_js = os.path.join(out, f'dump_{pkg}.js')
    cfg_json = os.path.join(out, f'config_{pkg}.json')
    if reuse and os.path.exists(dump_js) and os.path.exists(cfg_json) and suicide_lib_from_js(dump_js):
        print('[*] 复用已有分析产物(--reuse-analysis)')
        return pkg, dump_js, cfg_json
    print('[*] 跑 analyze 找自杀点 + 出配置...')
    r = subprocess.run([sys.executable, os.path.join(HERE, 'analyze.py'),
                        '--apk', apk, '-o', out, '--no-install'])
    if r.returncode != 0 or not os.path.exists(dump_js):
        sys.exit('[X] analyze 失败,单独跑 `analyze.py` 排查')
    return pkg, dump_js, cfg_json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', help='加壳 APK;不给就在 --apks-dir 交互选')
    ap.add_argument('--apks-dir', default='apks')
    ap.add_argument('-o', '--out', default='out')
    ap.add_argument('--timeout', type=int, default=28, help='等 dump 的秒数')
    ap.add_argument('--install', action='store_true', help='最后把脱壳 APK 装机并启动验证')
    ap.add_argument('--keep-inject', action='store_true', help='结束后不关闭注入(默认关,恢复干净)')
    ap.add_argument('--reuse-analysis', action='store_true', help='复用已有 analyze 产物(默认每次重新分析)')
    args = ap.parse_args()

    try:
        import capstone  # noqa: F401
    except ImportError:
        sys.exit('[!] 需要 capstone:用 frida/.venv/bin/python 跑')
    if not util.device_online() or not util.has_root():
        sys.exit('[!] 需要在线的 root 设备')

    apk = os.path.abspath(util.pick_apk(args.apks_dir, args.apk))
    args.out = os.path.abspath(args.out)              # 后面多处用绝对路径,统一
    os.makedirs(args.out, exist_ok=True)
    import shutil
    for stale in ('signed', 'dex', 'dump_bin'):       # 清旧产物,避免 stale APK 假成功
        shutil.rmtree(os.path.join(args.out, stale), ignore_errors=True)
    pkg = util.get_pkg(apk)

    # ① 先确保设备上装的是「加壳版」(analyze 和 dump 都要扫它;上次 --install 可能已换成脱壳版)
    print('[*] 确保装的是加壳版 APK(供分析 + dump)')
    util.adb('uninstall', pkg)
    r = util.adb('install', '-r', apk)
    if 'Success' not in (r.stdout + r.stderr):
        sys.exit(f'[X] 装加壳版失败: {r.stdout}{r.stderr}')

    # ② 再 analyze(此时扫的才是加壳版;默认每次重新分析,避免复用扫空的坏配置)
    pkg, dump_js, cfg_json = run_analyze(apk, args.out, reuse=args.reuse_analysis)
    lib = suicide_lib_from_js(dump_js)
    print(f'[*] 目标 {pkg},壳 so={lib or "(无)"}')

    for attempt in (1, 2):
        print(f'\n=== dump 尝试 {attempt} ===')
        print('[*] 推配置/脚本到 ZygiskFrida')
        push_configs(cfg_json, dump_js)
        print('[*] 杀透 app')
        kill_app(pkg)
        util.su(f'rm -f {data_dir(pkg)}/zf_* 2>/dev/null')
        print('[*] 启动 app')
        util.adb('shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1')
        n = wait_for_dumps(pkg, args.timeout)
        if n:
            print(f'[✓] 抓到 {n} 个 dex 区')
            break
        print('[!] 没抓到;检查是否有未patch的壳守护进程...')
        if attempt == 1 and escalate_guardians(pkg, cfg_json, lib):
            continue
        sys.exit('[X] dump 为空。可能壳没自解密/被杀太快;手动看 '
                 f'adb shell su -c "cat {data_dir(pkg)}/zf_*txt"')

    # 拉取 + 重建
    print('\n[*] 拉取 DEX dump')
    raw_dir = os.path.join(args.out, 'dump_bin')
    bins = pull_dumps(pkg, raw_dir)
    print(f'    拉到 {len(bins)} 个有效 dex 区')
    if not bins:
        sys.exit('[X] 没拉到有效 dex 区')
    dex_dir = os.path.join(args.out, 'dex')
    os.makedirs(dex_dir, exist_ok=True)
    print('[*] 重建 DEX')
    bins_abs = [os.path.abspath(b) for b in bins]     # cwd=dex_dir,bin 必须绝对路径
    subprocess.run([sys.executable, os.path.join(HERE, 'rebuild_dex.py'), *bins_abs], cwd=dex_dir)
    n_dex = len(glob.glob(os.path.join(dex_dir, 'classes_main_*.dex')))
    print(f'    重建出 {n_dex} 个 classes_main_*.dex')
    if not n_dex:
        sys.exit('[X] DEX 重建失败')

    # 关闭注入恢复干净(默认)
    if not args.keep_inject:
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='_off', delete=False) as t:
            t.write('{ "targets": [] }'); off = t.name
        util.place_in_zyg(off, f'{ZYG}/config.json')
        os.unlink(off)
        print('[*] 已关闭注入(config.json → targets:[])')

    # 重打包
    print('\n[*] 去壳重打包 + 重签名')
    repack_cmd = [sys.executable, os.path.join(HERE, 'repack.py'),
                  '--apk', apk, '--dex-dir', dex_dir, '--auto', '--pkg', pkg, '-o', args.out]
    if subprocess.run(repack_cmd).returncode != 0:
        sys.exit('[X] 重打包失败')
    signed = glob.glob(os.path.join(args.out, 'signed', '*-debugSigned.apk'))
    if not signed:
        sys.exit('[X] 重打包没出 APK')
    apk_out = signed[0]
    print(f'\n[✓] 脱壳可装 APK: {os.path.abspath(apk_out)}')

    if args.install:
        print('\n[*] 装机验证')
        util.adb('uninstall', pkg)
        r = util.adb('install', '-r', apk_out)
        print('   ', (r.stdout + r.stderr).strip().splitlines()[-1] if (r.stdout + r.stderr).strip() else 'installed')
        util.adb('shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1')
        time.sleep(8)
        alive = analyze.running_app_procs(pkg)
        print(f'    启动后进程: {[n for n,_ in alive] or "无(可能崩溃,看 logcat)"}')


if __name__ == '__main__':
    main()
