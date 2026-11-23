#!/usr/bin/env python3
"""unpackers/fart.py — FART 式「内存 dump 型 DEX 壳」脱壳插件(易盾/papa 那套)。

适用:加载时整体解密、靠 inline-svc 自杀 / 守护进程跨进程 kill 做反 frida 的 DEX 壳。
思路:ZygiskFrida 注入 gadget 跑 dump_full.js(反自杀 + 扫 rw-anon 区 dump 全部已解密 dex)
     → 轮询拉取 → rebuild_dex 补 magic/校验 → repack.py(apktool)换真 Application 重签名。

这是「通用兜底」插件:对识别不出更具体壳型的 APK 都用它试。
"""
from __future__ import annotations
import glob
import json
import os
import re
import subprocess
import sys
import time

from .base import Unpacker, Context, register
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import util      # noqa: E402
import analyze   # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZYG = analyze.ZYG_DIR


# ---------------- FART 流程小工具(原 deploy.py 内) ----------------
def data_dir(pkg):
    return f'/data/data/{pkg}'


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
    """推 ZygiskFrida config.json + dump 脚本 + script 模式 gadget 配置(SELinux 安全)。"""
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


def wait_for_dumps(pkg, timeout):
    last, stable, t0 = -1, 0, time.time()
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
        lp = os.path.join(dst, os.path.basename(rp))
        data = subprocess.run(['adb', 'exec-out', 'su', '-c', f'cat {rp}'], capture_output=True).stdout
        if data[:4] == b'\x30\x33\x35\x00':
            open(lp, 'wb').write(data); got.append(lp)
    return got


def suicide_lib_from_js(dump_js):
    m = re.search(r"SUICIDE_LIB:\s*'([^']*)'", open(dump_js, encoding='utf-8').read())
    return m.group(1) if m else ''


def escalate_guardians(pkg, cfg_json, lib):
    cfg = json.load(open(cfg_json, encoding='utf-8'))
    have = {t['app_name'] for t in cfg['targets']}
    added = [name for name, pid in analyze.running_app_procs(pkg)
             if name not in have and analyze.proc_has_lib(pid, lib)]
    for name in added:
        cfg['targets'].append({'app_name': name, 'enabled': True, 'start_up_delay_ms': 500,
                               'injected_libraries': [{'path': analyze.GADGET_PATH}]})
    if added:
        json.dump(cfg, open(cfg_json, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
        print(f'    发现未patch的壳进程,补入 config: {added}')
    return bool(added)


def run_analyze(apk, out, reuse):
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
        raise RuntimeError('analyze 失败,单独跑 analyze.py 排查')
    return pkg, dump_js, cfg_json


# ---------------- 插件 ----------------
@register
class FartUnpacker(Unpacker):
    name = 'fart'
    desc = '内存 dump 型 DEX 壳(易盾/papa 系):frida 注入扫内存 dex,apktool 重打包。通用兜底'

    def detect(self, ctx: Context) -> int:
        # 兜底:给低基线分,识别不出更具体壳型时就用它。
        return 5

    def unpack(self, ctx: Context) -> dict:
        import shutil
        for stale in ('signed', 'dex', 'dump_bin'):
            shutil.rmtree(os.path.join(ctx.out, stale), ignore_errors=True)
        pkg, dump_js, cfg_json = run_analyze(ctx.apk, ctx.out, ctx.reuse_analysis)
        lib = suicide_lib_from_js(dump_js)
        ctx.log(f'[*] 目标 {pkg},壳 so={lib or "(无)"}')
        ctx.meta['inject_on'] = True       # 通知 deploy:本插件会开启注入,结束要关
        for attempt in (1, 2):
            ctx.log(f'\n=== dump 尝试 {attempt} ===')
            ctx.log('[*] 推配置/脚本到 ZygiskFrida'); push_configs(cfg_json, dump_js)
            ctx.log('[*] 杀透 app'); kill_app(pkg)
            util.su(f'rm -f {data_dir(pkg)}/zf_* 2>/dev/null')
            ctx.log(f'[*] 启动 app: {util.launch_app(pkg)}')
            if wait_for_dumps(pkg, ctx.timeout):
                break
            ctx.log('[!] 没抓到;找未patch的壳守护进程...')
            if attempt == 1 and escalate_guardians(pkg, cfg_json, lib):
                continue
            raise RuntimeError(f'dump 为空;手动看 adb shell su -c "cat {data_dir(pkg)}/zf_*txt"')
        raw_dir = os.path.join(ctx.out, 'dump_bin')
        bins = pull_dumps(pkg, raw_dir)
        ctx.log(f'[*] 拉到 {len(bins)} 个有效 dex 区')
        if not bins:
            raise RuntimeError('没拉到有效 dex 区')
        dex_dir = os.path.join(ctx.out, 'dex')
        os.makedirs(dex_dir, exist_ok=True)
        subprocess.run([sys.executable, os.path.join(HERE, 'rebuild_dex.py'),
                        *[os.path.abspath(b) for b in bins]], cwd=dex_dir)
        n = len(glob.glob(os.path.join(dex_dir, 'classes_main_*.dex')))
        ctx.log(f'[*] 重建出 {n} 个 classes_main_*.dex')
        if not n:
            raise RuntimeError('DEX 重建失败')
        return {'dex_dir': dex_dir, 'pkg': pkg}

    def repack(self, ctx: Context, art: dict) -> str:
        ctx.log('\n[*] 去壳重打包 + 重签名(repack.py / apktool)')
        r = subprocess.run([sys.executable, os.path.join(HERE, 'repack.py'),
                            '--apk', ctx.apk, '--dex-dir', art['dex_dir'],
                            '--auto', '--pkg', ctx.pkg, '-o', ctx.out])
        if r.returncode != 0:
            raise RuntimeError('重打包失败')
        signed = glob.glob(os.path.join(ctx.out, 'signed', '*-debugSigned.apk'))
        if not signed:
            raise RuntimeError('重打包没出 APK')
        ctx.log(f'[✓] 签名 APK: {signed[0]}')
        return signed[0]
