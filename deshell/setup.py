#!/usr/bin/env python3
"""setup.py — 有 root 就自动把 dump 环境装好(doctor 报红的项,这里自动修)。

做的事(按需,已装的跳过):
  1) 自动对齐 frida-gadget 版本:读本机 frida client 版本 + 设备 abi →
     从 frida 官方 release 下载 frida-gadget-<ver>-android-<arch>.so.xz,解压,放到
     /data/local/tmp/re.zyg.fri/libgadget.so。
  2) 没装 ZygiskFrida 模块就从 github 下载最新 release.zip,用 root 管理器安装(KernelSU/Magisk/APatch),
     提示重启(模块要重启后才生效,且重启后才会建好 re.zyg.fri 工作目录)。
  3) 铺好 gadget 的 script 模式配置(libgadget.config.so)+ config.json 占位
     (真正的 dump 配置由 analyze.py 生成后覆盖进来)。

放外部文件的坑:re.zyg.fri 是 system_file 标签,ksu root 能覆盖已存在文件、但不能 create 新文件。
本脚本用「硬链接同目录已存在文件 → 再 cp 覆盖」绕过(link 权限 ksu 有)。

用法:  python3 deshell/setup.py            # 自动装缺的
       python3 deshell/setup.py --force    # 强制重下 gadget
"""
import argparse
import lzma
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util  # noqa: E402

ZYG_DIR = '/data/local/tmp/re.zyg.fri'
GADGET = ZYG_DIR + '/libgadget.so'
CACHE = os.path.expanduser('~/.cache/deshell')
ABI2ARCH = {'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'x86_64': 'x86_64', 'x86': 'x86'}


def host_frida_version():
    for py in (sys.executable, os.path.expanduser('~/android_root_tools/frida/.venv/bin/python')):
        try:
            v = subprocess.run([py, '-c', 'import frida;print(frida.__version__)'],
                               capture_output=True, text=True).stdout.strip()
            if v and v[0].isdigit():
                return v
        except Exception:
            pass
    import shutil
    if shutil.which('frida'):
        return subprocess.run(['frida', '--version'], capture_output=True, text=True).stdout.strip()
    return None


def download(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print(f'  下载 {url}')
    req = urllib.request.Request(url, headers={'User-Agent': 'deshell-setup'})
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, 'wb') as f:
        f.write(r.read())
    print(f'  → {dest} ({os.path.getsize(dest)} bytes)')
    return dest


def root_manager():
    for name, probe in [('ksu', 'command -v ksud'), ('magisk', 'command -v magisk'), ('apatch', 'command -v apd')]:
        if util.su(probe).strip():
            return name
    return None


def place_in_zyg(local_path, remote_path):
    """把本机文件放到 system_file 标签的 re.zyg.fri 里(覆盖已存在 / 否则硬链接后覆盖)。"""
    base = os.path.basename(remote_path)
    tmp = f'/data/local/tmp/.push_{base}'
    util.adb('push', local_path, tmp)
    exists = 'No such' not in util.su(f'ls {remote_path} 2>&1')
    if not exists:
        # 找同目录一个已存在文件,硬链接出目标名(继承 system_file 标签,绕过 create 限制)
        donor = util.su(f'ls {ZYG_DIR} 2>/dev/null').split()
        donor = next((d for d in donor if d), None)
        if donor:
            util.su(f'ln {ZYG_DIR}/{donor} {remote_path} 2>/dev/null')
    out = util.su(f'cp {tmp} {remote_path} 2>&1')
    util.su(f'rm -f {tmp}')
    ok = 'No such' not in util.su(f'ls {remote_path} 2>&1') and 'denied' not in out.lower()
    return ok, out


def ensure_gadget(frida_ver, arch, force):
    # 已有且版本一致就跳过
    if not force and 'No such' not in util.su(f'ls {GADGET} 2>&1'):
        cur = util.su(f"strings {GADGET} 2>/dev/null | grep -m1 -oE '\"version\":\"[0-9.]+\"'")
        if frida_ver in cur:
            print(f'[=] gadget 已是 {frida_ver},跳过')
            return True
    url = f'https://github.com/frida/frida/releases/download/{frida_ver}/frida-gadget-{frida_ver}-android-{arch}.so.xz'
    xz = os.path.join(CACHE, f'gadget-{frida_ver}-{arch}.so.xz')
    so = xz[:-3]
    try:
        if not os.path.exists(so):
            download(url, xz)
            with lzma.open(xz) as z, open(so, 'wb') as f:
                f.write(z.read())
    except Exception as e:
        print(f'[X] 下载/解压 gadget 失败: {e}')
        return False
    if 'No such' in util.su(f'ls {ZYG_DIR} 2>&1'):
        print(f'[X] {ZYG_DIR} 不存在(ZygiskFrida 还没装好/没重启);先装模块并重启再跑本脚本')
        return False
    ok, out = place_in_zyg(so, GADGET)
    print(f'[{"✓" if ok else "X"}] gadget 放置 {GADGET}' + ('' if ok else f'  ({out.strip()})'))
    return ok


def ensure_zygiskfrida(mgr):
    if 'zygiskfrida' in util.su('ls /data/adb/modules 2>/dev/null'):
        print('[=] ZygiskFrida 模块已安装,跳过')
        return True, False
    print('[*] 未装 ZygiskFrida,下载最新 release...')
    import json
    try:
        with urllib.request.urlopen(urllib.request.Request(
                'https://api.github.com/repos/lico-n/ZygiskFrida/releases/latest',
                headers={'User-Agent': 'deshell-setup'}), timeout=30) as r:
            rel = json.load(r)
        asset = next(a for a in rel['assets']
                     if a['name'].endswith('-release.zip') and 'riru' not in a['name'])
    except Exception as e:
        print(f'[X] 查询 ZygiskFrida release 失败: {e}')
        return False, False
    zip_local = os.path.join(CACHE, asset['name'])
    try:
        download(asset['browser_download_url'], zip_local)
    except Exception as e:
        print(f'[X] 下载模块失败: {e}')
        return False, False
    util.adb('push', zip_local, '/data/local/tmp/zf.zip')
    cmd = {'ksu': 'ksud module install /data/local/tmp/zf.zip',
           'magisk': 'magisk --install-module /data/local/tmp/zf.zip',
           'apatch': 'apd module install /data/local/tmp/zf.zip'}[mgr]
    out = util.su(cmd)
    print('   ' + out.strip()[-200:])
    ok = 'success' in out.lower() or 'installed' in out.lower()
    return ok, True


def scaffold_configs():
    """script 模式的 gadget 配置 + config.json 占位(真正的由 analyze.py 覆盖)。"""
    cfg_gadget = '{ "interaction": { "type": "script", "path": "%s/config.json.example", "on_change": "ignore" } }' % ZYG_DIR
    import tempfile
    results = []
    for name, content in [('libgadget.config.so', cfg_gadget),
                          ('config.json', '{ "targets": [] }'),
                          ('config.json.example', '// 由 analyze.py 生成的 dump 脚本覆盖此文件\n')]:
        with tempfile.NamedTemporaryFile('w', suffix='_' + name, delete=False) as t:
            t.write(content)
            local = t.name
        # 已存在才覆盖;不存在也尝试(place_in_zyg 会硬链接)
        ok, _ = place_in_zyg(local, f'{ZYG_DIR}/{name}')
        os.unlink(local)
        results.append((name, ok))
    for name, ok in results:
        print(f'   [{"✓" if ok else "!"}] {name}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--force', action='store_true', help='强制重下 gadget')
    ap.add_argument('--frida-version', help='指定 gadget 版本(默认跟随本机 frida client)')
    args = ap.parse_args()

    if not util.device_online():
        sys.exit('[X] 没有在线设备')
    if not util.has_root():
        sys.exit('[X] 需要 root(KernelSU/Magisk/APatch)')
    mgr = root_manager()
    abi = util.adb('shell', 'getprop', 'ro.product.cpu.abi').stdout.strip()
    arch = ABI2ARCH.get(abi, 'arm64')
    fver = args.frida_version or host_frida_version()
    print(f'[*] root={mgr}  abi={abi}({arch})  frida={fver}')
    if not fver:
        sys.exit('[X] 读不到本机 frida 版本,用 --frida-version 指定')
    if not mgr:
        sys.exit('[X] 认不出 root 管理器(ksud/magisk/apd)')

    print('\n=== ① ZygiskFrida 模块 ===')
    zf_ok, just_installed = ensure_zygiskfrida(mgr)
    if just_installed:
        print('\n[!] 模块刚装上,需要重启生效:  adb reboot')
        print('    重启后再跑一次 `python3 deshell/setup.py` 放 gadget + 配置。')
        return

    print('\n=== ② frida-gadget(对齐版本)===')
    g_ok = ensure_gadget(fver, arch, args.force)

    print('\n=== ③ gadget 配置脚手架 ===')
    scaffold_configs()

    print('\n完成。接下来:`.venv/bin/python deshell/analyze.py` 自动出 dump 配置。' if (zf_ok and g_ok)
          else '\n有未完成项(上面 [X]),按提示处理。')


if __name__ == '__main__':
    main()
