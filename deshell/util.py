#!/usr/bin/env python3
"""util.py — 共享小工具:终端选 APK、从 APK 读包名、adb/root 封装。"""
import glob
import os
import re
import subprocess
import sys

HOME = os.path.expanduser('~')


def find_aapt():
    import shutil
    a = shutil.which('aapt') or shutil.which('aapt2')
    if a:
        return a
    cands = sorted(glob.glob(f'{HOME}/Android/Sdk/build-tools/*/aapt'), reverse=True)
    return cands[0] if cands else None


def get_pkg(apk):
    """用 aapt 从 APK 读包名;拿不到返回 None。"""
    aapt = find_aapt()
    if not aapt:
        return None
    try:
        out = subprocess.run([aapt, 'dump', 'badging', apk], capture_output=True, text=True).stdout
        m = re.search(r"package: name='([^']+)'", out)
        return m.group(1) if m else None
    except Exception:
        return None


def list_apks(apks_dir):
    return sorted(glob.glob(os.path.join(apks_dir, '*.apk')))


def pick_apk(apks_dir, given=None):
    """给了 --apk 就用它;否则列出 apks/ 目录让用户在终端选。"""
    if given:
        if not os.path.exists(given):
            sys.exit(f'[!] APK 不存在: {given}')
        return given
    apks = list_apks(apks_dir)
    if not apks:
        sys.exit(f'[!] {apks_dir}/ 下没有 .apk,放一个进去或用 --apk 指定')
    if len(apks) == 1:
        print(f'[*] 只有一个 APK,直接用: {os.path.basename(apks[0])}')
        return apks[0]
    print(f'\n{apks_dir}/ 下的 APK:')
    for i, p in enumerate(apks, 1):
        pkg = get_pkg(p) or '?'
        sz = os.path.getsize(p) / 1e6
        print(f'  [{i}] {os.path.basename(p):40s} {sz:7.1f} MB  {pkg}')
    while True:
        s = input(f'选择 [1-{len(apks)}] (回车=1): ').strip() or '1'
        if s.isdigit() and 1 <= int(s) <= len(apks):
            return apks[int(s) - 1]
        print('  无效,重选')


# ---------- adb / root 封装 ----------

def adb(*args, **kw):
    return subprocess.run(['adb', *args], capture_output=True, text=True, **kw)


def su(cmd):
    """adb shell su -c '<cmd>',返回 stdout 文本。"""
    return subprocess.run(['adb', 'shell', 'su', '-c', cmd], capture_output=True, text=True).stdout


def device_online():
    return subprocess.run(['adb', 'get-state'], capture_output=True, text=True).stdout.strip() == 'device'


def has_root():
    return su('id').strip().startswith('uid=0')


def pidof(pkg):
    p = su(f'pidof {pkg}').strip().split()
    return int(p[0]) if p else None


def place_in_zyg(local_path, remote_path):
    """把本机文件放到 system_file 标签目录(如 re.zyg.fri)里。

    ksu root 能覆盖已存在文件、但不能 create 新文件。所以:已存在→cp 覆盖;
    不存在→硬链接同目录一个已存在文件出目标名(继承 system_file 标签,绕过 create 限制)再 cp 覆盖。
    返回 (是否成功, cp 的输出)。
    """
    import posixpath
    rdir = posixpath.dirname(remote_path)
    base = posixpath.basename(remote_path)
    tmp = f'/data/local/tmp/.push_{base}'
    adb('push', local_path, tmp)
    exists = 'No such' not in su(f'ls {remote_path} 2>&1')
    if not exists:
        donor = next((d for d in su(f'ls {rdir} 2>/dev/null').split() if d), None)
        if donor:
            su(f'ln {rdir}/{donor} {remote_path} 2>/dev/null')
    out = su(f'cp {tmp} {remote_path} 2>&1')
    su(f'rm -f {tmp}')
    ok = ('No such' not in su(f'ls {remote_path} 2>&1')) and ('denied' not in out.lower())
    return ok, out
