#!/usr/bin/env python3
"""doctor.py — 环境自检:把 deshell 全流程需要的工具/设备/依赖一次性查齐,缺啥报啥。

用法:  python3 deshell/doctor.py
       (想连 capstone 一起查,用带它的解释器跑,如 frida/.venv/bin/python)
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util  # noqa: E402

OK, WARN, BAD = '\033[32m[OK]\033[0m', '\033[33m[!]\033[0m', '\033[31m[X]\033[0m'


def check(name, ok, detail='', fatal=True):
    mark = OK if ok else (BAD if fatal else WARN)
    print(f'  {mark} {name:28s} {detail}')
    return ok


def have(cmd):
    return shutil.which(cmd) is not None


def jar(path):
    return os.path.exists(os.path.expanduser(path))


def main():
    print('\n=== 电脑端工具(重打包必需) ===')
    ok = True
    ok &= check('python3', True, sys.version.split()[0])
    ok &= check('java', have('java'),
                subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.splitlines()[0]
                if have('java') else '缺:apt install default-jre')
    apktool = os.environ.get('APKTOOL_JAR', '~/.apklab/apktool_3.0.3.jar')
    signer = os.environ.get('SIGNER_JAR', '~/.apklab/uber-apk-signer-1.3.0.jar')
    ok &= check('apktool.jar', jar(apktool), apktool)
    ok &= check('uber-apk-signer.jar', jar(signer), signer)
    ok &= check('zip / unzip', have('zip') and have('unzip'))
    check('aapt', util.find_aapt() is not None, util.find_aapt() or '缺:Android build-tools(读包名用)', fatal=False)

    print('\n=== dump 阶段工具(自己抓 DEX 才需要) ===')
    check('adb', have('adb'), fatal=False)
    try:
        import capstone
        check('capstone (python)', True, capstone.__version__, fatal=False)
    except ImportError:
        check('capstone (python)', False, '缺:pip install capstone(analyze.py 要);或用 frida/.venv 跑', fatal=False)
    try:
        import frida
        check('frida (python)', True, frida.__version__, fatal=False)
    except ImportError:
        check('frida (python)', False, '缺:pip install frida(版本要和手机 gadget 对齐)', fatal=False)
    check('dexdump / jadx', have('dexdump') or os.path.exists(os.path.expanduser('~/.apklab/jadx-1.5.6/bin/jadx')),
          '核对 dex 用(可选)', fatal=False)

    print('\n=== 设备(dump 阶段) ===')
    if have('adb'):
        online = util.device_online()
        check('设备在线', online, subprocess.run(['adb', 'get-state'], capture_output=True, text=True).stdout.strip(), fatal=False)
        if online:
            rooted = util.has_root()
            check('root (su)', rooted, util.su('id').strip()[:40] if rooted else '需要 KernelSU/Magisk/APatch', fatal=False)
            if rooted:
                zyg = util.su('ls /data/adb/modules 2>/dev/null')
                has_zf = 'zygiskfrida' in zyg
                check('ZygiskFrida 模块', has_zf,
                      'github.com/lico-n/ZygiskFrida' if not has_zf else '', fatal=False)
                gpath = '/data/local/tmp/re.zyg.fri/libgadget.so'
                has_g = 'No such' not in util.su(f'ls {gpath} 2>&1')
                check('gadget .so 就位', has_g, gpath, fatal=False)
    else:
        check('设备在线', False, 'adb 缺', fatal=False)

    print()
    if ok:
        print(f'{OK} 重打包必需项齐全。dump 阶段按上面的 [!] 补齐即可。')
    else:
        print(f'{BAD} 有重打包必需项缺失(上面 [X]),先补齐再跑 repack.py。')
        sys.exit(1)


if __name__ == '__main__':
    main()
