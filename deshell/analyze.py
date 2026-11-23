#!/usr/bin/env python3
"""analyze.py — 用 root + capstone 自动分析加壳 app,产出填好的 dump 脚本(不用手改 CFG)。

做的事:
  1) 在 apks/ 里选一个 APK(终端交互),用 aapt 读包名。
  2) 确保这个(加壳的)APK 装上并跑起来(壳 so 运行时才自解密,root 读内存不触发检测)。
  3) 读 /proc/<pid>/maps,找出 app 私有的 .so 的 r-x 段,逐个从 /proc/<pid>/mem dump 出来。
  4) capstone 反汇编,扫 inline-svc 自杀点:svc 前把 x8 设成 exit_group(94)/exit(93)/kill(129)。
  5) 含「exit_group + kill」inline-svc 的那个 so = 自杀壳 so;其偏移 = 自杀点。
  6) 把 PKG / SUICIDE_LIB / SUICIDE_OFFS 填进 dump_full.js 模板,生成 out/dump_<pkg>.js。

必须用带 capstone 的解释器跑(本机:/home/youyou/android_root_tools/frida/.venv/bin/python)。
用法:  .venv/bin/python deshell/analyze.py [--apk 路径] [--apks-dir apks] [-o out] [--no-install]
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import util  # noqa: E402

# syscall 号(arm64):自杀相关
SYS = {93: 'exit', 94: 'exit_group', 129: 'kill', 130: 'tgkill'}


def ensure_running(apk, pkg, do_install):
    """确保加壳 APK 装上并在跑;返回主进程 pid。"""
    if not util.device_online():
        sys.exit('[!] 没有在线设备(adb get-state)')
    if not util.has_root():
        sys.exit('[!] 需要 root(adb shell su)')

    installed = util.adb('shell', 'pm', 'path', pkg).stdout.strip()
    if do_install:
        # 装这个加壳 APK(签名可能和当前不同,先卸)
        print(f'[*] 安装加壳 APK 以供分析: {os.path.basename(apk)}')
        util.adb('uninstall', pkg)
        r = util.adb('install', '-r', apk)
        if 'Success' not in (r.stdout + r.stderr):
            sys.exit(f'[!] 安装失败: {r.stdout}{r.stderr}')
    elif not installed:
        sys.exit(f'[!] {pkg} 未安装,去掉 --no-install 让我装,或先手动装')

    util.su(f'am force-stop {pkg}')
    import time
    time.sleep(1)
    util.adb('shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1')
    # 等到 app 真正起来、且 native 库 r-x 映射进内存(壳 so 此时才会自解密完)
    pid = None
    for _ in range(25):
        time.sleep(1)
        pid = util.pidof(pkg)
        if not pid:
            continue
        maps = util.su(f'cat /proc/{pid}/maps 2>/dev/null')
        if re.search(r'r-xp\s+\S+\s+\S+\s+\S+\s+/data/(app|data)/\S+\.so', maps):
            break
    else:
        sys.exit('[!] app 没起来或没加载 native 库(可能被壳秒退,或装的是脱壳版);检查设备')
    time.sleep(5)   # 再给壳 so 自解密 + 其余库加载一点时间
    return util.pidof(pkg) or pid


def running_app_procs(pkg):
    """返回当前在跑的 app 进程 [(name, pid), ...](主进程 + <pkg>:xxx 子进程)。"""
    out = util.su('ps -A -o PID,NAME')
    procs = []
    for ln in out.splitlines():
        parts = ln.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid, name = int(parts[0]), parts[1].strip()
        if name == pkg or name.startswith(pkg + ':'):
            procs.append((name, pid))
    procs.sort(key=lambda t: (t[0] != pkg, t[0]))
    return procs


def proc_has_lib(pid, lib):
    """该进程的 maps 里是否加载了 lib(判定它是否也会执行壳自杀逻辑)。"""
    if not lib:
        return False
    return lib in util.su(f'cat /proc/{pid}/maps 2>/dev/null')


def declared_processes(apk, pkg):
    """从 manifest 读所有声明的 android:process(静态、不依赖运行时),返回完整进程名集合。"""
    aapt = util.find_aapt()
    if not aapt:
        return []
    out = subprocess.run([aapt, 'dump', 'xmltree', apk, 'AndroidManifest.xml'],
                         capture_output=True, text=True).stdout
    names = set()
    for m in re.finditer(r'android:process\([^)]*\)="([^"]+)"', out):
        v = m.group(1)
        names.add(v if not v.startswith(':') else pkg + v)
    return sorted(names)


ZYG_DIR = '/data/local/tmp/re.zyg.fri'                    # ZygiskFrida 工作目录
GADGET_PATH = ZYG_DIR + '/libgadget.so'                   # ZygiskFrida 注入的 gadget


def emit_zygiskfrida_config(path, procs):
    """生成 ZygiskFrida 的 config.json:主进程 + 每个守护进程都注入(都跑 dump 脚本)。"""
    import json
    targets = []
    for i, name in enumerate(procs):
        targets.append({
            'app_name': name,
            'enabled': True,
            'start_up_delay_ms': 3000 if name.count(':') == 0 else 500,
            'injected_libraries': [{'path': GADGET_PATH}],
        })
    open(path, 'w', encoding='utf-8').write(json.dumps({'targets': targets}, indent=2, ensure_ascii=False))


def app_so_rx_segments(pid):
    """返回 {so路径: {'base': 模块基址, 'rx': [(start,end), ...]}},只要 app 私有的 .so。"""
    maps = util.su(f'cat /proc/{pid}/maps')
    mods = {}
    for ln in maps.splitlines():
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s+(/\S+\.so)$', ln)
        if not m:
            continue
        start, end, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        # 只分析 app 私有 so(/data/app 或 /data/data),跳过 system/apex/vendor
        if not (path.startswith('/data/app') or path.startswith('/data/data')):
            continue
        d = mods.setdefault(path, {'base': start, 'rx': []})
        d['base'] = min(d['base'], start)
        if 'r' in perms and 'x' in perms:
            d['rx'].append((start, end))
    return mods


def dump_mem(pid, start, end):
    """root 从 /proc/<pid>/mem dump [start,end)(页对齐),返回 bytes。"""
    bs = 4096
    skip, count = start // bs, (end - start) // bs
    r = subprocess.run(['adb', 'exec-out', 'su', '-c',
                        f'dd if=/proc/{pid}/mem bs={bs} skip={skip} count={count} 2>/dev/null'],
                       capture_output=True)
    return r.stdout


def scan_suicide(code, seg_start, base):
    """扫 inline-svc 自杀点:svc 前把 x8/w8 设成自杀 syscall 号。返回 [(off, sysno), ...]

    aarch64 定长 4 字节:先按 4 字节边界 raw 搜 `svc #0`(0xd4000001,小端 01 00 00 d4),
    再对每个 svc 前面几条做 capstone 反汇编取 x8/w8 立即数。比线性反汇编鲁棒
    (段里混有数据时线性 disasm 会在数据处停住,到不了后面的代码)。
    """
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    SVC0 = b'\x01\x00\x00\xd4'
    hits, i = [], 0
    while True:
        p = code.find(SVC0, i)
        if p < 0:
            break
        i = p + 4
        if p % 4:
            continue
        # 反汇编 svc 前最多 3 条,找把 x8/w8 置成 syscall 号的那条
        win = max(0, p - 12)
        x8 = None
        for insn in md.disasm(code[win:p + 4], win):
            mn, ops = insn.mnemonic, insn.op_str
            if mn in ('mov', 'movz', 'orr') and (ops.startswith('x8,') or ops.startswith('w8,')):
                mm = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ops)
                x8 = int(mm.group(1), 0) if mm else None
            elif mn == 'svc' and x8 in SYS:
                hits.append((seg_start + p - base, x8))     # off = 内存地址 - 模块基址
    return hits


def fill_template(tpl_path, out_path, pkg, lib, offs):
    src = open(tpl_path, encoding='utf-8').read()
    offs_js = '[' + ', '.join(hex(o) for o in offs) + ']'
    # 替换 CFG 里的三行值(其余保持默认)
    src = re.sub(r"(PKG:\s*)'[^']*'", lambda m: m.group(1) + f"'{pkg}'", src, count=1)
    src = re.sub(r"(SUICIDE_LIB:\s*)'[^']*'", lambda m: m.group(1) + f"'{lib or ''}'", src, count=1)
    src = re.sub(r"(SUICIDE_OFFS:\s*)\[[^\]]*\]", lambda m: m.group(1) + offs_js, src, count=1)
    open(out_path, 'w', encoding='utf-8').write(src)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', help='直接指定加壳 APK(默认在 --apks-dir 里交互选)')
    ap.add_argument('--apks-dir', default='apks', help='APK 目录(默认 apks/)')
    ap.add_argument('-o', '--out', default='out', help='输出目录')
    ap.add_argument('--no-install', action='store_true', help='不要重装,用当前已装的')
    args = ap.parse_args()

    try:
        import capstone  # noqa: F401
    except ImportError:
        sys.exit('[!] 需要 capstone:用带它的解释器跑,如\n'
                 '    /home/youyou/android_root_tools/frida/.venv/bin/python deshell/analyze.py ...')

    if not util.find_aapt():
        sys.exit('[!] 找不到 aapt(读包名用):装 Android build-tools,或 export PATH 指到 aapt')
    apk = util.pick_apk(args.apks_dir, args.apk)
    pkg = util.get_pkg(apk)
    if not pkg:
        sys.exit('[!] aapt 读不到包名(APK 损坏?)')
    print(f'[*] 目标: {pkg}  ({os.path.basename(apk)})')

    pid = ensure_running(apk, pkg, do_install=not args.no_install)
    print(f'[*] 主进程 pid={pid},开始 dump + 扫描壳 so...')

    import time
    results = {}  # lib路径 -> {sysno: [off,...]}
    # 壳 so 自解密有时稍慢;首轮扫到 0 个自杀点就多等再扫,最多 4 轮
    for rnd in range(4):
        cur = util.pidof(pkg) or pid     # 进程可能重启,取最新 pid
        mods = app_so_rx_segments(cur)
        results = {}
        for path, d in mods.items():
            found = {}
            for (s, e) in d['rx']:
                code = dump_mem(cur, s, e)
                if not code:
                    continue
                for off, sysno in scan_suicide(code, s, d['base']):
                    found.setdefault(sysno, []).append(off)
            if found:
                results[path] = found
        if results or not mods:
            pid = cur
            break
        print(f'    第 {rnd+1} 轮没扫到自杀点,等 3s 再扫(壳 so 可能还没自解密)...')
        time.sleep(3)
    for path, found in results.items():
        tags = ', '.join(f'{SYS[k]}@' + '/'.join(hex(x) for x in v) for k, v in sorted(found.items()))
        print(f'    {os.path.basename(path)}: {tags}')
    if not app_so_rx_segments(util.pidof(pkg) or pid):
        sys.exit('[!] 没找到 app 私有 .so;进程可能已退,或装的是脱壳版/没有 native 壳')

    # 选自杀壳 so:优先同时含 exit_group(94) 和 kill(129);否则含 kill 的;否则含 exit*
    def rank(item):
        sysnos = set(item[1])
        return (94 in sysnos and 129 in sysnos, 129 in sysnos, 94 in sysnos, len(item[1]))
    cand = sorted(results.items(), key=rank, reverse=True)

    print('\n' + '=' * 60)
    if not cand:
        print('[!] 没扫到任何 inline-svc 自杀点。可能:壳 so 未自解密 / 该壳不用 inline-svc 自杀 /')
        print('    进程已被杀。可重试,或手动在 dump_full.js 的 CFG 里填 SUICIDE_LIB/OFFS。')
        lib, offs = '', []
    else:
        best, found = cand[0]
        lib = os.path.basename(best)
        offs = sorted({o for v in found.values() for o in v})
        print(f'[✓] 自杀壳 so: {lib}')
        for sysno, ol in sorted(found.items()):
            print(f'      {SYS[sysno]}(x8={sysno}) @ ' + ', '.join(hex(o) for o in ol))
        print(f'    SUICIDE_OFFS = [{", ".join(hex(o) for o in offs)}]')

    # 识别注入目标:凡加载了自杀壳 so 的进程都要注入+patch(守护进程才 kill 不了主进程)
    running = running_app_procs(pkg)
    targets = []
    print('\n[*] 当前在跑的 app 进程:')
    for name, ppid in running:
        hit = proc_has_lib(ppid, lib) if lib else (name == pkg)
        tag = '← 加载了 %s,注入' % lib if (lib and hit) else ('← 主进程,注入' if name == pkg else '← 不加载壳 so,跳过')
        if name == pkg or hit:
            targets.append(name)
        print(f'      {name:45s} pid={ppid}  {tag}')

    # manifest 声明但此刻没起的进程(如 :mind 常在用户同意隐私后才启动)
    declared = declared_processes(apk, pkg)
    later = [n for n in declared if n not in {t for t in targets} and n not in {r[0] for r in running}]
    if later:
        print('\n[!] manifest 还声明了这些进程(此刻未运行,可能稍后才起):')
        print('      ' + ', '.join(n.replace(pkg, '') or pkg for n in later[:20]) + (' …' if len(later) > 20 else ''))
        print(f'    若启动后主进程被 signal 9 杀,说明某守护进程(多为 :mind/:channel 类)也加载了 {lib or "壳 so"},')
        print('    把它的全名加进生成的 config.json 的 targets 即可(判据:它的 /proc/<pid>/maps 里有该 so)。')

    os.makedirs(args.out, exist_ok=True)
    out_js = os.path.join(args.out, f'dump_{pkg}.js')
    out_cfg = os.path.join(args.out, f'config_{pkg}.json')
    fill_template(os.path.join(here, 'dump_full.js'), out_js, pkg, lib, offs)
    emit_zygiskfrida_config(out_cfg, targets)

    print(f'\n[✓] dump 脚本(CFG 已填):     {os.path.abspath(out_js)}')
    print(f'[✓] ZygiskFrida 配置(多 target):{os.path.abspath(out_cfg)}')
    print('\n下一步:')
    print(f'    1) 把 {os.path.basename(out_cfg)} 覆盖到设备 /data/local/tmp/re.zyg.fri/config.json')
    print(f'    2) 把 {os.path.basename(out_js)} 覆盖到 .../re.zyg.fri/config.json.example(gadget script)')
    print('    3) 确认 .../re.zyg.fri/libgadget.so 是对齐版本的 gadget;杀透 app 重启')
    print(f'    4) 等十几秒,拉 DEX:for n in $(seq 1 20); do adb shell su -c "cat /data/data/{pkg}/zf_mdex_$n.bin" > zf_mdex_$n.bin; done')
    print('    5) python3 deshell/rebuild_dex.py zf_mdex_*.bin  →  python3 deshell/repack.py --dex-dir . --auto')


if __name__ == '__main__':
    main()
