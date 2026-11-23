#!/usr/bin/env python3
"""unpackers/cgakq.py — cgakq 系「磁盘缓存型 Flutter 壳」脱壳插件。

壳特征:
  - lib/ 只有一个壳桩 so(如 libcgakq.so),真 libflutter/libapp 等全加密;
  - AndroidManifest.xml 是合法 AXML 但被撑大(中部塞 ~50MB 非法 chunk)+ attributeSize=21(反工具);
  - 首启把整份解密产物落盘到 /data/data/<pkg>/app_<name>/:
        classes*.dex(真 dex) / assets.zip(真 assets) / <name>/*.so(真 so,含 libapp.so)
  - manifest 的 <application android:name> 指向壳桩 Application(只在壳 dex 里);
  - 真 dex 的 Flutter 引擎被改写,引用壳桩的若干方法(实测仅
    GnXbQhEeqKiiAOEjnPMgZDGwA(Context)->AssetManager,返回解密版 AssetManager)。

脱壳 = 启动让它落盘 → 拉取 → 清洗 manifest(去填充 + 把入口换回真 Application)
      → 生成壳桩「替身类」(把被引用的壳方法实现成原生直通,如 getAssets())
      → zip 手术重组 + 重签名。
"""
from __future__ import annotations
import glob
import os
import re
import struct
import subprocess
import sys
import time
import zipfile

from .base import Unpacker, Context, register
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import util  # noqa: E402

HOME = os.path.expanduser('~')
SIGNER = os.environ.get('SIGNER_JAR', f'{HOME}/.apklab/uber-apk-signer-1.3.0.jar')


# ============================ AXML 工具 ============================
def _axml_strings(raw: bytes):
    """返回 (strings, sp_size, flags)。只支持 UTF-16 无样式池(这类壳就是)。"""
    assert struct.unpack_from('<H', raw, 0)[0] == 0x0003, 'not AXML'
    sp = 8
    assert struct.unpack_from('<H', raw, sp)[0] == 0x0001
    sp_size = struct.unpack_from('<I', raw, sp + 4)[0]
    sc = struct.unpack_from('<I', raw, sp + 8)[0]
    flags = struct.unpack_from('<I', raw, sp + 16)[0]
    str_start = struct.unpack_from('<I', raw, sp + 20)[0]
    utf8 = bool(flags & 0x100)
    out = []
    for i in range(sc):
        p = sp + str_start + struct.unpack_from('<I', raw, sp + 28 + i * 4)[0]
        if utf8:
            n = raw[p]; p += 1
            if n & 0x80: n = ((n & 0x7f) << 8) | raw[p]; p += 1
            bl = raw[p]; p += 1
            if bl & 0x80: bl = ((bl & 0x7f) << 8) | raw[p]; p += 1
            out.append(raw[p:p + bl].decode('utf-8', 'replace'))
        else:
            n = struct.unpack_from('<H', raw, p)[0]; p += 2
            out.append(raw[p:p + n * 2].decode('utf-16-le', 'replace'))
    return out, sp_size, utf8


def _resmap(raw: bytes, sp_size: int):
    rm = 8 + sp_size
    if struct.unpack_from('<H', raw, rm)[0] != 0x0180:
        return []
    cnt = (struct.unpack_from('<I', raw, rm + 4)[0] - 8) // 4
    return [struct.unpack_from('<I', raw, rm + 8 + j * 4)[0] for j in range(cnt)]


def axml_application_name(raw: bytes):
    """读 <application android:name> 的字符串值(壳桩 Application 全名);没有返回 None。
    关键:attributeSize 从 attrExt 读(这类壳是 21,不是标准 20)。"""
    strings, sp_size, _ = _axml_strings(raw)
    resmap = _resmap(raw, sp_size)
    def S(i): return strings[i] if 0 <= i < len(strings) else None
    off = 8
    while off + 8 <= len(raw):
        t = struct.unpack_from('<H', raw, off)[0]
        cs = struct.unpack_from('<I', raw, off + 4)[0]
        if cs < 8 or off + cs > len(raw):
            break
        if t == 0x0102 and S(struct.unpack_from('<I', raw, off + 20)[0]) == 'application':
            aStart = struct.unpack_from('<H', raw, off + 24)[0]
            aSize = struct.unpack_from('<H', raw, off + 26)[0] or 20
            aCount = struct.unpack_from('<H', raw, off + 28)[0]
            for a in range(aCount):
                b = off + 16 + aStart + a * aSize
                ni = struct.unpack_from('<I', raw, b + 4)[0]
                rid = resmap[ni] if 0 <= ni < len(resmap) else 0
                vt = raw[b + 15]; data = struct.unpack_from('<I', raw, b + 16)[0]
                if rid == 0x01010003 and vt == 0x03:   # android:name, string
                    return S(data)
            return None
        off += cs
    return None


def strip_junk_chunks(raw: bytes) -> bytes:
    """删掉 AXML 中部的超大非法填充 chunk(type 不在合法集且 size>1MB),修正根 fileSize。"""
    valid = {0x0001, 0x0180, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104}
    off = 8
    while off + 8 <= len(raw):
        t = struct.unpack_from('<H', raw, off)[0]
        cs = struct.unpack_from('<I', raw, off + 4)[0]
        if cs < 8 or off + cs > len(raw):
            break
        if cs > 1_000_000 and t not in valid:
            new = bytearray(raw[:off] + raw[off + cs:])
            struct.pack_into('<I', new, 4, len(new))
            return bytes(new)
        off += cs
    return raw


def replace_pool_string(raw: bytes, old: str, new: str) -> bytes:
    """替换字符串池里某串(按内容),重建偏移表。UTF-16 无样式池。"""
    assert struct.unpack_from('<H', raw, 0)[0] == 0x0003
    sp = 8
    sp_size = struct.unpack_from('<I', raw, sp + 4)[0]
    count = struct.unpack_from('<I', raw, sp + 8)[0]
    flags = struct.unpack_from('<I', raw, sp + 16)[0]
    str_start = struct.unpack_from('<I', raw, sp + 20)[0]
    assert not (flags & 0x100), 'utf8 pool not supported'
    strings = []
    for i in range(count):
        p = sp + str_start + struct.unpack_from('<I', raw, sp + 28 + i * 4)[0]
        n = struct.unpack_from('<H', raw, p)[0]; p += 2
        strings.append(raw[p:p + n * 2].decode('utf-16-le'))
    if old not in strings:
        raise ValueError(f'字符串池无 {old!r}')
    strings[strings.index(old)] = new
    data = bytearray(); offs = []
    for s in strings:
        offs.append(len(data))
        data += struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\x00\x00'
    while len(data) % 4:
        data += b'\x00'
    body = bytearray()
    body += struct.pack('<HHI', 0x0001, 0x001c, 0)
    body += struct.pack('<IIII', count, 0, flags & ~0x1, 28 + count * 4)
    body += struct.pack('<I', 0)
    for o in offs:
        body += struct.pack('<I', o)
    body += data
    struct.pack_into('<I', body, 4, len(body))
    out = bytearray(raw[:8]) + body + raw[8 + sp_size:]
    struct.pack_into('<I', out, 4, len(out))
    return bytes(out)


# ============================ DEX 工具 ============================
def _dex_strings_types(path):
    d = open(path, 'rb').read()
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    sio, tio = u32(0x3c), u32(0x44)
    pis, pio = u32(0x48), u32(0x4c)
    mis, mio = u32(0x58), u32(0x5c)
    def s_at(i):
        o = u32(sio + i * 4); p = o
        while d[p] & 0x80: p += 1
        p += 1
        return d[p:d.index(b'\x00', p)].decode('utf-8', 'replace')
    def t_desc(ti):
        return s_at(u32(tio + ti * 4))
    return d, u32, s_at, t_desc, (pio), (mis, mio)


def dex_stub_method_refs(dex_paths, stub_desc: bytes):
    """返回 {(name, (param_descs...), ret_desc)} —— 真 dex 里引用的壳桩类方法全集。"""
    found = {}
    for path in dex_paths:
        d, u32, s_at, t_desc, pio, (mis, mio) = _dex_strings_types(path)
        tio = u32(0x44); tsz = u32(0x40)
        tgt = None
        for ti in range(tsz):
            if t_desc(ti).encode() == stub_desc:
                tgt = ti; break
        if tgt is None:
            continue
        def proto(pidx):
            base = pio + pidx * 12
            ret = t_desc(u32(base + 4))
            params_off = u32(base + 8)
            ps = []
            if params_off:
                n = u32(params_off)
                for k in range(n):
                    tidx = struct.unpack_from('<H', d, params_off + 4 + k * 2)[0]
                    ps.append(t_desc(tidx))
            return tuple(ps), ret
        for mi in range(mis):
            cidx = struct.unpack_from('<H', d, mio + mi * 8)[0]
            if cidx == tgt:
                pidx = struct.unpack_from('<H', d, mio + mi * 8 + 2)[0]
                nidx = u32(mio + mi * 8 + 4)
                ps, ret = proto(pidx)
                found[(s_at(nidx), ps, ret)] = found.get((s_at(nidx), ps, ret), 0) + 1
    return found


def _desc_to_java(desc: str) -> str:
    arr = 0
    while desc.startswith('['):
        arr += 1; desc = desc[1:]
    prim = {'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short', 'C': 'char',
            'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double'}
    if desc in prim:
        base = prim[desc]
    elif desc.startswith('L') and desc.endswith(';'):
        base = desc[1:-1].replace('/', '.')
    else:
        base = 'java.lang.Object'
    return base + '[]' * arr


def _default_return(ret_java: str) -> str:
    if ret_java == 'void':
        return ''
    if ret_java in ('boolean',):
        return 'return false;'
    if ret_java in ('byte', 'short', 'char', 'int', 'long', 'float', 'double'):
        return 'return 0;'
    return 'return null;'


# ============================ 插件 ============================
@register
class CgakqUnpacker(Unpacker):
    name = 'cgakq'
    desc = '磁盘缓存型 Flutter 壳(libcgakq 系):首启落盘 app_<name>/,拉取后重组'

    # ---------- 检测(静态,不启动) ----------
    def detect(self, ctx: Context) -> int:
        try:
            z = zipfile.ZipFile(ctx.apk)
            names = z.namelist()
            score = 0
            # 1) manifest 被撑大(junk 填充)
            mf = next((i for i in z.infolist() if i.filename == 'AndroidManifest.xml'), None)
            if mf and mf.file_size > 1_000_000:
                score += 50
            # 2) 是 Flutter 但 lib 里没有 libflutter/libapp(被加密)
            libs = [n for n in names if n.startswith('lib/') and n.endswith('.so')]
            libbases = {os.path.basename(n) for n in libs}
            is_flutter = any('io/flutter' in n or 'flutter_assets' in n for n in names) or \
                b'flutterEmbedding' in (z.read('AndroidManifest.xml')[:200000] if mf else b'')
            if is_flutter and 'libflutter.so' not in libbases and 'libapp.so' not in libbases:
                score += 40
            # 3) lib 里基本只有壳桩 so(极少)
            if 0 < len(libbases) <= 2 and 'libflutter.so' not in libbases:
                score += 10
            return min(score, 100)
        except Exception:
            return 0

    # ---------- 脱壳:启动落盘 + 拉取 ----------
    def _find_cache_dir(self, ctx: Context):
        """在 /data/data/<pkg>/ 找壳的落盘缓存目录:app_* 里同时有 assets.zip 和 classes.dex。"""
        dd = ctx.data_dir
        for d in util.su(f'ls -d {dd}/app_* 2>/dev/null').split():
            ls = util.su(f'ls {d} 2>/dev/null')
            if 'assets.zip' in ls and 'classes.dex' in ls:
                return d
        return None

    def unpack(self, ctx: Context) -> dict:
        import analyze
        # 杀透 + 启动,等壳把产物落盘
        util.adb('shell', 'am', 'force-stop', ctx.pkg)
        time.sleep(1)
        ctx.log(f'[*] 启动 app: {util.launch_app(ctx.pkg)}')
        cache = None
        t0 = time.time()
        while time.time() - t0 < ctx.timeout:
            cache = self._find_cache_dir(ctx)
            if cache:
                # 再等 .so 子目录齐活
                sub = util.su(f'ls {cache}/*/libapp.so 2>/dev/null').strip()
                if sub:
                    break
            ctx.log(f'    …等壳落盘({int(time.time()-t0)}s)')
            time.sleep(2)
        if not cache:
            raise RuntimeError('没等到壳落盘缓存目录(app_*/assets.zip+classes.dex)')
        ctx.log(f'[*] 壳缓存目录: {cache}')

        # 设备上整理到可读暂存,再 pull
        stage = '/data/local/tmp/deshell_pull'
        util.su(f'rm -rf {stage}; mkdir -p {stage}/dex {stage}/lib')
        util.su(f'cp {cache}/classes*.dex {stage}/dex/ 2>/dev/null')
        util.su(f'cp {cache}/assets.zip {stage}/ 2>/dev/null')
        util.su(f'cp {cache}/*/*.so {stage}/lib/ 2>/dev/null')
        util.su(f'chmod -R a+rX {stage}')

        art = os.path.join(ctx.out, 'artifacts')
        os.makedirs(art, exist_ok=True)
        for sub in ('dex', 'lib'):
            util.adb('pull', f'{stage}/{sub}', art)
        util.adb('pull', f'{stage}/assets.zip', art)
        util.su(f'rm -rf {stage}')

        dexes = sorted(glob.glob(os.path.join(art, 'dex', '*.dex')),
                       key=lambda p: (len(os.path.basename(p)), p))
        sos = sorted(glob.glob(os.path.join(art, 'lib', '*.so')))
        azip = os.path.join(art, 'assets.zip')
        if not (dexes and sos and os.path.exists(azip)):
            raise RuntimeError(f'拉取不全: dex={len(dexes)} so={len(sos)} assets={os.path.exists(azip)}')
        ctx.log(f'[✓] 拉取: {len(dexes)} dex, {len(sos)} so, assets.zip {os.path.getsize(azip)}B')
        return {'art': art, 'dexes': dexes, 'sos': sos, 'assets_zip': azip}

    # ---------- 找真 Application ----------
    def _find_real_app(self, ctx: Context, dexes, stub_dotted):
        here = ctx.here
        r = subprocess.run([sys.executable, '-I', os.path.join(here, 'find_application.py'),
                            '--pkg=' + ctx.pkg] + dexes, capture_output=True, text=True)
        cands = re.findall(r'^  ([A-Za-z][\w.]+)$', r.stdout, re.M)
        cands = [c for c in cands if c != stub_dotted]
        # 优先:非 io.flutter 框架类的、app 自有/自定义 Application
        custom = [c for c in cands if not c.startswith('io.flutter.') and
                  not c.startswith('androidx.')]
        return (custom or cands or ['io.flutter.app.FlutterApplication'])[0]

    # ---------- 生成壳桩替身类 ----------
    def _build_shim(self, ctx: Context, dexes, stub_dotted):
        stub_desc = ('L' + stub_dotted.replace('.', '/') + ';').encode()
        refs = dex_stub_method_refs(dexes, stub_desc)
        if not refs:
            ctx.log('[*] 真 dex 未引用壳桩方法,无需替身类')
            return None
        pkg_path = stub_dotted.rsplit('.', 1)[0].replace('.', '/')
        cls = stub_dotted.rsplit('.', 1)[1]
        methods = []
        ctx.log(f'[*] 壳桩被引用方法 {len(refs)} 个,生成替身:')
        for (name, params, ret) in refs:
            rj = _desc_to_java(ret)
            pj = [_desc_to_java(p) for p in params]
            args = ', '.join(f'{t} a{i}' for i, t in enumerate(pj))
            # 已知模式:返回 AssetManager + 有 Context 参 → 原生直通 getAssets()
            if rj == 'android.content.res.AssetManager':
                ctx_i = next((i for i, t in enumerate(pj)
                              if t in ('android.content.Context', 'java.lang.Object')), None)
                if ctx_i is not None:
                    body = f'return ((android.content.Context) a{ctx_i}).getAssets();'
                    ctx.log(f'     - {name}(...) -> AssetManager  [直通 getAssets()]')
                else:
                    body = _default_return(rj)
            else:
                body = _default_return(rj)
                ctx.log(f'     - {name}(...) -> {rj}  [默认返回,若功能异常需手工实现]')
            methods.append(f'    public static {rj} {name}({args}) {{ {body} }}')
        src_dir = os.path.join(ctx.out, 'shim', 'src', pkg_path)
        os.makedirs(src_dir, exist_ok=True)
        java = (f'package {stub_dotted.rsplit(".",1)[0]};\n\n'
                f'/* deshell 自动生成的壳桩替身:把被真 dex 引用的壳方法实现成原生直通 */\n'
                f'public class {cls} {{\n' + '\n'.join(methods) + '\n}\n')
        jpath = os.path.join(src_dir, cls + '.java')
        open(jpath, 'w').write(java)
        # 编译 -> dex
        aj = sorted(glob.glob(f'{HOME}/Android/Sdk/platforms/android-3*/android.jar'))
        if not aj:
            raise RuntimeError('找不到 android.jar(~/Android/Sdk/platforms/android-3*/)')
        aj = aj[-1]
        d8 = next((p for p in [f'{HOME}/Android/Sdk/cmdline-tools/latest/bin/d8']
                   + sorted(glob.glob(f'{HOME}/Android/Sdk/build-tools/*/d8'), reverse=True)
                   if os.path.exists(p)), None)
        if not d8:
            raise RuntimeError('找不到 d8')
        cdir = os.path.join(ctx.out, 'shim', 'classes')
        os.makedirs(cdir, exist_ok=True)
        subprocess.run(['javac', '--release', '8', '-cp', aj, '-d', cdir, jpath], check=True,
                       capture_output=True, text=True)
        clsfile = os.path.join(cdir, pkg_path, cls + '.class')
        shim_out = os.path.join(ctx.out, 'shim')
        subprocess.run([d8, '--min-api', '21', '--lib', aj, '--output', shim_out, clsfile],
                       check=True, capture_output=True, text=True)
        shim_dex = os.path.join(shim_out, 'classes.dex')
        ctx.log(f'[✓] 替身 dex: {shim_dex}')
        return shim_dex

    # ---------- 重打包 ----------
    def repack(self, ctx: Context, art: dict) -> str:
        if not os.path.exists(SIGNER):
            raise RuntimeError(f'找不到 uber-apk-signer: {SIGNER}')
        dexes, sos, azip = art['dexes'], art['sos'], art['assets_zip']
        src = zipfile.ZipFile(ctx.apk)
        raw_mf = src.read('AndroidManifest.xml')

        stub = axml_application_name(raw_mf)
        mf = strip_junk_chunks(raw_mf)
        shim_dex = None
        real_app = None
        if stub and stub not in self._dex_defined_classes(dexes):
            real_app = self._find_real_app(ctx, dexes, stub)
            ctx.log(f'[*] 入口 Application: 壳桩 {stub}  ->  真 {real_app}')
            mf = replace_pool_string(mf, stub, real_app)
            shim_dex = self._build_shim(ctx, dexes, stub)
        else:
            ctx.log(f'[*] application android:name={stub}(真 dex 已定义/无,无需换)')

        outdir = os.path.join(ctx.out, 'repack')
        os.makedirs(outdir, exist_ok=True)
        unsigned = os.path.join(outdir, 'deshelled_unsigned.apk')
        if os.path.exists(unsigned):
            os.remove(unsigned)
        zout = zipfile.ZipFile(unsigned, 'w', zipfile.ZIP_DEFLATED)

        def is_sig(n):
            u = n.upper()
            return u.startswith('META-INF/') and u.rsplit('.', 1)[-1] in ('SF', 'RSA', 'DSA', 'EC') \
                or u.endswith('MANIFEST.MF')
        seen = set()
        for it in src.infolist():
            n = it.filename
            if n in seen or n.endswith('/'):
                continue
            seen.add(n)
            if n == 'classes.dex' or n.startswith('assets/') or n.startswith('lib/') \
               or n in ('AndroidManifest.xml', 'ANDROIDMANIFEST.XML') or is_sig(n):
                continue
            data = src.read(n)
            if n == 'resources.arsc':
                zi = zipfile.ZipInfo('resources.arsc'); zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, data)
            else:
                zout.writestr(n, data, zipfile.ZIP_DEFLATED)

        zout.writestr('AndroidManifest.xml', mf, zipfile.ZIP_DEFLATED)
        all_dex = list(dexes) + ([shim_dex] if shim_dex else [])
        for i, d in enumerate(all_dex, 1):
            name = 'classes.dex' if i == 1 else f'classes{i}.dex'
            zout.writestr(name, open(d, 'rb').read(), zipfile.ZIP_DEFLATED)
        for s in sos:
            zout.writestr('lib/arm64-v8a/' + os.path.basename(s), open(s, 'rb').read(), zipfile.ZIP_DEFLATED)
        az = zipfile.ZipFile(azip)
        for it in az.infolist():
            if not it.filename.endswith('/'):
                zout.writestr(it.filename, az.read(it.filename), zipfile.ZIP_DEFLATED)
        zout.close(); src.close(); az.close()
        ctx.log(f'[*] 未签名 APK: {unsigned} ({os.path.getsize(unsigned)}B, {len(all_dex)} dex, {len(sos)} so)')

        subprocess.run(['java', '-jar', SIGNER, '--apks', unsigned, '--allowResign',
                        '-o', os.path.join(outdir, 'signed')], check=True)
        signed = glob.glob(os.path.join(outdir, 'signed', '*-debugSigned.apk'))
        if not signed:
            raise RuntimeError('签名没出 APK')
        ctx.log(f'[✓] 签名 APK: {signed[0]}')
        return signed[0]

    @staticmethod
    def _dex_defined_classes(dexes):
        """返回这些 dex 里「定义」的类描述符集合(class_defs),用于判断某类是否在真 dex。"""
        defined = set()
        for path in dexes:
            d = open(path, 'rb').read()
            u32 = lambda o: struct.unpack_from('<I', d, o)[0]
            sio = u32(0x3c); tio = u32(0x44)
            cds, cdo = struct.unpack_from('<II', d, 0x60)
            def s_at(i):
                o = u32(sio + i * 4); p = o
                while d[p] & 0x80: p += 1
                p += 1
                return d[p:d.index(b'\x00', p)].decode('utf-8', 'replace')
            for i in range(cds):
                cidx = u32(cdo + i * 32)
                desc = s_at(u32(tio + cidx * 4))
                if desc.startswith('L') and desc.endswith(';'):
                    defined.add(desc[1:-1].replace('/', '.'))
        return defined
