/*
 * deshell/dump_full.js — frida-gadget on_load 脚本:反自杀 + 全区扫描 dump 全部已解密 DEX
 *
 * 适用:加载时整体解密、靠 inline-svc 自杀 / 守护进程跨进程 kill 做反 frida 的壳
 * (如网易易盾 Overmind)。思路:先 NOP 掉自杀点并拦致命信号,让进程稳定存活,
 * 再定时扫描所有 rw 匿名区,把每个「被抹了 dex\n 头」的 DEX 整段 dump 出来。
 *
 * 与「hook DoCall 的 FART」相比:FART 只能发现被解释器执行过的方法所在 dex,
 * 本法扫内存里全部已解密 dex,一次抓全(含没被执行到的入口类)。
 *
 * 用法:作为 ZygiskFrida(或任意 gadget)的 script 模式脚本注入;对「主进程 + 守护进程」
 * 双 target 注入,两者都跑本脚本(都 NOP 自杀点,守护进程才 kill 不了主进程)。
 * dump 产物写到 /data/data/<PKG>/zf_mdex_N.bin,外部用 adb 拉取后交给 rebuild_dex.py。
 */
(function () {
  // ============================ 配置(换 app/设备改这里)============================
  var CFG = {
    PKG: 'com.join.android.app.mgsim.wufun',        // 目标包名(决定 dump 落盘目录)
    SUICIDE_LIB: 'libvuoum.so',                      // 自杀逻辑所在壳 so(没有就留空字符串)
    SUICIDE_OFFS: [0x27bd4, 0x27c34],                // 该 so 内的 inline-svc 自杀点偏移(capstone 定位)
    KILL_SIGNALS: [9, 6, 15],                         // 要拦截的致命信号
    SCAN_TIMES_MS: [5000, 10000, 16000, 24000, 34000, 46000, 60000, 78000], // 多轮扫描时刻(兼顾懒加载)
    MAX_DEX_SIZE: 40 * 1024 * 1024                    // 单个 dex 区的 dump 上限(保险)
  };
  // ================================================================================

  function gx(n) {
    try { return Module.getGlobalExportByName ? Module.getGlobalExportByName(n) : Module.findExportByName(null, n); }
    catch (e) { try { return Module.findExportByName('libc.so', n); } catch (e2) { return null; } }
  }
  var D = '/data/data/' + CFG.PKG + '/';
  function log(name, s) { try { new File(D + name, 'w').write('' + s); } catch (e) {} }

  try {
    // ① NOP 壳 so 的 inline-svc 自杀点(exit_group / kill)
    if (CFG.SUICIDE_LIB) {
      var m = Process.findModuleByName(CFG.SUICIDE_LIB);
      if (m) {
        var nop = [0x1f, 0x20, 0x03, 0xd5];          // aarch64 NOP
        CFG.SUICIDE_OFFS.forEach(function (o) {
          var a = m.base.add(o); Memory.protect(a, 16, 'rwx'); a.writeByteArray(nop);
        });
      }
    }
    // ② 拦 kill/tgkill/tkill 的致命信号(守护进程 → 主进程 signal 9 等)
    [['kill', 1], ['tgkill', 2], ['tkill', 1]].forEach(function (p) {
      var e = gx(p[0]);
      if (e) Interceptor.attach(e, { onEnter: function (a) {
        var s = a[p[1]].toInt32();
        if (CFG.KILL_SIGNALS.indexOf(s) >= 0) a[p[1]] = ptr(0);
      } });
    });
    log('zf_pp_' + Process.id + '.txt', 'patched');

    // ③ 只有主进程(有 libart)才扫 dex;守护进程只需上面的反自杀
    var libart = Process.findModuleByName('libart.so');
    if (!libart) { log('zf_guard_' + Process.id + '.txt', 'no libart, patch-only'); return; }

    // 被抹掉 "dex\n" 后:区首 4 字节 = "035\0" = 30 33 35 00;偏移整体 -4,于是
    //   header_size @ raw 0x20 == 0x70、endian_tag @ raw 0x24 == 0x12345678、file_size @ raw 0x1c
    var MAGIC = [0x30, 0x33, 0x35, 0x00];
    var seen = {}, idx = 0, manifest = [];

    function dexFileSize(base) {
      try {
        var h = new Uint8Array(base.readByteArray(0x28));
        for (var i = 0; i < 4; i++) if (h[i] !== MAGIC[i]) return null;
        if ((h[0x20] | h[0x21] << 8 | h[0x22] << 16 | h[0x23] << 24) !== 0x70) return null;      // header_size
        if (!(h[0x24] === 0x78 && h[0x25] === 0x56 && h[0x26] === 0x34 && h[0x27] === 0x12)) return null; // endian
        return (h[0x1c] | h[0x1d] << 8 | h[0x1e] << 16 | h[0x1f] << 24) >>> 0;                   // file_size
      } catch (e) { return null; }
    }

    function scan(tag) {
      var ranges;
      try { ranges = Process.enumerateRanges('rw-'); } catch (e) { ranges = []; }
      var found = 0;
      ranges.forEach(function (r) {
        if (r.file) return;                          // file-backed(vdex/framework)跳过
        var k = r.base.toString();
        if (seen[k]) return;
        var fsize = dexFileSize(r.base);
        if (fsize === null) return;
        seen[k] = 1; idx++;
        var take = Math.min(r.size, fsize + 0x10000);
        if (take > CFG.MAX_DEX_SIZE) take = CFG.MAX_DEX_SIZE;
        try {
          var b = new File(D + 'zf_mdex_' + idx + '.bin', 'wb');
          b.write(r.base.readByteArray(take)); b.close();
          manifest.push('mdex_' + idx + ' base=' + r.base + ' rangeSz=' + r.size + ' fileSize=' + fsize + ' took=' + take + ' [' + tag + ']');
          found++;
        } catch (e) { manifest.push('mdex_' + idx + ' DUMP_FAIL base=' + r.base + ' ' + e); }
      });
      log('zf_mdex_manifest.txt', manifest.join('\n') + '\n--- scan ' + tag + ': +' + found + ', total ' + idx + ' ---');
    }

    CFG.SCAN_TIMES_MS.forEach(function (t) { setTimeout(function () { scan('t' + t); }, t); });
    log('zf_mdex_hook.txt', 'dump_full armed; ' + CFG.SCAN_TIMES_MS.length + ' scans scheduled');
  } catch (e) { log('zf_err_' + Process.id + '.txt', '' + e); }
})();
