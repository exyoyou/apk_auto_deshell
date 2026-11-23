# deshell

**去壳重打包工具** —— 把脱出的真实 DEX 还原成一个**可安装、可原生运行**的去壳 APK。

`unpack` 负责 **scan → dump → repair → verify**(把加密/抽取的 DEX 从内存里搞出来);
`deshell` 接在它后面,负责 **de-shell → repack → resign → run**:换掉壳的 Application 入口、
把真 DEX 塞回 APK、重签名,得到一个不再依赖壳、能直接装到手机上跑的 APK。

> 实战验证:网易易盾(Overmind)壳的 `com.join.android.app.mgsim.wufun`(悟饭游戏厅)——
> 完整脱出 10 个主体 DEX,去壳重签名后在 Android 17 arm64 上原生正常运行(无壳、无 frida)。
> 全链路细节见 [`docs/全链路脱壳手册.md`](docs/全链路脱壳手册.md)。

---

## 它解决什么

脱壳拿到 DEX 只是一半。要让 app **脱离壳独立运行**,还得过三关,`deshell` 把这三关自动化:

1. **找对真正的 Application 入口**(最大的坑)
   壳把 manifest 的 `application android:name` 改成了壳的桩类。直接用脱出的 DEX 重打包、
   但入口还是壳类 → 一启动就崩;换成**中间基类**(各种 BaseApp / Hilt_* / VApp)→ 全局静态
   context 不初始化,主界面出来几秒后崩(本样本:ORMLite `getHelper(null)`)。
   真入口 = 继承链能到 `android.app.Application` 且**没有子类**的那个「叶子」。
   → `find_application.py` 自动解析继承链找出来。

2. **把真 DEX 塞回去、改回真入口、重签名**
   `apktool d -s`(保留原 dex、不反编 smali)→ 改 manifest 入口 → `apktool b` →
   用真 DEX 替换壳 `classes.dex`(ART 原生 multidex)→ `uber-apk-signer` 重签名。
   → `repack.py` 一条命令完成。

3. **为什么重签名后不会被壳的完整性校验秒退**
   换掉桩 Application 后,壳的 native 库(做完整性校验/反调试的那个,如 `libvuoum.so`)
   再也不会被 `loadLibrary` → 壳根本不启动 → 没有完整性校验 → 改字节/重签名都无所谓。
   (app 自己的真库如 `libovermind*.so` 要保留。)

---

## 依赖

纯脚本,无需安装。按阶段分:

### 电脑端(host)

| 工具 | 用在哪 | 说明 |
|---|---|---|
| `python3`(标准库即可) | 全程 | 跑本项目脚本 |
| `java` | 重打包 | 跑 apktool / signer |
| [`apktool`](https://apktool.org/) | 重打包 | 默认 `~/.apklab/apktool_3.0.3.jar`,或环境变量 `APKTOOL_JAR` |
| [`uber-apk-signer`](https://github.com/patrickfav/uber-apk-signer) | 重打包 | 默认 `~/.apklab/uber-apk-signer-1.3.0.jar`,或 `SIGNER_JAR`;自动建 debug key |
| `zip` / `unzip` | 重打包 | 换 dex |
| `aapt`(Android build-tools) | 看包名/入口 | `~/Android/Sdk/build-tools/*/aapt`,非必需 |
| `adb` | dump + 装机 | |
| `frida` client | dump | 版本要和手机上的 gadget **对齐** |
| `dexdump` / `jadx` | 核对(可选) | 验证脱出的 dex |

### 手机端(device)——**仅 dump 阶段需要**

> 重打包出来的脱壳 APK **装到任意手机都能跑,不需要 root / 不需要下面这些**。
> 下面这套只在「你要自己从加壳 app 抓 DEX」时才需要。

- **已 root**(KernelSU / Magisk / APatch 任一)
- **Zygisk 实现**:ZygiskNext(`zygisksu`)或 Magisk 自带 Zygisk
- **ZygiskFrida 模块**([lico-n/ZygiskFrida](https://github.com/lico-n/ZygiskFrida)),刷入重启
- **frida-gadget .so**(版本和电脑上 frida client 对齐),放到 ZygiskFrida 工作目录
  `/data/local/tmp/re.zyg.fri/libgadget.so`
- 该目录下三个配置文件(见下「用法 B」):`config.json`(注入哪些进程)、
  `libgadget.config.so`(script 模式)、`config.json.example`(= 本项目的 `dump_full.js`)
- `adb` 能拿到 root(`su`)

### 获取目标包名 / 入口

`repack.py` 会**自动**从 manifest 读包名,一般不用管。要手动查:

```bash
aapt dump badging 目标.apk | grep -E "^package|launchable-activity"
#   package: name='com.xxx' ...
#   launchable-activity: name='com.xxx.SomeActivity' ...   ← 桌面入口(不是真 Application)
```
注意 `dump_full.js` 落盘要用到包名(写进脚本顶部 `CFG.PKG`)。

---

## 用法

### A. 已经有脱出的 DEX → 直接出可装 APK

```bash
# 自动识别真 Application + 去壳重签名
python3 deshell/repack.py \
    --apk 原始加壳.apk \
    --dex-dir 脱出的dex目录 \
    --auto --pkg com.example.app \
    -o out

# 产物在 out/signed/*-debugSigned.apk,按提示 adb install
```

手动指定入口(跳过自动识别):
```bash
python3 deshell/repack.py --apk 原始.apk --dex-dir dexdir --app com.MApplication -o out
```

可选:同时删掉壳 so(一般不必,壳不启动就不加载;确实想删时):
```bash
python3 deshell/repack.py ... --keep-shell-lib libvuoum.so,libvuoum-x86.so
```

### B. 还没有 DEX → 先用 dump 脚本抓(针对易盾这类「加载时整体解密」的壳)

1. 把 `deshell/dump_full.js` 顶部 `CFG` 改成你的包名/壳 so/自杀点偏移(见脚本注释和手册)。
2. 作为 frida-gadget 的 script 注入(推荐 ZygiskFrida **双 target**:主进程 + 守护进程都注入,
   两者都跑本脚本,守护进程才 kill 不了主进程)。
3. 启动 app,等十几秒,脚本会把每个已解密 DEX 写到 `/data/data/<pkg>/zf_mdex_N.bin`。
4. 拉下来并重建成合法 DEX:
   ```bash
   # dump 文件在 app 私有目录(/data/data/<pkg>/,mode 0600、app uid 所有),
   # 所以不能用 adb pull(会 "0 files pulled" 权限失败),必须用 root 的 su -c cat 导出:
   for n in $(seq 1 20); do adb shell su -c "cat /data/data/<pkg>/zf_mdex_$n.bin" > zf_mdex_$n.bin 2>/dev/null; done
   # 可选:看脚本抓到几个 / 诊断
   adb shell su -c "cat /data/data/<pkg>/zf_mdex_manifest.txt"
   python3 deshell/rebuild_dex.py zf_mdex_*.bin      # 出 classes_main_N.dex
   ```
5. 回到 A。

---

## 脚本清单

| 脚本 | 作用 |
|---|---|
| `deshell/repack.py` | **主编排器**:去壳 + 换真 DEX + 重签名,一条命令出可装 APK |
| `deshell/find_application.py` | 从 DEX 解析继承链,**自动识别真实 Application 入口**(叶子类) |
| `deshell/rebuild_dex.py` | 把被抹了 `dex\n` 头的内存 dump 修复成合法 DEX(补头 + 修 checksum/signature) |
| `deshell/list_classdefs.py` | 快速枚举 DEX 里所有已定义类(不反汇编,用于核对完整性) |
| `deshell/dump_full.js` | frida-gadget 脚本:反自杀 + **扫全部 rw 匿名区 dump 全部已解密 DEX** |

---

## 适用范围 / 限制

- 面向**整包解密型 / 函数抽取后在内存里能凑齐**的壳(易盾 Overmind 已验证)。
- `dump_full.js` 的自杀点偏移、守护进程名、壳 so 名是 **app/设备/壳版本相关**的,换目标要重定位
  (手册里有用 capstone 定位 inline-svc 自杀点的方法)。
- `repack.py` 本身与具体壳无关,只要你有真 DEX + 原 APK + 真入口类名就能用。
- 仅用于**授权的安全研究 / 自有 app 分析**。

更多原理见 [`docs/全链路脱壳手册.md`](docs/全链路脱壳手册.md)。
