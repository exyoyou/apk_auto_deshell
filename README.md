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
| `capstone`(python) | 自动分析 | `analyze.py` 反汇编找自杀点;用带它的解释器跑(本机 `frida/.venv`) |
| `dexdump` / `jadx` | 核对(可选) | 验证脱出的 dex |

### 手机端(device)——**仅 dump 阶段需要**

> 重打包出来的脱壳 APK **装到任意手机都能跑,不需要 root / 不需要下面这些**。
> 下面这套只在「你要自己从加壳 app 抓 DEX」时才需要。

**只要已 root,下面的 ②③④ 全部用 `python3 deshell/setup.py` 一键自动装齐**(下载对齐版 gadget +
安装 ZygiskFrida 模块 + 铺配置)。手动的话:

- ① **已 root**(KernelSU / Magisk / APatch 任一)+ Zygisk 实现(ZygiskNext `zygisksu` 或 Magisk 自带)
- ② **ZygiskFrida 模块**([lico-n/ZygiskFrida](https://github.com/lico-n/ZygiskFrida)),刷入重启
- ③ **frida-gadget .so**(版本和电脑 frida client 对齐)→ `/data/local/tmp/re.zyg.fri/libgadget.so`
- ④ 该目录下的配置:`config.json`(注入哪些进程)、`libgadget.config.so`(script 模式)、
  `config.json.example`(= `analyze.py` 生成的 dump 脚本)
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

### 🚀 一条命令全自动(有 root 的设备)

```bash
# 把加壳 APK 放进 apks/,然后(用带 capstone/frida 的解释器):
/path/to/.venv/bin/python deshell/setup.py          # 首次:自动装 ZygiskFrida + 对齐版 gadget
/path/to/.venv/bin/python deshell/deploy.py --install
# deploy 全自动:选 APK → 内存找自杀点 → 注入 dump 全部 DEX → 重建 → 去壳重签名 → 装机验证
# 产物:out/signed/*-debugSigned.apk
```

下面是分步/手动用法。

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

### B. 还没有 DEX → 先 dump(针对易盾这类「加载时整体解密」的壳)

**不用手改任何配置**。`analyze.py` 会用 root + capstone 自动分析,生成填好的 dump 脚本。

0. 先自检环境:`python3 deshell/doctor.py`(缺的工具会标红)。

1. **自动分析出配置**(要用带 capstone/frida 的解释器):
   ```bash
   # 交互选 apks/ 里的 APK → aapt 读包名 → 装上跑起来 →
   # root 从内存 dump 各壳 so 的 r-x 段 → capstone 扫 inline-svc 自杀点(exit_group/kill)→
   # 自动定出 PKG / SUICIDE_LIB / SUICIDE_OFFS,并按「哪些进程加载了壳 so」识别注入目标
   /path/to/.venv/bin/python deshell/analyze.py          # 需 capstone(本机:frida/.venv)
   ```
   产出两份:`out/dump_<pkg>.js`(填好 CFG 的 dump 脚本)和 `out/config_<pkg>.json`(ZygiskFrida 多 target 配置)。
   典型输出:`自杀壳 so: libvuoum.so / SUICIDE_OFFS = [0x27bd4, 0x27c34]`。

2. 把两份覆盖到 ZygiskFrida 工作目录:
   `config_<pkg>.json → .../re.zyg.fri/config.json`、`dump_<pkg>.js → .../re.zyg.fri/config.json.example`。
   > 注:守护进程(如 `:mind`)常在**同意隐私后才起**,此刻 analyze 看不到它。若启动后主进程被 signal 9 杀,
   > 按 analyze 的提示把那个也加载了壳 so 的守护进程全名加进 config.json 的 `targets`(判据:它 maps 里有壳 so)。

3. 启动 app,等十几秒,脚本把每个已解密 DEX 写到 `/data/data/<pkg>/zf_mdex_N.bin`。

4. 拉下来并重建成合法 DEX:
   ```bash
   # dump 文件在 app 私有目录(/data/data/<pkg>/,mode 0600、app uid 所有),
   # 不能用 adb pull(会 "0 files pulled" 权限失败),必须用 root 的 su -c cat 导出:
   for n in $(seq 1 20); do adb shell su -c "cat /data/data/<pkg>/zf_mdex_$n.bin" > zf_mdex_$n.bin 2>/dev/null; done
   adb shell su -c "cat /data/data/<pkg>/zf_mdex_manifest.txt"   # 可选:看抓到几个
   python3 deshell/rebuild_dex.py zf_mdex_*.bin                   # 出 classes_main_N.dex
   ```
5. 回到 A(`repack.py` 不给 `--apk` 时也会自动在 `apks/` 里让你选)。

> 若 `analyze.py` 扫不到自杀点(壳不用 inline-svc 自杀,或该壳没 native 反调试),它仍会填好 PKG,
> `SUICIDE_LIB/OFFS` 留空也能跑——很多壳只靠 ④ 的 DEX 加密,不需要反自杀。

---

## 脚本清单

| 脚本 | 作用 |
|---|---|
| `deshell/deploy.py` | **一条命令全自动**:选 APK → (analyze 自动出配置)→ 推 ZygiskFrida → 杀透重启 → 轮询拉 DEX → 重建 → 去壳重签名 →(可选)装机验证。全程无需点屏 |
| `deshell/doctor.py` | **环境自检**:一次性查齐电脑端工具(java/apktool/signer/zip/aapt)、dump 工具(adb/capstone/frida)、设备(在线/root/ZygiskFrida/gadget),缺啥报啥 |
| `deshell/setup.py` | **有 root 一键装齐 dump 环境**:自动下载安装 ZygiskFrida 模块 + 对齐本机 frida 版本的 frida-gadget + 铺好配置(把 doctor 报红的项自动修好) |
| `deshell/analyze.py` | **root + capstone 自动分析**:选 APK → 读包名 → 内存里扫壳 so 的 inline-svc 自杀点 → 按「是否加载壳 so」识别注入目标进程 → 生成填好配置的 dump 脚本 **和 ZygiskFrida config.json**(需 capstone) |
| `deshell/repack.py` | **主编排器**:(选 APK)去壳 + 换真 DEX + 重签名,一条命令出可装 APK |
| `deshell/find_application.py` | 从 DEX 解析继承链,**自动识别真实 Application 入口**(叶子类 / 按链长) |
| `deshell/rebuild_dex.py` | 把被抹了 `dex\n` 头的内存 dump 修复成合法 DEX(补头 + 修 checksum/signature) |
| `deshell/list_classdefs.py` | 快速枚举 DEX 里所有已定义类(不反汇编,用于核对完整性) |
| `deshell/dump_full.js` | frida-gadget 脚本模板:反自杀 + **扫全部 rw 匿名区 dump 全部已解密 DEX**(CFG 由 `analyze.py` 填) |
| `deshell/util.py` | 共享:终端选 APK、aapt 读包名、adb/root 封装 |

---

## 适用范围 / 限制

- 面向**整包解密型 / 函数抽取后在内存里能凑齐**的壳(易盾 Overmind 已验证)。
- `dump_full.js` 的自杀点偏移、守护进程名、壳 so 名是 **app/设备/壳版本相关**的,换目标要重定位
  (手册里有用 capstone 定位 inline-svc 自杀点的方法)。
- `repack.py` 本身与具体壳无关,只要你有真 DEX + 原 APK + 真入口类名就能用。
- 仅用于**授权的安全研究 / 自有 app 分析**。

更多原理见 [`docs/全链路脱壳手册.md`](docs/全链路脱壳手册.md)。
