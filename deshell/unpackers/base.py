#!/usr/bin/env python3
"""unpackers/base.py — 脱壳插件框架的基座。

设计:每一类壳 = 一个 Unpacker 插件,自己负责三件事:
  detect(ctx)  —— 看这个 APK/设备是不是自己能处理的壳,返回 0..100 的置信度(0=不是我)
  unpack(ctx)  —— 把解密后的真产物(dex/so/assets)弄出来,返回 artifacts
  repack(ctx)  —— 用 artifacts 重打包出一个「原生可运行」的签名 APK,返回其路径

deploy.py 只做调度:装壳版 → 让所有插件 detect → 选置信度最高的 → unpack → repack → verify。
以后加新壳:在 unpackers/ 下加一个文件,写个 @register 的 Unpacker 子类即可,无需改 deploy。
"""
from __future__ import annotations
import dataclasses
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import util  # noqa: E402


@dataclasses.dataclass
class Context:
    """一次脱壳任务的共享上下文。"""
    apk: str                       # 加壳 APK 路径(绝对)
    pkg: str                       # 包名
    out: str                       # 本 app 的输出目录(绝对)
    here: str                      # deshell 包所在目录(定位同级脚本/模板)
    timeout: int = 40              # 等落盘/等 dump 的秒数
    install: bool = True           # 重打包后是否装机验证
    user: str = '0'                # adb install 目标用户(默认 user 0;'all'=全用户)
    keep_inject: bool = False      # 结束是否保留 frida 注入
    reuse_analysis: bool = False   # 复用已有分析产物
    meta: dict = dataclasses.field(default_factory=dict)  # 插件间/检测期传数据

    # —— 常用派生 ——
    @property
    def data_dir(self) -> str:
        return f'/data/data/{self.pkg}'

    def log(self, msg: str):
        print(msg)


class Unpacker:
    name = 'base'
    desc = ''

    def detect(self, ctx: Context) -> int:
        """返回 0(不是我)或 1..100(置信度)。只读、不应有副作用之外的破坏。"""
        return 0

    def unpack(self, ctx: Context) -> dict:
        """产出 artifacts(至少含 dex/so/assets 信息),供 repack 用。"""
        raise NotImplementedError

    def repack(self, ctx: Context, artifacts: dict) -> str:
        """产出可运行签名 APK,返回路径。"""
        raise NotImplementedError

    # —— 通用装机验证:装上、启动、看进程是否存活 ——
    def verify(self, ctx: Context, apk: str, wait: int = 9) -> bool:
        import analyze
        ctx.log('\n[*] 装机验证')
        util.adb('uninstall', ctx.pkg)
        r = util.install_apk(apk, user=ctx.user)
        msg = (r.stdout + r.stderr).strip().splitlines()
        ctx.log('    ' + (msg[-1] if msg else 'installed'))
        ctx.log(f'    启动: {util.launch_app(ctx.pkg)}')
        time.sleep(wait)
        alive = analyze.running_app_procs(ctx.pkg)
        ok = bool(alive)
        ctx.log(f'    启动后进程: {[n for n, _ in alive] or "无(可能崩溃/卡死,看 logcat)"}')
        return ok


# ---------------- 注册表 ----------------
REGISTRY: list[Unpacker] = []


def register(cls):
    """@register 装饰器:实例化并登记一个 Unpacker。"""
    REGISTRY.append(cls())
    return cls


def pick(ctx: Context) -> Unpacker | None:
    """跑所有插件的 detect,选置信度最高的(>0)。打印评分表。"""
    scored = []
    for u in REGISTRY:
        try:
            s = u.detect(ctx)
        except Exception as e:
            s = 0
            print(f'    [!] {u.name}.detect 异常: {e}')
        scored.append((s, u))
    scored.sort(key=lambda x: x[0], reverse=True)
    print('\n[*] 壳类型识别:')
    for s, u in scored:
        mark = '→' if (s == scored[0][0] and s > 0) else ' '
        print(f'   {mark} {u.name:12s} score={s:3d}  {u.desc}')
    best_s, best_u = scored[0]
    return best_u if best_s > 0 else None
