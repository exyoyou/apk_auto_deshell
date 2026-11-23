"""unpackers — 可扩展脱壳插件框架。

加新壳:在本目录新增 xxx.py,写个 @register 的 Unpacker 子类(实现 detect/unpack/repack),
再在下面 import 进来即可被 deploy 自动调度。
"""
from .base import Unpacker, Context, REGISTRY, register, pick  # noqa: F401

# 注册内置插件(import 即触发 @register)。越具体的壳放前面(仅影响同分平手时的顺序)。
from . import cgakq   # noqa: F401,E402  磁盘缓存型 Flutter 壳
from . import fart    # noqa: F401,E402  内存 dump 型 DEX 壳(通用兜底)
