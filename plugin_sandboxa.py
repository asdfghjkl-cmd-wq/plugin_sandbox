# -*- coding: utf-8 -*-

import pickle
import builtins as _builtins
import collections
import copy
import datetime
import functools
import http.client
import importlib as _importlib
import io
import itertools
import json as _json
import logging
import math
import os
import random
import re
import socket
import string
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import types as _types
import urllib.parse
import urllib.request
import weakref

import mutagen
import mutagen.flac
import mutagen.id3
import tkinter
import tkinter.colorchooser
import tkinter.filedialog
import tkinter.font
import tkinter.messagebox
import tkinter.simpledialog
import tkinter.ttk
import ttkbootstrap
from PIL import Image as _PILImage
from PIL import ImageTk as _PILImageTk

__all__ = ['SandboxDenied','Policy','parse_policy','SandBox','SandboxView','env_box',
           'ASK_YES','ASK_SESSION','ASK_ALWAYS','ASK_NEVER']

# 宿主专用凭据:只有"本来就持有它的一方"能给插件授权。插件拿不到这个对象,
# 所以 plugin/nb/a.py 里那种"给自己 grant 一下"的写法只会被拒。
_HOST_TOKEN = object()

# 询问授权时宿主可以返回的答案。
ASK_YES = 'yes'          # 只放行这一次
ASK_SESSION = 'session'  # 本次运行都放行(记住这个目录/能力)
ASK_ALWAYS = 'always'    # 放行并持久化到 config.json
# 第七批之后(bug 名 `ask_once`):用户明确要求"不再询问"。
# 只有这一个答案才会让沙盒**停止弹窗**;其余答案(包括拒绝)下次照样弹 ——
# 一次拒绝不该变成永久拒绝,否则用户再也没机会改主意。
ASK_NEVER = 'never'      # 不再询问这一类,并持久化到 config.json 的 plugin_deny


class SandboxDenied(Exception):
    """插件访问了没有授权的能力。调用方应当把它当成"操作没发生"。"""


# ---------------------------------------------------------------- 路径判定

def _norm_uncached(path):
    """`_norm` 的真身(不带缓存的那一份),逻辑一个字没改。"""
    if not isinstance(path,str):
        try:
            path = os.fspath(path)
        except TypeError:
            return None
        if not isinstance(path,str):
            return None
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError,ValueError):
        return None


# 第七批(性能,`path_norm_cache`):`_norm` 的结果是"路径 -> 字符串"的纯映射,
# 但 `os.path.realpath` 在 Windows 上每次都要走 `nt._getfinalpathname` 系统调用
# (实测单次 ~0.24ms)。审计钩子每扫一帧就经 `under()` 调两次 `_norm`,而
# `is_plugin_frame_on_stack()` / `_hook_box_on_stack()` 要把栈扫到 500 帧 ——
# 于是"宿主自己 open 一个文件"这种最常见的动作,光路径规范化就要几十毫秒。
#
# 实测(cProfile,10 次 create):920 次 `nt._getfinalpathname` 占掉 260ms 里的 219ms。
# 加缓存之后同样的判定只做一次 realpath,其余全是字典命中。
#
# 安全性:`_norm` 是判权的**输入**(不是判权结果),缓存只可能让它变快,不会让
# "越权路径"变成"授权路径";键就是调用方给的路径,插件刷一堆不同路径最多把缓存
# 挤出去(那时重新算,结果依旧相同)。上限 8192:够放下所有插件目录根 /
# `_ALWAYS_READABLE` 根 / 常见目标路径,又不会被刷爆内存。
#
# 注意缓存要罩住**入参转换**:`_norm` 对非 str(PathLike / 不可哈希对象)有明确的
# 兜底行为,所以先 `os.fspath` 转成 str 再进缓存,免得把 `TypeError` 变成"判权抛异常"。
#
# **相对路径的坑**:`realpath('a.txt')` 依赖当前工作目录,缓存不能跨 cwd 复用。
# 所以每次比一下 `os.getcwd()`(便宜),一旦变了就整体清空 —— 宁可重算,也不能拿
# "旧 cwd 下的绝对路径"去判权。绝对路径(宿主传进来的 plugin_dir、审计事件的路径
# 基本都是绝对路径)不受影响。
_NORM_CACHE = {}
_NORM_CACHE_MAX = 8192
_NORM_CWD = None


def _norm(path,_isabs=os.path.isabs):
    """规范化成"绝对 + 解析过符号链接 + 大小写统一"的形式,用于前缀比较。

    路径不存在也能算(realpath 只解析已存在的部分),所以写入新文件前也能判定。
    结果按路径记忆化(见上面的说明)。

    第十一批(性能,`hook_fastpath`):**绝对路径不再比 cwd**。
    原来这里每次调用都要 `os.getcwd()`(Windows 上是一次系统调用),而
    `_hook_frames_box` 每扫一帧就要经 `under()` 调它**两次** —— 这是审计钩子在
    宿主的普通文件操作上的第二大开销。但 `realpath` 对**绝对路径**的结果与当前
    工作目录无关,所以"绝对路径"根本不需要那道 cwd 比较:
      * `C:\\...` / `\\\\server\\share\\...`(UNC) => 跳过 getcwd,缓存直接可用;
      * 相对路径(含 Windows 的盘符相对路径 `C:foo`) => 照旧比 cwd,变了就整体清空。
    这只少做"无意义的工作",不改变任何一条路径的判定结果。`os.path.isabs` 按本文件
    的老规矩固化成默认参数(第三批那种写法),不新增可写的模块全局。
    """
    global _NORM_CWD
    if not isinstance(path,str):
        try:
            key = os.fspath(path)
        except TypeError:
            return None
        if not isinstance(key,str):
            return None
        path = key
    else:
        key = path
    # 绝对路径与 cwd 无关 => 免掉 os.getcwd(),也免掉"按 cwd 清缓存"。
    if not _isabs(key):
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = None
        if cwd != _NORM_CWD:
            _NORM_CWD = cwd
            _NORM_CACHE.clear()
    try:
        return _NORM_CACHE[key]
    except KeyError:
        pass
    got = _norm_uncached(path)
    if len(_NORM_CACHE) >= _NORM_CACHE_MAX:
        _NORM_CACHE.clear()          # 被刷爆就整体丢,不做复杂的淘汰
    _NORM_CACHE[key] = got
    return got


def _norm_cache_clear():
    _NORM_CACHE.clear()


_norm.cache_clear = _norm_cache_clear        # 方便自测/调试
_norm.__wrapped__ = _norm_uncached           # 想要"不带缓存的那一份"时用


def under(root, path):
    """path 是否就是 root 或位于 root 之内。"""
    r = _norm(root)
    p = _norm(path)
    if r is None or p is None:
        return False
    if r == p:
        return True
    if not r.endswith(os.sep):
        r += os.sep
    return p.startswith(r)


def _mode_writes(mode):
    """open() 的 mode 是否涉及写。"""
    return any(c in mode for c in ('w','a','x','+'))


# ---------------------------------------------------------------- 策略

class Policy:
    """一个插件的能力策略。默认:只读自己的目录,写/网络/进程全关。

    freeze() 之后这份策略就**不可再改**:插件的逃逸样本里有一招是
    `box.policy.fs_read = ['C:\\\\']`,原来 seal() 只是把 list 换成 tuple、
    谁都没拦着赋值,于是门面检查当场全放行。现在 freeze() 置 _frozen,
    任何后续写(setattr/delattr)都直接抛 SandboxDenied。
    """

    # 冻结后连这些也不许改:它们要么参与判定(unsafe/net/proc/ask),
    # 要么是宿主用来记账的(warnings),插件都不该碰。
    _FREEZE_KEYS = frozenset(('fs_read','fs_write','net','proc','ask','unsafe',
                              'unsafe_requested','modules','plugin_dir','warnings'))

    def __init__(self,plugin_dir):
        self.plugin_dir = os.path.abspath(plugin_dir)
        self.fs_read = [self.plugin_dir]
        self.fs_write = []
        self.net = False
        self.proc = False
        self.ask = True
        self.unsafe = False            # 生效值:只有宿主在用户确认后能打开
        self.unsafe_requested = False   # 插件在 plugin.json 里"要求"不受限制
        self.modules = []
        self.warnings = []
        self._frozen = False           # 只能由 freeze() 打开

    def __setattr__(self,name,value):
        if getattr(self,'_frozen',False) and name in self._FREEZE_KEYS:
            raise SandboxDenied(f'插件沙盒策略已封存,不能再改 {name}')
        object.__setattr__(self,name,value)

    def __delattr__(self,name):
        if getattr(self,'_frozen',False) and name in self._FREEZE_KEYS:
            raise SandboxDenied(f'插件沙盒策略已封存,不能再删 {name}')
        object.__delattr__(self,name)

    def roots(self,write):
        """写权限隐含读权限。"""
        if write:
            return list(self.fs_write)
        return list(self.fs_read) + list(self.fs_write)

    def freeze(self):
        """封存:换掉可变容器,并锁死后续所有改写。"""
        self.fs_read = tuple(self.fs_read)
        self.fs_write = tuple(self.fs_write)
        self.modules = tuple(self.modules)
        self.warnings = list(self.warnings)     # 宿主内部还要往里追加
        self._frozen = True

    def frozen(self):
        return bool(self._frozen)

    def snapshot(self):
        """判权用的只读副本:封存之后 can() 只认它,插件改 policy 也没用。"""
        snap = Policy(self.plugin_dir)
        snap.fs_read = tuple(self.fs_read)
        snap.fs_write = tuple(self.fs_write)
        snap.net = bool(self.net)
        snap.proc = bool(self.proc)
        snap.ask = bool(self.ask)
        snap.unsafe = bool(self.unsafe)
        snap.unsafe_requested = bool(self.unsafe_requested)
        snap.modules = tuple(self.modules)
        snap.warnings = []
        snap._frozen = True
        return snap

    def describe(self):
        if self.unsafe:
            return '不受沙盒限制(危险,已由你确认)'
        out = [f'读取:{", ".join(self.fs_read) or "无"}',
               f'写入:{", ".join(self.fs_write) or "无(需要时向你申请)"}']
        if self.net:
            out.append('网络:允许')
        if self.proc:
            out.append('外部进程:允许')
        if self.modules:
            out.append('额外模块:' + ','.join(self.modules))
        if self.unsafe_requested:
            out.append('插件要求不受沙盒限制(你没确认,当前仍受限)')
        return ' | '.join(out)


def _str_list(raw,key,policy,base_dir):
    v = raw.get(key,None)
    if v is None:
        return None
    if isinstance(v,str):
        v = [v]
    if not isinstance(v,(list,tuple)):
        policy.warnings.append(f'sandbox.{key} 不是字符串或数组,未生效')
        return None
    out = []
    for item in v:
        if not isinstance(item,str) or not item.strip():
            policy.warnings.append(f'sandbox.{key} 里的 {item!r} 无效,已忽略')
            continue
        p = item if os.path.isabs(item) else os.path.join(base_dir,item)
        out.append(os.path.normpath(p))
    return out


def parse_policy(raw_sandbox,legacy_privilege,plugin_dir):
    """从 plugin.json 的 sandbox 段(以及历史的 privilege)得出 Policy。

    任何不认识的键、类型不对的值都只记一条 warning 并按默认(更严)处理,
    不让一个写错的 plugin.json 把插件变成不受限制。
    """
    p = Policy(plugin_dir)
    raw = raw_sandbox if isinstance(raw_sandbox,dict) else {}
    if raw_sandbox is not None and not isinstance(raw_sandbox,dict):
        p.warnings.append('sandbox 不是 JSON 对象,按默认(最严)处理')

    known = ('fs_read','fs_write','net','proc','ask','unsafe','modules')
    for k in raw:
        if k not in known:
            p.warnings.append(f'sandbox 里的未知键 {k!r} 已忽略')

    got = _str_list(raw,'fs_read',p,p.plugin_dir)
    if got is not None:
        p.fs_read = got
    got = _str_list(raw,'fs_write',p,p.plugin_dir)
    if got is not None:
        p.fs_write = got

    for key in ('net','proc','ask'):
        v = raw.get(key,None)
        if v is None:
            continue
        if not isinstance(v,bool):
            p.warnings.append(f'sandbox.{key} 不是布尔值,未生效')
            continue
        setattr(p,key,v)
    # unsafe 只是"申请":真正放开要宿主在用户确认后调 set_unsafe()
    v = raw.get('unsafe',None)
    if v is not None:
        if not isinstance(v,bool):
            p.warnings.append('sandbox.unsafe 不是布尔值,未生效')
        elif v:
            p.unsafe_requested = True
            p.warnings.append('sandbox.unsafe=true:要求完全不受沙盒限制,需要你在装载时确认')

    mods = raw.get('modules',None)
    if mods is not None:
        if isinstance(mods,str):
            mods = [mods]
        if not isinstance(mods,(list,tuple)):
            p.warnings.append('sandbox.modules 不是字符串或数组,未生效')
        else:
            for item in mods:
                if isinstance(item,str) and item.strip() and re.fullmatch(r'[A-Za-z_][\w.]*',item):
                    p.modules.append(item)
                else:
                    p.warnings.append(f'sandbox.modules 里的 {item!r} 不是合法模块名,已忽略')

    # 历史 privilege
    legacy = legacy_privilege
    if legacy is not None and not isinstance(legacy,(list,tuple)):
        p.warnings.append('privilege 不是数组,已忽略')
        legacy = None
    for item in (legacy or ()):
        if item == 'no_sandbox_really':
            p.unsafe_requested = True
            p.warnings.append('privilege=no_sandbox_really:要求完全不受沙盒限制,'
                              '需要你在装载时确认')
        elif item == 'built':
            p.warnings.append("privilege 'built' 已被沙盒取代(常用内置函数默认可用),已忽略")
        else:
            p.warnings.append(f'未知的 privilege {item!r} 已忽略')

    return p


# ---------------------------------------------------------------- 门面

# ------------------------------------------------------------------ 模块门面的内部数据
#
# 第五批加固(bug 名 environ):门面的内部数据(真模块、沙盒、包装表、白名单……)
# 原来就放在 `__slots__` 的**普通属性**上。`__getattr__` 只对"找不到的属性"触发,
# 所以 `os._real.environ['PATH']`、`os._sb`、`os.path._real`、`sys._real.modules`
# 全都绕过了白名单;而"读环境变量"不产生 Python 审计事件,第二道闸没有可挂的钩子,
# 于是 `os.environ` 就这么被一行属性访问读走了。
#
# 这和第四批宿主门面(`pro.app._app`)是同一个 bug,只是当时没修模块门面。
# 这一批的做法与第四批**略有不同**:内部数据不放在实例的槽里(槽是描述符,
# `type(p)._d.__get__(p)` / `object.__getattribute__(p,'_d')` 两头都能绕过
# `__getattribute__`),而是放在这个模块私有的弱引用表里 —— 实例上什么都不留。
# 诚实说明:同进程内省拿到模块 globals 之后 `_PROXY_DATA[p]` 照样读得到,那和
# 直接读 `_g['os']` 是一个层级(见文件头),不是本批能解决的。
_PROXY_DATA = weakref.WeakKeyDictionary()


def _real_of(obj):
    """门面背后的真模块/真对象;不是门面就原样返回。

    取代原来的 `getattr(obj,'_real',obj)`:内部数据搬进 `_PROXY_DATA` 之后,
    实例上已经没有 `_real` 这个属性了。
    """
    try:
        return _PROXY_DATA[obj][1]
    except (KeyError,TypeError):
        return obj


def _is_child_module(label,value):
    """value 是不是"这个门面自己的子模块"(按模块名判定)。

    只有同一包里的子模块才递归放行(`tkinter.filedialog`、`ttkbootstrap.style`、
    `PIL.ImageDraw`…);`logging.os`、`tkinter.sys`、`random._os` 这种"外来模块句柄"
    一律拒 —— 它们就是插件读环境变量、绕开能力检查的入口。
    """
    name = getattr(value,'__name__',None) or ''
    return bool(label) and name.startswith(label + '.')


class _Proxy:
    """按白名单把真模块暴露给插件;能碰文件/网络/进程的入口换成检查过的包装。

    用 `__slots__`(且不留 `__dict__`),插件即便拿到门面也塞不进新属性;未知属性一律
    SandboxDenied(而不是 AttributeError),让插件作者一眼看出"是沙盒挡的"。

    第五批(bug 名 environ)在这里改了三件事:
      * 内部数据只存在 `_PROXY_DATA` 里,实例上一个属性都没有 —— `_real`/`_sb`/
        `_wrap` 这些名字直接撞 `__getattr__` 的"下划线名字不给";
      * 外来模块句柄不交出去(见 `_is_child_module`),只有门面自己的子模块才递归包;
      * 读环境变量的 `os.path.expandvars`/`expanduser` 在 path 门面的 deny 名单里。
    """

    __slots__ = ('__weakref__',)

    def __init__(self,sb,real,label,allow=None,wrap=None,deny=(),extra=None):
        merged = dict(wrap or {})
        if extra:
            merged.update(extra)          # 不涉及检查的固定属性(如 urllib.parse)
        _PROXY_DATA[self] = (
            sb,
            real,
            label,
            None if allow is None else frozenset(allow),
            merged,
            frozenset(deny or ()),
        )

    def __getattribute__(self,name):
        # `_d` 是第四批那种"内部数据槽"的名字:实例上已经没有它了,这里单独拦一下
        # 只是为了留一条 violation,告诉插件作者"这个名字是沙盒的东西"。
        if name == '_d':
            try:
                sb,_,label = _PROXY_DATA[self][:3]
            except (KeyError,TypeError):
                raise AttributeError(name)
            sb.violation('module_attr',f'插件不能访问 {label}._d',None)
            raise SandboxDenied(
                f'插件不能访问 {label}._d(那是门面的内部数据,拿走就等于把真模块交出去)')
        return object.__getattribute__(self,name)

    def __getattr__(self,item):
        try:
            sb,real,label,allow,wrap,deny = _PROXY_DATA[self]
        except KeyError:
            raise AttributeError(item)
        if item in deny:
            sb.violation('attr',f'{label}.{item} 已被沙盒禁用',None)
            raise SandboxDenied(f'{label}.{item} 被插件沙盒禁用')
        if item in wrap:
            return wrap[item]
        if item.startswith('__') and item.endswith('__'):
            raise AttributeError(item)
        allowed = allow is not None and item in allow
        if item.startswith('_') and not allowed:
            # 门面自己的内部名字(`_real`/`_sb`/`_label`/`_allow`/`_wrap`/`_deny`/
            # `_d`)在实例上已经不存在了,落到这里;真模块的私有属性(`random._os`)
            # 也一并挡掉 —— 它们不是给插件用的。
            sb.violation('attr',f'{label}.{item} 是门面内部名字,不给插件',None)
            raise SandboxDenied(f'{label}.{item} 是沙盒门面的内部名字,不给插件')
        if allow is not None and not allowed:
            sb.violation('attr',f'{label}.{item} 不在沙盒白名单里',None)
            raise SandboxDenied(f'{label}.{item} 不在插件沙盒白名单里')
        try:
            value = getattr(real,item)
        except AttributeError:
            raise AttributeError(f'{label} 没有属性 {item}')
        if isinstance(value,_types.ModuleType):
            if _is_child_module(label,value):
                child = _Proxy(sb,value,value.__name__)
                wrap[item] = child        # 同一个门面上只包一次
                return child
            sb.violation('module_attr',
                         f'{label}.{item} 会把真模块 {value.__name__} 交给插件',None)
            raise SandboxDenied(
                f'{label}.{item} 会把真实模块 {value.__name__} 交给插件'
                f'(可以据此读环境变量、绕开能力检查),已拒绝')
        return value

    def __dir__(self):
        try:
            data = _PROXY_DATA[self]
        except KeyError:
            return []
        return sorted(set(data[4]) | set(data[3] or ()))

    def __repr__(self):
        try:
            sb,_,label = _PROXY_DATA[self][:3]
        except KeyError:
            return '<sandbox module facade (detached)>'
        return f'<sandbox {label} for {sb.name}>'


class SandboxView:
    """给插件自己看的只读视图:能查"我有什么权限",改不了策略。"""

    __slots__ = ('name','can','describe','events')

    def __init__(self,sb):
        
        self.name = sb.name
        self.can = sb.can
        self.describe = sb.policy.describe
        self.events = sb.audit

    def __repr__(self):
        return f'<sandbox {self.name}: {self.describe()}>'


# ---------------------------------------------------------------- 判权层
#
# 2026-10 加固(第二批):把"判权数据"从 SandBox 实例上搬到模块私有的记账表里。
#
# 起因是逃逸样本(plugin/escape)最后两条得手:
#     * `box._policy_frozen = <unsafe 快照>` —— 判权快照是实例属性,谁都能换;
#     * `box.can = lambda cap, target=None: True` —— 判权入口本身也是实例属性,
#       换掉它以后**门面(check_fs/check_net/check_proc)和审计钩子会同时失明**,
#       因为它们都通过 box.can 判权。
# 上一批加固只锁了"策略数据"(Policy.freeze),没锁"判权入口"。
#
# 这里的做法:**判权只认 _AUTH 里的记账**,不认 SandBox 实例上任何可写属性:
#     * `_AUTH[id(box)]` 是模块私有字典(名字带下划线、插件只能内省去猜),
#       存封存时的策略快照、授权基线、以及**一份独立的** session 集合;
#     * `SandBox.can()` / 审计钩子都走 `_auth_can()`,读的是记账;
#       插件改 `box.policy` / `box._session` / `box._policy_frozen` 一律不影响判权,
#       只会在审计里多一条 `violation:tamper`(复核逻辑见 `_auth_tamper`);
#     * 审计钩子在装钩子时把 `_auth_can` 收进闭包,不再回调 `box.can` ——
#       所以 `box.can = lambda: True` 之后钩子照样按真实策略拒。
#
# 诚实说明:同进程里插件仍然可以直接改 `_AUTH` 这本账(它内省得到模块字典)。
# 这一步只是把"改三个普通实例属性就能静默拆掉沙盒"抬高成"必须先找到记账表,
# 而且改动会留痕";真正的边界仍然只能靠单独进程。

_AUTH = {}          # id(box) -> 判权记账:{'box','policy','frozen','org','session',...}


def _auth_entry(box,_auth=_AUTH):
    """取(必要时建)某个沙盒的判权记账。

    没封存的沙盒也建一条:里面直接引用**当前** policy / session,行为跟加固前
    完全一样(装载期宿主可以照常 grant)。封存时 `_auth_bind` 会把它们换成快照
    和独立副本 —— 从那一刻起插件手上的那份就只是"影子"了。

    第三批加固(module_globals):`_AUTH` 用默认参数**固化**。插件
    `g['_AUTH'] = {...}` 换不掉这本账了(它仍然能改这本账的**内容** ——
    那一层由 `_auth_domain` 的授权基线过滤兜着,见下)。
    """
    ent = _auth.get(id(box))
    if ent is not None and ent['box'] is box:
        return ent
    ent = {
        'box':box,
        'policy':box.policy,
        'frozen':None,
        'org':None,
        'session':box._session,
        'tamper_warned':set(),
    }
    _auth[id(box)] = ent                       # 值里留着 box,id 不会被复用
    return ent


def _auth_frozen(ent):
    """判权用的只读策略快照(封存后)或当前策略(封存前)。"""
    return ent['frozen'] if ent['frozen'] is not None else ent['policy']


def _auth_domain(ent,cap,_frozen=_auth_frozen):
    """某个能力当前允许的根/开关。(纯读,不碰文件系统。)

    写权限隐含读权限;授权基线之外的 session 条目由 `_auth_tamper` 记账忽略,
    所以插件往 `box._session` 里塞的授权不在这里出现。

    第三批加固(module_globals):这里原来**只信** `ent['session']`,而 `ent`
    就是 `_AUTH` 里那个普通 dict —— 插件内省拿到模块 globals 之后
    `ent['session']['fs:write'].add('C:\\\\')` 就能让判权当场认账
    (plugin/escape2 第 07 步,实测 can() 从 False 变 True)。现在判权只认
    **授权基线** `ent['org']` 里也有的条目:基线由 `_auth_snapshot_sets()`
    在封存和每次合法授权之后重建,插件手工塞进去的东西不在基线里,直接忽略。
    """
    pol = _frozen(ent)
    org = ent.get('org')
    if cap == 'fs:write':
        base = set(pol.fs_write)
        roots = tuple(pol.fs_write) + tuple(ent['session']['fs:write'])
        keep = (org or {}).get('fs:write')
    elif cap == 'fs:read':
        base = set(pol.fs_read) | set(pol.fs_write)
        roots = (tuple(pol.fs_read) + tuple(pol.fs_write)
                 + tuple(ent['session']['fs:read']))
        keep = (org or {}).get('fs:read')
    elif cap in ('net','proc'):
        if bool(getattr(pol,cap)):
            return True
        if org is None:                        # 未封存:装载期 grant 照旧生效
            return bool(ent['session'][cap])
        # 开关类:session 置真但基线里没有 => 判权不认(第 07 步就是这么堵的)
        return bool(ent['session'][cap]) and bool(org.get(cap))
    else:
        return None
    if keep is None:                           # 未封存:不过滤,行为与加固前一致
        return roots
    return tuple(r for r in roots if r in base or r in keep)


def _auth_can(ent,cap,target=None,_under=under,_domain=_auth_domain,
              _frozen=_auth_frozen):
    """唯一的判权实现:只读记账,绝不读 SandBox 实例上的可变属性。

    宿主门面、`SandBox.can()` 和审计钩子都调这里,所以"换掉 box.can"不再
    能让任何一道闸失明。

    第三批加固(module_globals):`under` / `_auth_domain` / `_auth_frozen` 全部
    改成**默认参数固化**。它们原来都是按全局名查找的,插件
    `g['under'] = lambda r,p: True`(plugin/escape2 第 08 步)或
    `g['_auth_entry'] = <unsafe 记账>`(第 09 步)就能把判权改掉;
    固化之后换 globals 里的名字影响不到这里已经绑好的引用。
    """
    pol = _frozen(ent)
    if pol.unsafe:
        return True
    if cap in ('fs:read','fs:write'):
        if target is None:
            return False
        roots = _domain(ent,cap)
        return any(_under(r,target) for r in roots)
    if cap in ('net','proc'):
        return _domain(ent,cap)
    raise ValueError(f'未知能力:{cap!r}')


def _auth_snapshot_sets(ent):
    """把记账里的三个集合整体换新:快照 + 授权基线 + **独立的** session 副本。

    独立副本很关键:加固前判权读的就是 `box._session` 本身,插件
    `box._session['fs:write'].add(r'C:\\')` 之后判权当场认账。
    """
    pol = ent['policy']
    ent['frozen'] = pol.snapshot()
    ent['org'] = {
        'fs:read':frozenset(pol.fs_read) | frozenset(ent['session']['fs:read']),
        'fs:write':frozenset(pol.fs_write) | frozenset(ent['session']['fs:write']),
        'net':bool(pol.net) or bool(ent['session']['net']),
        'proc':bool(pol.proc) or bool(ent['session']['proc']),
        'unsafe':bool(pol.unsafe)}
    ent['session'] = {
        'fs:read':set(ent['session']['fs:read']),
        'fs:write':set(ent['session']['fs:write']),
        'net':bool(ent['session']['net']),
        'proc':bool(ent['session']['proc'])}


def _auth_bind(box,_entry=_auth_entry,_snapshot=_auth_snapshot_sets,_frozen=_auth_frozen):
    """封存时把判权记账定下来,并把沙盒上的"影子副本"对齐到它。

    之后 `box.policy` / `box._policy_frozen` / `box._session` 都只是给人看的;
    判权读 `_AUTH`。注意顺序:先建快照,再让 `_policy_for_can()` 去读它。

    这里要**重取**一次 `box.policy`:共用 env_id 的两个插件在装载期会走
    `_merge_policy` 换掉 `policy` 对象,记账里那份可能已经是旧的 —— 不重取的话,
    合并后的策略会被漏掉(判权反而变得更严,`t_grants_applied_at_load` 一类
    授权就白发了)。
    """
    ent = _entry(box)
    ent['policy'] = box.policy                   # 合并策略可能换过对象,重取
    _snapshot(ent)
    box._policy_frozen = _frozen(ent)          # 影子:方便排查,不参与判权
    box._org = dict(ent['org'])                # 影子:同上
    return ent


def _auth_apply_grant(box,cap,target_root,_entry=_auth_entry,
                      _snapshot=_auth_snapshot_sets,_frozen=_auth_frozen):
    """宿主合法授权之后同步记账(否则判权读不到这次授权)。

    判权读 `ent['session']`,所以这里必须同时写记账;`box._session` 是影子副本,
    封存之后两者已经不是同一个对象了,要各自写一次,免得审计复核误报成篡改。
    """
    ent = _entry(box)
    if cap in ('fs:read','fs:write'):
        ent['session'][cap].add(target_root)
        box._session[cap].add(target_root)
        if cap == 'fs:write':
            ent['session']['fs:read'].add(target_root)
            box._session['fs:read'].add(target_root)
    elif cap in ('net','proc'):
        ent['session'][cap] = True
        box._session[cap] = True
    else:
        return
    if ent['frozen'] is not None:
        # 封存后仍有合法授权(用户在弹窗里点了"允许"):重建快照与基线
        _snapshot(ent)
        box._policy_frozen = _frozen(ent)
        box._org = dict(ent['org'])


def _auth_tamper(box,_entry=_auth_entry):
    """宿主没给过的东西被塞进 policy/_session:记一条审计(判权照旧不认)。

    去重按"哪一类"而不是"哪个具体路径":插件要是把策略改成整个盘,每个被问到
    的路径都会走到这里,按路径去重会瞬间刷出几百条记录。
    """
    ent = _entry(box)
    if ent['org'] is None:
        return
    live = box.policy                          # 插件能摸到的那份(影子)
    org = ent['org']
    tampered = []
    try:
        live_read = tuple(live.fs_read)
        live_write = tuple(live.fs_write)
    except Exception:
        tampered.append('policy 里的读写目录')
    else:
        if (live_read != tuple(ent['frozen'].fs_read)
                or live_write != tuple(ent['frozen'].fs_write)):
            tampered.append('policy 里的读写目录')
        for key in ('net','proc','unsafe'):
            if bool(getattr(live,key)) != bool(getattr(ent['frozen'],key)):
                tampered.append('policy.' + key)
    try:
        live_session = box._session
        for cap in ('fs:read','fs:write'):
            if set(live_session[cap]) - org[cap]:
                tampered.append(f'session 里的 {cap}')
        for cap in ('net','proc'):
            if live_session[cap] and not org[cap]:
                tampered.append(f'session 里的 {cap}')
    except Exception:
        tampered.append('session')
    if not tampered:
        return
    key = tuple(sorted(set(tampered)))
    if key not in ent['tamper_warned']:
        ent['tamper_warned'].add(key)
        box.violation('tamper',
                      '策略/授权被宿主之外的代码改动,判权已忽略:' + ','.join(key),
                      None)


# ---------------------------------------------------------------- 沙盒

class SandBox:
    """一个插件的策略 + 受控命名空间。

    宿主用法(见 b.py 的 Plugin):
        box = SandBox(env_id,name,plugin_dir,policy)
        box.set_ask(...); box.set_persist(...)
        box.attach_host(tkaapp)      # 决定 pro 是什么
        exec(code,box.namespace)
        box.seal()                   # 装载结束、插件代码开跑之前
    """

    def __init__(self,env_id,name,plugin_dir,policy,_entry=_auth_entry):
        self.env_id = env_id
        self.name = name
        self.policy = policy
        self.plugin_dir = os.path.abspath(plugin_dir)
        self._norm_dir = _norm(self.plugin_dir)      # 判断"这一帧是不是插件自己"用
        self._sealed_at = None                        # seal() 的时刻(判据见 guarded_names)
        self._policy_frozen = None                   # 影子:封存时的策略快照,不参与判权
        self._org = None                             # 影子:授权基线,不参与判权
        self._tamper_warned = set()                   # 篡改只报一次,别把审计刷爆
        self.namespace = {}
        self.events = []                 # 审计:最近的拒绝/授权
        self._session = {'fs:read':set(),'fs:write':set(),'net':False,'proc':False}
        self._never_ask = set()          # 用户明确点过"不再询问"的 (能力, 归一化目标)
        self._ask = None
        self._persist = None
        self._persist_deny = None
        self._host = None
        self._facade = None              # 插件真正拿到的 pro(白名单门面)
        self._local_modules = {}
        self._module_cache = {}
        self.__sealed = False            # 名字改写后是 _SandBox__sealed
        self._code_series = 0            # 第六批:注册过几棵 code 树(和账本对账)
        self._build_namespace()
        _entry(self)                     # 判权记账:装载期直接引用 policy/_session
        register_plugin_frames(self)     # 让审计钩子认得"这是插件的代码帧"
        # 第六批:顺便按 code 对象把"这个盒子"登记进身份账本。
        _ledger.remember_box(self)
        _PLUGIN_BOXES[id(self)] = self
        # 第六批:自己把插件的 init/command 源码读出来登记(见 _register_own_code)。
        # 这样**不需要宿主改一行代码**:b.py 照旧 `compile(...)` + `exec(...)`,
        # 只要它编译的是同一份源码,code 对象登记的就是它要执行的那一棵。
        self._register_own_code()

    # ---------------- 第六批:插件自己的代码身份 ----------------

    def _own_sources(self):
        """按 b.py 的读法,把插件 init/command 的源码取出来。

        与 `b.py` 的 `Plugin.__init__` 保持一致的三处细节:
          * manifest 是插件目录下的 `plugin.json`;
          * 有 `init_file` / `command_file` 时**文件内容覆盖**字符串字段;
          * 读进来的源码要做 `.replace('from b import *','',1)`(b.py 就是这么
            加工之后再编译的 —— 少这一步,编译出来的 code 对象就和宿主的不是
            同一棵,登记等于没登记)。
        读不到/解析不了都只是"这一批没认出来",不该拦住装载,所以整体吞异常。
        """
        try:
            path = os.path.join(self.plugin_dir,'plugin.json')
            with io.open(path,'r',encoding='utf-8') as fp:
                n = _json.load(fp)
            if not isinstance(n,dict):
                return ()
            out = []
            for src_key,file_key in (('init','init_file'),('command','command_file')):
                src = n.get(src_key,'') or ''
                src = str(src).replace('from b import *','',1)
                fname = n.get(file_key,'') or ''
                if fname:
                    try:
                        with io.open(os.path.join(self.plugin_dir,str(fname)),
                                     'r',encoding='utf-8') as fp:
                            src = fp.read().replace('from b import *','',1)
                    except Exception:
                        print(f'[沙盒] 读取 {fname} 失败(第六批身份登记跳过这一段)')
                if src.strip():
                    out.append((src_key,src))
            return tuple(out)
        except Exception:
            return ()

    def _register_own_code(self):
        """把本插件 init / command 的源码编译成 code 树并登记身份。

        登记的是**宿主将要执行的那一棵**(同一份源码 + 同一个文件名
        `<plugin {name} init>`,CPython 的 code 对象按内容而非时间区分),
        所以这一步不改变任何权限判定,只是让审计钩子有身份可认。

        只在"插件目录 + manifest 都在"时管用;宿主若走 `exec_plugin_code()`
        那条路,由那个方法自己登记,不依赖这里。
        """
        for kind,src in self._own_sources():
            try:
                code = compile(src,f'<plugin {self.name} {kind}>','exec')
            except Exception as e:
                print(f'[沙盒] 插件 {self.name} 的 {kind} 源码无法编译,'
                      f'身份登记跳过:{e}')
                continue
            self.register_plugin_code(code)

    # ---------------- 封存后不许再换判权入口 ----------------

    def guarded_names(self):
        """封存后连宿主都不该再改的名字。

        最要紧的是 `can`:门面和审计钩子原来都回调 `box.can(...)`,插件只要
        `box.can = lambda cap, target=None: True` 就能让两道闸同时失明
        (逃逸样本第 08 步)。判权已经搬到 `_AUTH` 记账里了,这里再加一道
        "封存后不许再绑",把静默改写变成会报警的 SandboxDenied ——
        普通插件没有理由在装载之后换掉沙盒的判权入口。

        `violation` / `note` / `events` 是同一类问题的审计面:钩子和门面原来都
        回调 `box.violation(...)` 记拦截,插件把它换成 no-op 之后"拦得住但记不下"
        (逃逸样本第 09 步),出事就没有日志可查 —— 所以这三个也一起锁。

        注意**没有**锁 `_host` / `_facade` / `_ask` / `_persist`:那些是宿主接口,
        封存之后宿主仍要合法地重新挂(`b.py` 的 `Plugin.run()` 每次执行命令都会
        再 `attach_host` 一次,换一份新的 pro 门面)。插件改了它们也拿不到额外
        能力(空间里只有 `pro`,而门面背后是不是真宿主由宿主自己决定),
        为它牺牲一条正常路径不值。
        """
        return frozenset((
            'can','violation','note','events',
            '_policy_frozen','_org','_session','policy','_sealed_at',
            'namespace','_norm_dir','plugin_dir','name','env_id',
        ))

    def __setattr__(self,name,value):
        # 注意:这里只查"名字 + 是否已封存",不查值是什么
        # 插件想改它,必须走 object.__setattr__ 硬来 —— 而判权读的是 _AUTH,
        # 硬来的结果只是审计里多一条 violation:tamper。
        if name in SandBox.guarded_names(self) and getattr(self,'_sealed_at',None) is not None:
            raise SandboxDenied(
                f'插件 {self.name} 的沙盒已封存,不能再改 {name}'
                f'(判权入口/策略在封存之后就不可变)')
        object.__setattr__(self,name,value)

    # ---------------- 挡住"插件直接调宿主接口" ----------------

    def _plugin_caller(self):
        """栈上有插件代码帧就返回它;没有(宿主自己在调)返回 None。

        这是"插件偷到宿主凭据也没用"的关键:凭据管的是"你是不是那个对象",
        这里管的是"这次调用是不是从插件代码里发出的"。插件在同一个解释器里
        必然有插件帧,所以 grant/set_unsafe/create 这类宿主入口一律能识破。
        """
        try:
            frame = sys._getframe(1)          # 从调用者开始扫
        except ValueError:
            return None
        depth = 0
        while frame is not None and depth < 500:
            box = _box_for_frame(frame.f_code.co_filename,frame.f_code)
            if box is not None:
                return box
            frame = frame.f_back
            depth += 1
        return None

    def refuse_plugin_caller(self,what):
        """插件调用宿主专用入口:记审计并拒绝。"""
        caller = self._plugin_caller()
        self.violation(what,
                       f'插件代码帧调用了宿主专用入口({what}),已拒绝',
                       getattr(caller,'name',None))
        raise SandboxDenied(
            f'插件 {self.name} 不能从插件代码里调用 {what}(只有宿主能)')

    # ---------------- 封存与授权 ----------------

    @property
    def frame_tag(self):
        """b.py 用 <plugin 名字 init/command> 当编译出来的文件名,靠它认插件帧。"""
        return f'<plugin {self.name} '

    def _guarded(self,func,*args,_auth=None,_entry=_auth_entry,_can=_auth_can,
                 _tamper=_auth_tamper,_allow_plugin_caller=False,**kwargs):
        """执行"沙盒 / 宿主替插件做的真实调用"。

        这期间审计钩子放行:权限刚刚已经查过了。顺带也避免了钩子自己的
        策略检查(realpath 会触发 os.lstat 审计事件)递归回来。

        但"放行"不能无条件 —— 门面里的检查原来是调 `self.can()`,而 `can`
        是实例属性:插件 `box.can = lambda cap, target=None: True` 之后门面就
        自己把这次真实 `open` 当"已授权",而钩子又因为 depth>0 直接放行,
        两道闸一起失效(2026-10 实测到的洞)。所以这里先拿 `_auth_can()` 复核
        一遍(读的是 `_AUTH` 记账,插件换不掉):**真授权才豁免**,
        没授权就根本不进 `_guarded`,让真实调用不做、由钩子/门面去拒。

        `auth=(能力, 目标)` 为 None 表示这次调用不涉及插件自己的能力判定
        (例如宿主自己的持久化回调),照旧无条件豁免。

        第八批加固(bug 名 `guarded_frame`,见文件头该节)
        --------------------------------------------------
        上面那句"无条件豁免"原来**没有任何身份检查** —— 而"栈上有没有
        `_guarded` 的 code 对象"正是审计钩子判断"这是不是门面替插件做的事"
        的**唯一**依据(`_hook_in_facade_frame`)。于是插件只要
        `box._guarded(lambda: open(r'C:\\Windows\\win.ini'))`,
        传 `_auth=None` 就跳过上面的复核,凭空造出一个被钩子信任的"门面帧",
        越权 `open` 在里面当场成功(`dsh/guarded_frame_probe.py` 有干净复现:
        对照组直接读 = BLOCK,这一组 = 读到了;`os.system` 同样跑通)。

        这里补一道身份判定:**直接调用者是不是插件代码**。

        为什么是"直接调用者"而不是 `_plugin_caller()`(栈上有没有插件帧):
        合法的宿主路径里,插件帧**本来就在栈上** —— 插件调 `pro.open(...)`
        时是  插件帧 -> `fs_open` -> `_guarded`,插件调 `import a`
        时是      插件帧 -> `_load_local_module` -> `_guarded`。
        拿"栈上有插件帧"当判据会把这两条正常功能一起打死(实测:会误伤
        `import` 插件自己的本地模块)。而插件**直接**调 `box._guarded(...)`
        时,`_guarded` 的直接调用者就是插件帧本身 —— 两者可以精确分开。

        另外要区分两种插件来源的 `func`:
          * `net_guard` / `proc_guard` 的 `func` 是**插件提供的可调用对象**
            (`os.system` 之类),那时 `_auth` 非 None,已经过 `_auth_can` 复核,
            所以本检查**不用管**它(合法路径,而且 `_auth` 才是它的闸);
          * 插件自己调 `_guarded(fn)`:这时 `_auth` 一定是 None(插件拿不到
            `_auth_pair` 那种内部口径),绕过整个复核 —— 这才是要堵的。
        因此判据取"**插件直接调用 + `_auth is None`**",两条都要满足。

        `_allow_plugin_caller=True` 是给宿主**明知**要从插件帧里调、又确实
        不需要能力判定的路径留的口子(目前没有这样的调用点;`_load_local_module`
        读的是插件目录自己的文件,直接调用者是宿主方法,不受本检查影响)。
        将来真要加,必须在这里写明理由 —— 这个口子等于自愿放弃这道闸。
        """
        if (_auth is None and not _allow_plugin_caller
                and _plugin_code_at(1)):
            self.violation(
                'guarded_frame',
                '插件直接调用了 _guarded():那是审计钩子"门面帧"判据的来源,'
                '不经过门面就不许用它豁免判权,已拒绝',None)
            raise SandboxDenied(
                f'插件 {self.name} 不能直接调用 _guarded()'
                f'(它会造出一个被审计钩子信任的"门面帧",从而绕开能力检查)')
        auth = _auth
        if auth is not None:
            cap,target = auth

            ent = _entry(self)
            if not _can(ent,cap,target):
                _tamper(self)
                self.violation(
                    'guard',
                    f'门面准备执行 {cap} 操作,但记账里并没有这份授权(判权入口可能被换过)',
                    target)
                raise SandboxDenied(
                    f'插件 {self.name} 的 {cap} 操作没有授权'
                    f'(判权入口在封存后被改动过),已拒绝:{target}')
        _facade_enter()
        try:
            
            return func(*args,**kwargs)
        finally:
            _facade_exit()

    def seal(self):
        """冻结策略。之后连宿主也不能再 grant,插件更不行。

        同时做三件防篡改的事:
          * `_auth_bind()` 把判权记账定下来 —— 之后 can()/审计钩子只认 `_AUTH`
            里的快照与独立 session 副本,插件把 `box.policy.fs_read` 改成整个盘、
            换掉 `box._policy_frozen`、或者 `box.can = lambda: True` 都没用
            (第三条会当场被 guarded_names 拒掉,硬来也只留一条审计);
          * `box.policy` / `box._policy_frozen` / `box._session` 降级成"影子":
            给人看、给宿主记账用,不再参与判权;
          * `ent['org']` 记下授权基线(`policy ∪ 装载期已发的 session` 授权):
            基线之外的 session 条目记一条 `violation:tamper`,判权仍然忽略它
            (`t_grants_applied_at_load` 撞过误报,所以一定要把装载期授权算进基线)。
        """
        self.policy.freeze()
        _auth_bind(self)
        self._sealed_at = True
        self.__sealed = True
        self.note('seal','*',None,f'策略冻结:{self.policy.describe()}')

    def is_sealed(self):
        return self.__sealed

    def _policy_for_can(self,_entry=_auth_entry,_tamper=_auth_tamper):
        """判权读哪份策略:封存后只认 `_AUTH` 里的快照。

        实例上的 `_policy_frozen` 只是影子(方便排查);顺手把"封存前就被改过的
        policy"和"封存后被塞东西的 _session"对照一遍 —— 插件改这两个地方都不会
        改变判权结果,只会在审计里留下一条记录。
        """
        ent = _entry(self)
        if ent['frozen'] is None:
            return self.policy
        _tamper(self)
        return ent['frozen']

    def grant(self,*args,_host_token=None,**kwargs):
        """只有宿主(持有 _HOST_TOKEN 的一方)能调用。

        插件调用会走到这里然后被拒 —— plugin/nb/a.py 里那几行
        "env_dict.grant(__env_id__,[...])" 就是想走这条路。

        注意:光比 _HOST_TOKEN 还不够。插件跟宿主同进程,那个对象它摸得到
        (逃逸样本就是从 `type(pro.menu).__init__.__globals__` 里拿的),
        所以这里再查一次"调用栈上有没有插件帧"。宿主自己调时栈上是干净的。
        """
        if _host_token is not _HOST_TOKEN:
            self.violation('grant','插件试图给自己授权',None)
            raise SandboxDenied(f'插件 {self.name} 不能给自己授权(只有宿主能)')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('grant')
        if self.is_sealed():
            raise SandboxDenied(f'插件 {self.name} 的沙盒已封存,不能再改策略')
        cap = args[0] if args else kwargs.get('cap')
        target = args[1] if len(args) > 1 else kwargs.get('target')
        self._apply_grant(cap,target,persist=False)
        self.note('grant','*',target,f'宿主授予 {cap}')

    def set_unsafe(self,value=True,_host_token=None):
        """把插件从沙盒里放出来。只有宿主能调,而且必须已经得到用户确认。

        同样要过"栈上没有插件帧"这一关:逃逸样本用偷来的凭据调这句话,
        就能把 policy.unsafe 置真、让审计钩子对所有事件失明。
        """
        if _host_token is not _HOST_TOKEN:
            self.violation('set_unsafe','插件试图解除自己的沙盒限制',None)
            raise SandboxDenied(f'插件 {self.name} 不能解除自己的沙盒限制')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('set_unsafe')
        if self.is_sealed():
            raise SandboxDenied(f'插件 {self.name} 的沙盒已封存,不能再改')
        self.policy.unsafe = bool(value)
        self.note('unsafe','*',None,f'unsafe={bool(value)}')

    def _apply_grant(self,cap,target,persist=False):
        if cap in ('fs:read','fs:write'):
            root = self._grant_root(target)
            self._session[cap].add(root)
            if cap == 'fs:write':
                self._session['fs:read'].add(root)
            self.policy.warnings.append(f'宿主额外授予 {cap} = {root}')
        elif cap in ('net','proc'):
            self._session[cap] = True
        else:
            raise SandboxDenied(f'没有这种能力:{cap!r}')
        # 判权读的是 _AUTH 记账,所以合法授权也必须同步进去(否则授权不生效)
        root = self._grant_root(target) if cap in ('fs:read','fs:write') else None
        _auth_apply_grant(self,cap,root)
        if persist and self._persist is not None:
            try:
                self._persist(self.name,cap,self._grant_root(target) if target else True)
            except Exception:
                logging.exception('保存插件授权失败')

    def _grant_root(self,target):
        if not target:
            return None
        target = os.path.abspath(os.fspath(target))
        if os.path.isdir(target):
            return target
        parent = os.path.dirname(target)
        return parent or target

    # ---------------- 宿主接口 ----------------

    def set_ask(self,func):
        """func(sandbox,cap,target,detail) -> 'yes'/'session'/'always'/其它=拒绝"""
        self._ask = func

    def set_persist(self,func):
        """func(plugin_name,cap,target) -> None:把授权写进 config.json。"""
        self._persist = func

    def set_persist_deny(self,func):
        """func(plugin_name,cap,target) -> None:把"不再询问"写进 config.json。

        与 `set_persist` 对称:授权和永久拒绝都要落盘,否则重启后用户又会被
        同一个问题反复问(或者反过来,拒绝被忘掉)。
        """
        self._persist_deny = func

    def remember_denied(self,cap,target,_host_token=None):
        """宿主把 config.json 里记着的"不再询问"喂回来(装载时调一次)。

        只有宿主能调:插件自己调等于"把别人的询问静音",和 `grant()` 一样属于
        越权入口,所以同样要凭据 + 栈上没有插件帧两道关。
        """
        if _host_token is not _HOST_TOKEN:
            self.violation('remember_denied',
                           '插件试图制造"不再询问"记录',f'{cap} {target or ""}')
            raise SandboxDenied(f'插件 {self.name} 不能伪造"不再询问"记录(只有宿主能)')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('remember_denied')
        self._never_ask.add(self._ask_key(cap,target))
        self.note('ask_never_restored',cap,target,'按 config.json 恢复"不再询问"')
        return True

    def attach_host(self,tkaapp,facade=None,**kwargs):
        """把宿主以"白名单门面"的形式交给插件(不再是整个 Tkapp)。"""
        self._host = tkaapp
        if tkaapp is None:
            return None
        self._facade = HostFacade(self,tkaapp) if facade is None else facade
        self.namespace['pro'] = self._facade
        return self._facade

    def audit(self,limit=20):
        return list(self.events[-limit:])

    def note(self,action,cap,target,detail=''):
        rec = {'plugin':self.name,'action':action,'cap':cap,
               'target':str(target) if target is not None else None,'detail':detail}
        self.events.append(rec)
        if len(self.events) > 200:
            del self.events[:100]
        return rec

    def violation(self,action,detail,target):
        self.note('violation:'+action,'*',target,detail)
        _facade_enter()
        try:
            logging.warning('插件 %s 触发沙盒拦截:%s(%s)',self.name,detail,target)
            print(f'[沙盒] 插件 {self.name}:{detail}')
        finally:
            _facade_exit()

    # ---------------- 能力判定 ----------------

    def can(self,cap,target=None,_entry=_auth_entry,_can=_auth_can,
            _tamper=_auth_tamper):
        """现在是否允许,不弹窗、不抛异常(插件自查与宿主 UI 都用它)。

        判权**不在本方法里**:`_auth_can()` 读的是模块私有的 `_AUTH` 记账,
        不是这个实例上的属性。所以就算插件把 `box.can` 换成 `lambda: True`,
        也只是换掉了一个没人信的入口(而且封存后这么赋值会被直接拒) ——
        门面、审计钩子都走 `_auth_can`。
        """
        ent = _entry(self)
        if ent['frozen'] is not None:
            _tamper(self)
        return _can(ent,cap,target)

    def _ask_key(self,cap,target):
        """弹窗去重/永久拒绝用的凭证:`(能力, 归一化目录)`。

        路径用 `_norm`(绝对+解析符号链接+大小写统一);目标是文件时归到**所在目录**,
        和 `_grant_root` 的口径一致 —— 用户点"不再询问"针对的是那个目录/那个能力,
        不该被同目录里的另一个文件绕过去。
        """
        if not target:
            return (cap,'')
        if cap in ('fs:read','fs:write'):
            root = self._grant_root(target) or _norm(target)
            return (cap,_norm(root) or str(target))
        return (cap,str(target))

    def _ask_user(self,cap,target,detail):
        """问用户要不要放行这一次。

        第七批之后(bug 名 `ask_once`):**每次越权都弹窗**,只有用户明确答
        `ASK_NEVER`(宿主的"不再询问")才停止 —— 那时记进 `_never_ask` 并持久化。

        以前这里用 `_asked` 集合"同类只弹一次",后果是第一次答"拒绝"或
        "只允许本次"之后,第二次就被**静默拒绝**,用户再也没机会改主意
        (实测见 `dsh/ask_repeat_probe.py` 与 SANDBOX.md 的 `ask_once` 条目)。

        安全上这不是放宽:每次都重新问,只有"答 yes 的那一次"才放行;反而是
        以前那条"弹过就不再问"让人误以为沙盒坏了。真机连弹窗由用户的
        "不再询问"收口,不靠静默拒绝兜底。
        """
        pol = self._policy_for_can()
        if pol.unsafe:
            return True
        if not pol.ask or self._ask is None:
            return False
        if threading.current_thread() is not threading.main_thread():
            self.note('ask_skipped',cap,target,'不在主线程,不能弹窗,直接拒绝')
            return False
        key = self._ask_key(cap,target)
        if key in self._never_ask:
            self.note('ask_muted',cap,target,'你之前选了"不再询问",直接拒绝')
            return False
        try:
            ans = self._guarded(self._ask,self,cap,target,detail)
        except Exception:
            logging.exception('插件沙盒的授权询问失败,按拒绝处理')
            return False
        if ans == ASK_NEVER:
            self._never_ask.add(key)
            self.note('ask_never',cap,target,'用户点了"不再询问",以后这一类不再弹窗')
            if self._persist_deny is not None:
                try:
                    self._persist_deny(self.name,cap,
                                       self._grant_root(target) if target else None)
                except Exception:
                    logging.exception('保存"不再询问"失败')
            return False
        if ans == ASK_YES:
            self.note('grant_once',cap,target,detail)
            return True
        if ans in (ASK_SESSION,ASK_ALWAYS):
            self._apply_grant(cap,target,persist=(ans == ASK_ALWAYS))
            self.note('grant_'+ans,cap,target,detail)
            return True
        # 其它答案(含宿主把弹窗关掉):只拒绝这一次,**不记账** —— 下次照样问。
        self.note('denied_by_user',cap,target,detail)
        return False

    def deny(self,cap,target,what):
        self.violation('deny',f'{what or "操作"}需要能力 {cap},未获授权',target)
        raise SandboxDenied(
            f'插件 {self.name} 的 {what or "操作"} 需要 {cap} 能力,'
            f'而它没有被授权:{target if target is not None else ""}')

    def check_fs(self,path,write=False,what='',_entry=_auth_entry,_can=_auth_can):
        """检查路径;返回 `(路径, 是否记账授权)`。

        判权走 `_auth_can()`(读 `_AUTH` 记账),**不调 `self.can`** ——
        插件换掉 `box.can` 只能骗到自己,骗不到门面。

        第二个返回值表示"这份授权是不是记账里真有的"(策略/基线/合法 session):
        用户在弹窗里点"只允许本次"属于**不落账**的一次性放行,门面执行那一次
        真实调用时不该再要求记账里有它(`test_sandbox_facade.py` 的
        `t_audit_allows_own_dir_and_facade` 专门盯着这条),但也不能因此就被
        当成"长期授权"。
        """
        if isinstance(path,int):
            self.violation('fd','不支持用文件描述符访问文件',path)
            raise SandboxDenied('沙盒不允许用文件描述符(fd)访问文件')
        cap = 'fs:write' if write else 'fs:read'
        if _can(_entry(self),cap,path):
            return path,True
        if self._ask_user(cap,path,what or ('写入文件' if write else '读取文件')):
            return path,False
        self.deny(cap,path,what)

    def check_net(self,what='网络访问',_entry=_auth_entry,_can=_auth_can):
        """返回 `(是否放行, 授权是否已经落账)`。

        第二个返回值是给 `_guarded` 的复核用的:用户答"允许本次"(ASK_YES)时
        **不落账**,复核就该跳过 —— 否则"用户已经同意"的那一次会被执行前
        复核自己打死(bug 名 `ask_once_exec`)。落账的授权才需要复核。
        """
        if _can(_entry(self),'net'):
            return True,True
        if self._ask_user('net',None,what):
            return True,False          # 一次性放行,没落账
        self.deny('net',None,what)

    def check_proc(self,what='启动外部进程',_entry=_auth_entry,_can=_auth_can):
        """同 `check_net`:第二个返回值表示授权是否落账。"""
        if _can(_entry(self),'proc'):
            return True,True
        if self._ask_user('proc',None,what):
            return True,False          # 一次性放行,没落账
        self.deny('proc',None,what)

    def _auth_pair(self,allowed,durable,cap,target=None):
        """给 `_guarded` 的复核参数:只有**记账里真有的**授权才需要(也才应该)复核。

        没授权、或者只是"允许本次"这种一次性放行,都返回 None —— 让 `_guarded`
        不重复判一次(它的 `_can` 读的是同一份记账,重复判只会把已经放行的那一次
        再拒掉,而且会留下"判权入口可能被换过"这种吓人的假警报)。
        """
        return (cap,target) if (allowed and durable) else None

    # ---------------- 文件操作(受控) ----------------

    def fs_open(self,file,mode='r',*args,**kwargs):
        if isinstance(file,int):
            self.violation('fd','不支持用文件描述符打开文件',file)
            raise SandboxDenied('沙盒不允许用文件描述符(fd)打开文件')
        write = _mode_writes(mode)
        cap = 'fs:write' if write else 'fs:read'
        path,durable = self.check_fs(file,write,f'open({mode!r})')
        return self._guarded(_builtins.open,path,mode,*args,
                             _auth=self._auth_pair(True,durable,cap,path),**kwargs)

    def fs_listdir(self,path='.'):
        p,durable = self.check_fs(path,False,'listdir')
        return self._guarded(os.listdir,p,_auth=self._auth_pair(True,durable,'fs:read',p))

    def fs_scandir(self,path='.'):
        p,durable = self.check_fs(path,False,'scandir')
        return self._guarded(lambda q:list(os.scandir(q)),p,
                             _auth=self._auth_pair(True,durable,'fs:read',p))

    def fs_stat(self,path,**kwargs):
        p,durable = self.check_fs(path,False,'stat')
        return self._guarded(lambda *a,**k:os.stat(*a,**k),p,
                             _auth=self._auth_pair(True,durable,'fs:read',p),**kwargs)

    def fs_walk(self,top,*args,**kwargs):
        top,durable = self.check_fs(top,False,'walk')
        # 开走之前按记账复核一次(一次性放行不落账,所以可能为 None)
        self._guarded(lambda:None,
                      _auth=self._auth_pair(True,durable,'fs:read',top))

        def _gen():
            for root,dirs,files in os.walk(top,*args,**kwargs):
                dirs[:] = [d for d in dirs if self.can('fs:read',os.path.join(root,d))]
                yield root,dirs,files
        return _gen()

    def fs_write_call(self,func,what,path,*args,**kwargs):
        p,durable = self.check_fs(path,True,what)
        return self._guarded(func,p,*args,
                             _auth=self._auth_pair(True,durable,'fs:write',p),**kwargs)

    def fs_rename(self,src,dst,**kwargs):
        src,_ = self.check_fs(src,True,'rename')
        dst,durable = self.check_fs(dst,True,'rename')
        auth = self._auth_pair(True,durable,'fs:write',dst)
        if kwargs.pop('replace',False):
            return self._guarded(os.replace,src,dst,_auth=auth)
        return self._guarded(os.rename,src,dst,_auth=auth)

    def fs_probe(self,func,path,*args,**kwargs):
        """只读探测(exists/isfile/isdir/getsize):没权限就安静地返回 False/0。

        探测到处弹窗会很烦;这里不抛异常也不问,只记一条审计。
        """
        if not self.can('fs:read',path):
            self.note('probe_denied','fs:read',path,'只读探测被拒,返回空值')
            return False
        try:
            return func(path,*args,**kwargs)
        except OSError:
            return False

    # ---------------- 网络/进程 ----------------

    def net_guard(self,func,what):
        @functools.wraps(func)
        def wrapper(*args,**kwargs):
            ok,durable = self.check_net(what)
            return self._guarded(func,*args,
                                 _auth=self._auth_pair(ok,durable,'net'),**kwargs)
        return wrapper

    def proc_guard(self,func,what):
        @functools.wraps(func)
        def wrapper(*args,**kwargs):
            ok,durable = self.check_proc(what)
            return self._guarded(func,*args,
                                 _auth=self._auth_pair(ok,durable,'proc'),**kwargs)
        return wrapper

    # ---------------- 模块门面 ----------------

    def os_module(self):
        wrap = {
            'open':self.fs_open,
            'listdir':self.fs_listdir,
            'scandir':self.fs_scandir,
            'stat':self.fs_stat,
            'walk':self.fs_walk,
            'mkdir':lambda p,*a,**k:self.fs_write_call(os.mkdir,'mkdir',p,*a,**k),
            'makedirs':lambda p,*a,**k:self.fs_write_call(os.makedirs,'makedirs',p,*a,**k),
            'remove':lambda p,*a,**k:self.fs_write_call(os.remove,'remove',p,*a,**k),
            'unlink':lambda p,*a,**k:self.fs_write_call(os.remove,'unlink',p,*a,**k),
            'rmdir':lambda p,*a,**k:self.fs_write_call(os.rmdir,'rmdir',p,*a,**k),
            'removedirs':lambda p,*a,**k:self.fs_write_call(os.removedirs,'removedirs',p,*a,**k),
            'utime':lambda p,*a,**k:self.fs_write_call(os.utime,'utime',p,*a,**k),
            'rename':self.fs_rename,
            'replace':lambda s,d:self.fs_rename(s,d,replace=True),
            'system':self.proc_guard(os.system,'os.system'),
            'popen':self.proc_guard(os.popen,'os.popen'),
            'startfile':self.proc_guard(os.startfile,'os.startfile'),
            'path':self.path_module(),
        }
        allow = {'name','sep','altsep','pathsep','linesep','curdir','pardir','devnull','extsep',
                 'getcwd','getcwdb','getpid','cpu_count','get_terminal_size','fspath','PathLike',
                 'error','stat_result'}
        deny = {'environ','putenv','setenv','unsetenv','getenv','chdir','chroot','chmod','chown',
                'link','symlink','readlink','kill','abort','_exit','fork','forkpty','setsid',
                'setuid','setgid','execv','execve','execl','execle','execlp','execvp','execvpe',
                'execlpe','spawnv','spawnve','spawnl','spawnle','spawnlp','spawnvpe','spawnlpe',
                'posix_spawn','posix_spawnp','add_dll_directory','nice','waitpid','wait',
                'dup','dup2','fdopen','close','openpty','pipe'}
        return _Proxy(self,os,'os',allow=allow,wrap=wrap,deny=deny)

    def path_module(self):
        wrap = {
            'exists':lambda p:self.fs_probe(os.path.exists,p),
            'isfile':lambda p:self.fs_probe(os.path.isfile,p),
            'isdir':lambda p:self.fs_probe(os.path.isdir,p),
            'islink':lambda p:self.fs_probe(os.path.islink,p),
            'getsize':lambda p:self.fs_probe(os.path.getsize,p) or 0,
            'getmtime':lambda p:self.fs_probe(os.path.getmtime,p) or 0,
            'getctime':lambda p:self.fs_probe(os.path.getctime,p) or 0,
            'getatime':lambda p:self.fs_probe(os.path.getatime,p) or 0,
            'realpath':lambda p:self.fs_probe(os.path.realpath,p) or os.path.abspath(str(p)),
        }
        allow = {'join','dirname','basename','splitext','split','splitdrive','abspath',
                 'normpath','normcase','isabs','commonpath',
                 'commonprefix','relpath','sep','altsep','pathsep','curdir','pardir','extsep'}
        # 第五批(bug 名 environ):`expandvars`/`expanduser` 本来就是"读环境变量"的入口
        # (`%PATH%`、`~`),放在 allow 名单里等于把 os.environ 借给插件 —— 读环境变量
        # 不产生审计事件,所以只能在门面这里拒。要展开就自己 `os.path.join`,别读环境。
        return _Proxy(self,os.path,'os.path',allow=allow,wrap=wrap,
                      deny={'sameopenfile','samestat','samefile','lexists',
                            'expandvars','expanduser'})

    def sys_module(self):
        wrap = {'argv':list(sys.argv)}
        allow = {'version','version_info','platform','maxsize','float_info','int_info',
                 'byteorder','getdefaultencoding','getfilesystemencoding','getrecursionlimit',
                 'setrecursionlimit','getswitchinterval','stdout','stderr','stdin',
                 'executable','hexversion','api_version','implementation'}
        deny = {'modules','path','meta_path','path_hooks','path_importer_cache','exit','_getframe',
                'settrace','setprofile','addaudithook','breakpointhook','displayhook',
                'excepthook','unraisablehook','__interactivehook__','intern','getrefcount',
                'set_coroutine_origin_tracking_depth','_xoptions','dont_write_bytecode'}
        return _Proxy(self,sys,'sys',allow=allow,wrap=wrap,deny=deny)

    def io_module(self):
        allow = {'BytesIO','StringIO','BufferedReader','BufferedWriter','BufferedRWPair',
                 'TextIOWrapper','UnsupportedOperation','SEEK_SET','SEEK_CUR','SEEK_END',
                 'DEFAULT_BUFFER_SIZE','IOBase','BlockingIOError'}
        return _Proxy(self,io,'io',allow=allow,wrap={'open':self.fs_open})

    def builtins_view(self):
        """import builtins 拿到的是"受控内置"的视图,不是真的 builtins 模块。"""
        ns = self.restricted_builtins()

        class _B:
            def __getattr__(self,item):
                if item in ns:
                    return ns[item]
                raise AttributeError(item)

            def __dir__(self):
                return sorted(ns)
        return _B()

    def image_module(self):
        wrap = {'open':self.guarded_image_open}
        return _Proxy(self,_PILImage,'PIL.Image',wrap=wrap)

    def mutagen_module(self):
        wrap = {
            'File':self.guarded_mutagen_file,
            'flac':_Proxy(self,mutagen.flac,'mutagen.flac',
                          wrap={'FLAC':self.guarded_mutagen_file}),
            'id3':_Proxy(self,mutagen.id3,'mutagen.id3',
                         wrap={'ID3':self.guarded_mutagen_file}),
        }
        return _Proxy(self,mutagen,'mutagen',wrap=wrap)

    def guarded_image_open(self,fp,*args,**kwargs):
        auth = None
        if isinstance(fp,(str,bytes,os.PathLike)):
            fp,durable = self.check_fs(fp,False,'PIL.Image.open')
            auth = self._auth_pair(True,durable,'fs:read',fp)
        return self._guarded(_PILImage.open,fp,*args,_auth=auth,**kwargs)

    def guarded_mutagen_file(self,filething,*args,**kwargs):
        # 注意:mutagen.File 自己会去 open()那一次走的是审计钩子(这里是宿主帧,
        # 不受影响),所以这里只需要放行"插件把路径交给门面"这一步。
        auth = None
        if isinstance(filething,(str,bytes,os.PathLike)):
            filething,durable = self.check_fs(filething,False,'读取音频标签')
            auth = self._auth_pair(True,durable,'fs:read',filething)
        return self._guarded(mutagen.File,filething,*args,_auth=auth,**kwargs)

    def socket_module(self):
        allow = {'AF_INET','AF_INET6','AF_UNIX','SOCK_STREAM','SOCK_DGRAM','SOL_SOCKET',
                 'SO_REUSEADDR','IPPROTO_TCP','has_ipv6','gaierror','error','timeout',
                 'getdefaulttimeout','setdefaulttimeout','gethostname'}
        wrap = {
            'socket':self.net_guard(socket.socket,'创建 socket'),
            'create_connection':self.net_guard(socket.create_connection,'socket.create_connection'),
            'getaddrinfo':self.net_guard(socket.getaddrinfo,'DNS 查询'),
            'gethostbyname':self.net_guard(socket.gethostbyname,'DNS 查询'),
            'create_server':self.net_guard(socket.create_server,'创建监听'),
        }
        return _Proxy(self,socket,'socket',allow=allow,wrap=wrap)

    def urllib_module(self):
        request = _Proxy(self,urllib.request,'urllib.request',
                         allow={'Request','build_opener','url2pathname'},
                         wrap={'urlopen':self.net_guard(urllib.request.urlopen,'urlopen'),
                               'urlretrieve':self.net_guard(urllib.request.urlretrieve,'urlretrieve')},
                         deny={'urlcleanup','getproxies','proxy_bypass','install_opener',
                               'FancyURLopener','URLopener','pathname2url'})
        # 第五批(bug 名 environ):`urllib.parse` 原来给的是真模块 —— 真模块句柄一律换成
        # 安全门面(真模块的全局里挂着别的东西,句柄交出去就等于绕开这一层)。
        return _Proxy(self,urllib,'urllib',
                      extra={'request':request,
                             'parse':self.safe_module('urllib.parse',urllib.parse)})

    def http_module(self):
        client = _Proxy(self,http.client,'http.client',
                        allow={'HTTPConnection','HTTPSConnection','HTTPResponse','responses',
                               'HTTPException','NotConnected','InvalidURL'},
                        wrap={'HTTPConnection':self.net_guard(http.client.HTTPConnection,'HTTP 连接'),
                              'HTTPSConnection':self.net_guard(http.client.HTTPSConnection,'HTTPS 连接')})
        return _Proxy(self,http,'http',wrap={'client':client})

    def subprocess_module(self):
        wrap = {
            'run':self.proc_guard(subprocess.run,'subprocess.run'),
            'Popen':self.proc_guard(subprocess.Popen,'subprocess.Popen'),
            'call':self.proc_guard(subprocess.call,'subprocess.call'),
            'check_call':self.proc_guard(subprocess.check_call,'subprocess.check_call'),
            'check_output':self.proc_guard(subprocess.check_output,'subprocess.check_output'),
        }
        allow = {'PIPE','STDOUT','DEVNULL','SubprocessError','CalledProcessError','TimeoutExpired'}
        return _Proxy(self,subprocess,'subprocess',allow=allow,wrap=wrap)

    def safe_module(self,name,real,wrap=None,deny=()):
        """"本身安全"的模块也套一层门面(第五批,bug 名 environ)。

        这些模块不提供文件/网络/进程能力,但**真模块的全局里挂着 os/sys/子模块**:
        `logging.os.environ['PATH']`、`tkinter.sys.modules`、`random._os` 都是一行就能
        读环境变量的路;读 environ 不产生审计事件,所以第二道闸根本挂不上钩子,只能
        靠门面不把句柄交出去。规则就一条:模块对象要么是它自己的子模块(递归包一层),
        要么拒 —— 见 `_Proxy.__getattr__` / `_is_child_module`。
        """
        return _Proxy(self,real,name,allow=None,wrap=wrap,deny=deny)

    def imagetk_module(self):
        """ImageTk 也是真模块(`PIL.ImageTk`):它自己会牵出 `PIL.Image` 等模块句柄。"""
        return self.safe_module('ImageTk',_PILImageTk)

    def module_builders(self):
        """模块名 -> 门面对象(建一次就缓存:import os 和命名空间里的 os 是同一个)。"""
        if not self._module_cache:
            self._module_cache = {
                'os':self.os_module(),
                'sys':self.sys_module(),
                'io':self.io_module(),
                'socket':self.socket_module(),
                'urllib':self.urllib_module(),
                'http':self.http_module(),
                'subprocess':self.subprocess_module(),
                'PIL':self.image_module(),
                'mutagen':self.mutagen_module(),
                'builtins':self.builtins_view(),
            }
            # 第五批(bug 名 environ):直通模块不再交真模块,一律套安全门面。
            for name,mod in self._PASSTHROUGH.items():
                if '.' in name:
                    continue
                self._module_cache.setdefault(name,self.safe_module(name,mod))
        return self._module_cache

    # 直接放行的模块:它们本身不提供文件/网络/进程能力(不碰路径的那些功能)。
    _PASSTHROUGH = {
        'json':_json,'re':re,'math':math,'random':random,'time':time,
        'datetime':datetime,'collections':collections,'itertools':itertools,
        'functools':functools,'string':string,'textwrap':textwrap,
        'traceback':traceback,'logging':logging,
        'tkinter':tkinter,'tkinter.ttk':tkinter.ttk,
        'tkinter.simpledialog':tkinter.simpledialog,
        'tkinter.messagebox':tkinter.messagebox,
        'tkinter.filedialog':tkinter.filedialog,
        'tkinter.colorchooser':tkinter.colorchooser,
        'tkinter.font':tkinter.font,
        'ttkbootstrap':ttkbootstrap,
    }

    # ---------------- import ----------------

    # 这些包的子模块可以直接给真模块(tkinter.ttk / tkinter.scrolledtext /
    # PIL.ImageDraw…):它们只提供界面/图像工具,本身不含文件、网络、进程能力;
    # 真去读文件的调用由审计钩子兜底。
    _SUBMODULE_PACKAGES = ('tkinter','ttkbootstrap','PIL')

    @staticmethod
    def _dotted_exists(obj,name):
        """门面背后是真模块/真对象:校验 a.b.c 这条链真的存在。

        否则 `import os.environ.x` 这种(真 Python 里根本不存在的模块)也会被放行,
        插件会拿到一个莫名其妙的 os 门面。
        """
        real = _real_of(obj)
        for part in name.split('.')[1:]:
            try:
                real = getattr(real,part)
            except AttributeError:
                return False
        return True

    def _resolve_module(self,name):
        """模块名 -> 插件该拿到的东西(受控门面 / 安全模块 / None=不在白名单)。"""
        root = name.split('.')[0]
        built = self.module_builders().get(root)
        if built is not None:
            if '.' not in name:
                return built
            # "a.b"/"a.b.c":先顺着门面属性把**子模块门面**拿到 —— `from a.b import x`
            # 要的是 a.b 这个模块本身(`import a.b` 要的才是顶层包 a,那条按
            # `__import__` 的契约在 import_module 里补)。第五批之前这里直接返回根模块,
            # 子模块是门面之后必须专门走一遍,否则 `from tkinter.simpledialog import ...`
            # 会在包门面上找不到 askstring。
            if self._dotted_exists(built,name):
                sub = built
                for part in name.split('.')[1:]:
                    try:
                        sub = getattr(sub,part)
                    except (AttributeError,SandboxDenied):
                        sub = None
                        break
                if sub is not None:
                    return sub
        if name in self._PASSTHROUGH:
            # 第五批(bug 名 environ):直通模块也套门面,不再把真模块交出去
            return self.safe_module(name,self._PASSTHROUGH[name])
        if root in self._PASSTHROUGH:
            if root in self._SUBMODULE_PACKAGES:
                try:
                    mod = _importlib.import_module(name)
                except Exception:
                    return None
                self.note('import_submodule','*',name,
                          f'{root} 的子模块,只提供界面/工具能力')
                # 子模块同样是真模块(`PIL.ImageDraw` 会牵出 `PIL.Image`)——一样套门面
                return self.safe_module(name,mod)
            return None
        local = self.import_local(root)
        if local is not None:
            return local
        if root in tuple(self.policy.modules):
            try:
                mod = _importlib.import_module(name)
            except Exception as e:
                raise ImportError(f'{name} 导入失败:{e}')
            self.note('import_declared','*',name,'插件在 plugin.json 里声明的模块,不受沙盒代理')
            logging.warning('插件 %s 导入了声明放行的模块 %s(不经沙盒代理)',self.name,name)
            return mod
        return None

    def _attach_fromlist(self,name,obj,fromlist):
        """from X import Y 里 Y 是子模块时,先把它挂到父模块上,否则 getattr 找不到。"""
        root = name.split('.')[0]
        if root not in self._SUBMODULE_PACKAGES:
            return obj
        for item in fromlist:
            if not isinstance(item,str) or item == '*':
                continue
            try:
                present = hasattr(obj,item)
            except SandboxDenied:
                present = False
            if present:
                continue
            try:
                sub = _importlib.import_module(f'{name}.{item}')
            except Exception:
                continue
            real = _real_of(obj)
            try:
                setattr(real,item,sub)
            except Exception:
                pass
        return obj

    def import_module(self,name,globals=None,locals=None,fromlist=(),level=0):
        if not isinstance(name,str) or not name:
            raise SandboxDenied('import 的模块名无效')
        if level:
            self.violation('import','不支持相对 import',name)
            raise SandboxDenied('沙盒里不支持相对 import')
        obj = self._resolve_module(name)
        if obj is None:
            self.violation('import',f'import {name!r} 不在沙盒白名单里',name)
            raise SandboxDenied(
                f'import {name!r} 被插件沙盒拒绝;'
                f'确有需要请在 plugin.json 的 sandbox.modules 里声明')
        if fromlist:
            # from X import a,b:补上子模块,剩下的交给 import 机制去 getattr
            return self._attach_fromlist(name,obj,fromlist)
        # __import__ 的契约:没有 fromlist 的 "import a.b" 必须返回**顶层** a,
        # 这样字节码把 a 绑到名字上之后,a.b 仍能按属性取到。
        # 这里原来直接返回了 a.b,于是 `import tkinter.simpledialog` 会把
        # tkinter 绑成子模块,之后 tkinter.simpledialog.xxx 全都炸 —— 就是这个 bug。
        top = name.split('.')[0]
        if top == name:
            return obj
        topobj = self._resolve_module(top)
        return obj if topobj is None else topobj

    def import_local(self,name):
        """插件自己目录里的模块:用沙盒命名空间执行,不能借它拿到真 os。"""
        if name in self._local_modules:
            return self._local_modules[name]
        path = os.path.join(self.plugin_dir,name+'.py')
        pkg = os.path.join(self.plugin_dir,name,'__init__.py')
        target = path if os.path.isfile(path) else (pkg if os.path.isfile(pkg) else None)
        if target is None:
            return None
        mod = _types.ModuleType(name)
        mod.__dict__['__builtins__'] = self.restricted_builtins()
        mod.__dict__['__sandbox__'] = SandboxView(self)
        mod.__dict__['__file__'] = target
        self._local_modules[name] = mod
        try:
            with self._guarded(_builtins.open,target,'r',encoding='utf-8') as fp:
                code = compile(fp.read(),target,'exec')
            exec(code,mod.__dict__)
        except Exception:
            del self._local_modules[name]
            raise
        return mod

    # ---------------- 受控内置 ----------------

    _SAFE_BUILTINS = (
        'abs','all','any','ascii','bin','bool','bytearray','bytes','callable','chr',
        'classmethod','complex','delattr','dict','divmod','enumerate','filter','float',
        'format','frozenset','getattr','hasattr','hash','hex','id','int','isinstance',
        'issubclass','iter','len','list','map','max','min','next','object','oct','ord',
        'pow','print','property','range','repr','reversed','round','set','setattr','slice',
        'sorted','staticmethod','str','sum','super','tuple','type','vars','zip',
        'ArithmeticError','AssertionError','AttributeError','BaseException','BlockingIOError',
        'BrokenPipeError','BufferError','BytesWarning','ChildProcessError','ConnectionAbortedError',
        'ConnectionError','ConnectionRefusedError','ConnectionResetError','DeprecationWarning',
        'EOFError','EnvironmentError','Exception','FileExistsError','FileNotFoundError',
        'FloatingPointError','FutureWarning','GeneratorExit','IOError','ImportError',
        'ImportWarning','IndentationError','IndexError','InterruptedError','IsADirectoryError',
        'KeyError','KeyboardInterrupt','LookupError','MemoryError','ModuleNotFoundError',
        'NameError','NotADirectoryError','NotImplementedError','OSError','OverflowError',
        'PendingDeprecationWarning','PermissionError','ProcessLookupError','RecursionError',
        'ReferenceError','ResourceWarning','RuntimeError','RuntimeWarning','StopAsyncIteration',
        'StopIteration','SyntaxError','SyntaxWarning','SystemError','TabError','TimeoutError',
        'TypeError','UnboundLocalError','UnicodeDecodeError','UnicodeEncodeError',
        'UnicodeError','UnicodeTranslateError','UnicodeWarning','UserWarning','ValueError',
        'Warning','ZeroDivisionError','__build_class__','__name__','NotImplemented',
        'Ellipsis','True','False','None','copyright','credits','license',
    )

    def restricted_builtins(self):
        b = {}
        for k in self._SAFE_BUILTINS:
            if k in ('True','False','None','__name__'):
                continue
            v = getattr(_builtins,k,None)
            if v is not None:
                b[k] = v
        b['open'] = self.fs_open
        b['__import__'] = self.import_module
        b['eval'] = self.sandbox_eval
        b['exec'] = self.sandbox_exec
        b['compile'] = self.sandbox_compile
        b['globals'] = _builtins.globals
        b['locals'] = _builtins.locals
        b['dir'] = _builtins.dir
        b['input'] = self._no_input
        return b

    def _no_input(self,*args,**kwargs):
        self.violation('builtin','插件里不能用 input()(控制台在播放器手上)',None)
        raise SandboxDenied('沙盒里不允许使用 input()')

    def _scope(self,globals):
        g = globals if isinstance(globals,dict) else self.namespace
        g['__builtins__'] = self.restricted_builtins()
        return g

    def sandbox_eval(self,source,globals=None,locals=None):
        g = self._scope(globals)
        if type(source) is type((lambda: 0).__code__):
            register_plugin_code(self,source)
        return _builtins.eval(source,g,g if locals is None else locals)

    def sandbox_exec(self,source,globals=None,locals=None):
        g = self._scope(globals)
        # 第六批:走这条路执行的 code 是"插件自己的代码"—— 把整棵 code 树
        # 登记进身份账本,之后栈上出现它的任何一帧,钩子都按插件判。
        if type(source) is type((lambda: 0).__code__):
            register_plugin_code(self,source)
        return _builtins.exec(source,g,g if locals is None else locals)

    def exec_plugin_code(self,code,globals=None):
        """宿主把"给插件编译出来的 code"交给沙盒执行:先登记身份,再 exec。

        这是第六批建议宿主走的入口(b.py 原来是自己 `compile` + 真 `exec`;
        直接调本方法即可把"顶层那一帧算不算插件"也一起定下来)。
        """
        register_plugin_code(self,code)
        g = self._scope(globals)
        return _builtins.exec(code,g,g)

    def register_plugin_code(self,code):
        """只登记身份、不执行(宿主自己拿着 code 要 exec 时用)。"""
        return register_plugin_code(self,code)

    def sandbox_compile(self,source,filename=None,mode='exec',*args,**kwargs):
        if filename is None:
            filename = f'<plugin {self.name} exec>'
        return _builtins.compile(source,filename,mode,*args,**kwargs)

    # ---------------- 命名空间 ----------------

    def _build_namespace(self):
        ns = self.namespace
        ns['__name__'] = 'plugin_'+str(self.env_id)
        ns['__doc__'] = None
        ns['__builtins__'] = self.restricted_builtins()
        ns['__sandbox__'] = SandboxView(self)
        ns['SandboxDenied'] = SandboxDenied    # 插件可以精确地 except 它
        ns['open'] = self.fs_open
        facades = self.module_builders()
        for name,mod in self._PASSTHROUGH.items():
            if '.' not in name:
                # 第五批(bug 名 environ):放的是安全门面,不是真模块
                ns[name] = facades.get(name) or self.safe_module(name,mod)
        ns['os'] = facades['os']
        ns['sys'] = facades['sys']
        ns['io'] = facades['io']
        ns['Image'] = facades['PIL']
        ns['ImageTk'] = self.imagetk_module()
        ns['mutagen'] = facades['mutagen']
        ns['plugin_dir'] = self.plugin_dir
        ns['__env_id__'] = self.env_id     # 老插件(如 plugin/nb)在用它
        if self._host is not None:
            ns['pro'] = self._facade or self._host   # 重建命名空间时别把宿主弄丢
        return ns


# ---------------------------------------------------------------- 注册表

class env_box:
    """宿主侧的沙盒注册表:env_id -> SandBox。

    保留 a / get() 的形状,免得插件里已经写下的 pro.env_dict.a[...] 直接失效。
    命名空间一旦被删(plugin/nb/a.py 就试过 del pro.env_dict.a['2']),宿主手里的
    SandBox 对象仍然有效,get()/create() 会按需把它重新登记回来。
    """
    #只能防老实的插件
    #陌生插件还是发给gpt吧

    def __init__(self):
        self.a = {}
        self._boxes = {}
        self.__sealed = False

    def create(self,env_id,name,plugin_dir,policy,_host_token=None):
        """只有宿主能建沙盒/改策略。插件即便拿着 pro.env_dict 也只能取回自己的命名空间。"""
        box = self._boxes.get(env_id)
        if _host_token is not _HOST_TOKEN:
            if box is None:
                raise SandboxDenied(f'只有宿主能创建插件沙盒(env_id={env_id!r})')
            box.violation('create','插件试图改造已有沙盒',env_id)
            self.a[env_id] = box.namespace
            return box
        # 凭据对不代表"这次调用是宿主发的":插件同进程,凭据它偷得到。
        # 栈上有插件帧就说明是插件拿着偷来的凭据在改策略,直接拒。
        if is_plugin_frame_on_stack():
            caller = box if box is not None else None
            target = caller or next(iter(self._boxes.values()),None)
            if target is not None:
                target.refuse_plugin_caller('env_dict.create')
            raise SandboxDenied('插件不能借 env_dict.create 改沙盒策略(只有宿主能)')
        if box is not None:
            self.a[env_id] = box.namespace      # 自我修复:被删了就重新登记
            if self.__sealed or box.is_sealed():
                # 封存之后谁都不能再改策略,只允许把命名空间登记回来
                return box
            merged = _merge_policy(box.policy,policy,box.name,name)
            if merged is not None:
                box.policy = merged
                box._build_namespace()
                print(f'[沙盒] {name} 与 {box.name} 共用 env_id={env_id},'
                      f'合并后的策略:{merged.describe()}')
            return box
        box = SandBox(env_id,name,plugin_dir,policy)
        self._boxes[env_id] = box
        self.a[env_id] = box.namespace
        return box

    def sandbox(self,env_id):
        return self._boxes.get(env_id)

    def boxes(self):
        return list(self._boxes.values())

    def get(self,env_id):
        box = self._boxes.get(env_id)
        if box is None:
            raise KeyError(f'env_id={env_id!r} 还没有创建沙盒;请先调用 create()')
        self.a[env_id] = box.namespace
        return box.namespace

    def seal(self):
        self.__sealed = True
        for box in self._boxes.values():
            if not box.is_sealed():
                box.seal()
        return len(self._boxes)

    def is_sealed(self):
        return self.__sealed

    def grant(self,*args,_host_token=None,**kwargs):
        """宿主专用:给某个 env 的插件额外授权。插件调用会在这里被拒。"""
        if _host_token is not _HOST_TOKEN:
            for box in self._boxes.values():
                box.violation('grant','插件试图通过 env_dict 给自己授权',None)
            raise SandboxDenied('插件不能给自己授权(只有宿主能)')
        if is_plugin_frame_on_stack():
            box = self._boxes.get(args[0]) if args else None
            if box is not None:
                box.violation('grant','插件拿着凭据从插件代码里给自己授权',None)
            raise SandboxDenied('插件不能借 env_dict.grant 给自己授权(只有宿主能)')
        if not args:
            raise SandboxDenied('grant 需要 env_id 和能力名')
        box = self._boxes.get(args[0])
        if box is None:
            raise SandboxDenied(f'没有 env_id={args[0]!r} 的沙盒')
        return box.grant(*args[1:],_host_token=_HOST_TOKEN)


def _merge_policy(old,new,old_name,new_name):
    """共用 env_id 的两个插件合并成一份策略(取并集,并打印提示)。

    共用 env_id 等于自愿共享一个命名空间,所以这里把它们当成同一个信任域;
    真要最小权限,就别让两个插件共用 env_id。
    """
    if old.unsafe or new.unsafe:
        return None if old.unsafe else new
    merged = Policy(old.plugin_dir)
    merged.fs_read = list(dict.fromkeys(list(old.fs_read) + list(new.fs_read)))
    merged.fs_write = list(dict.fromkeys(list(old.fs_write) + list(new.fs_write)))
    merged.net = old.net or new.net
    merged.proc = old.proc or new.proc
    merged.ask = old.ask or new.ask
    merged.modules = list(dict.fromkeys(list(old.modules) + list(new.modules)))
    merged.warnings = [f'与 {old_name} / {new_name} 共用 env_id,策略已合并']
    return merged


# ---------------------------------------------------------------- 宿主门面

def _facade_leak(obj,label,name):
    """门面的内部槽被插件直接读到:记一条 violation 再拒。

    第四批加固(`facade_slots`):`_d`(门面内部数据)是实例上唯一真实存在的槽,
    而 `__getattr__` 只对**找不到**的属性触发 —— 所以它必须由 `__getattribute__`
    单独拦住,否则 `pro.app._d` 一样能把真控件连同沙盒一起交出去。
    """
    sb = object.__getattribute__(obj,'_d')[0]
    sb.violation('host_attr',f'插件不能访问 {label}.{name}',None)
    raise SandboxDenied(
        f'插件不能访问 {label}.{name}'
        f'(那是门面的内部数据,拿走就等于把宿主交出去)')


class _MenuFacade:
    """只放行"往菜单里加东西"。不给控件对象:控件有 .tk,那就是 Tcl 通道。

    第四批加固(`facade_slots`):原来控件放在 `__slots__ = ('_sb','_menu')` 上,
    而 `__getattr__` 只对**找不到**的属性触发 —— `pro.menu._menu` 是真实存在的槽,
    白名单那一句根本轮不到执行,插件直接拿走真 Menu 控件(`.tk` 即 Tcl 通道)。
    现在控件和沙盒只存在 `_d` 里,而 `_d` 由 `__getattribute__` 自己拦着。
    """

    __slots__ = ('_d',)

    _ALLOW = ('add_command','add_separator','add_checkbutton','add_radiobutton')

    def __init__(self,sb,menu):
        object.__setattr__(self,'_d',(sb,menu))

    def __getattribute__(self,name):
        if name == '_d':
            _facade_leak(self,'pro.menu',name)
        return object.__getattribute__(self,name)

    def _delegate(self,item):
        # 用闭包包一层,不把绑定方法交出去:绑定方法的 __self__ 是控件,
        # 而控件有 .tk 通道(这条只是抬高门槛,不是边界,见 SANDBOX.md)
        sb,menu = object.__getattribute__(self,'_d')
        target = getattr(menu,item)

        def call(*a,**k):
            return target(*a,**k)
        return call

    def __getattr__(self,item):
        sb,menu = object.__getattribute__(self,'_d')
        if item in _MenuFacade._ALLOW and menu is not None:
            return self._delegate(item)
        sb.violation('host_attr',f'插件不能访问 pro.menu.{item}',None)
        raise SandboxDenied(f'插件不能访问 pro.menu.{item}(只能加菜单项)')

    def __repr__(self):
        sb,menu = object.__getattribute__(self,'_d')
        return f'<sandbox menu for {sb.name}>'


class _AppFacade:
    """主窗口门面:白名单,不暴露 tk/call/eval/winfo_children/nametowidget。

    第四批加固(`facade_slots`):真 Tkapp 原来就放在 `__slots__ = ('_sb','_app')`
    的 `_app` 上,插件一句 `pro.app._app` 就把它拿走了(`__getattr__` 不触发),
    紧接着 `.tk.eval("exec ...")` 就是一条完整的 Tcl 起进程通道 —— 实测真 Tk 下
    `.tk.eval('expr 1+1')` 返回 `2`。现在真控件只存在 `_d` 里。
    """

    __slots__ = ('_d',)

    _ALLOW = ('after','after_idle','after_cancel','title','geometry','deiconify',
              'withdraw','iconify','destroy','update','update_idletasks',
              'bind','unbind','bind_all','unbind_all','resizable','minsize','maxsize',
              'winfo_width','winfo_height','winfo_screenwidth','winfo_screenheight',
              'winfo_x','winfo_y','winfo_exists','attributes')

    # 第六批:这些白名单方法的参数里有"插件交来的回调",Tk 会在**别的执行上下文**
    # (mainloop 下一轮)里调它 —— 那时插件帧早没了,必须靠门面顺手挂归属。
    # `bind`/`bind_all` 走的是同一条路,但它们的回调挂在控件事件上(不是一次性
    # 执行),归属计数要按"事件次数"算,本批没做(见文件头"没堵住的")。
    _CALLBACK_CHANNELS = ('after','after_idle')

    # 第九批(bug 名 `bind_channel`):`bind`/`bind_all` 走的是**同一条路**,区别只在
    # 回调会**反复触发**,所以归属记在 `_bind_owner`(弱引用、命中即长期有效),
    # 不能记 `_CodeLedger.pending`(按"还欠几次执行"递减 —— 事件的第二次触发
    # 就会归零,又落回"认不出 → 当宿主放行")。
    _BIND_CHANNELS = ('bind','bind_all')

    def __init__(self,sb,app):
        object.__setattr__(self,'_d',(sb,app))

    def __getattribute__(self,name):
        if name == '_d':
            _facade_leak(self,'pro.app',name)
        return object.__getattribute__(self,name)

    def _delegate(self,item):
        sb,app = object.__getattribute__(self,'_d')
        target = getattr(app,item)

        if item in _AppFacade._CALLBACK_CHANNELS or item in _AppFacade._BIND_CHANNELS:
            # 第六批/第九批:把插件交来的函数转交给 Tk 之前,先登记"这个回调算哪个
            # 插件的"。这是这两条通道唯一的立足点:门面调用一定是从插件帧里发出来的,
            # 而回调真正跑起来时(异步、插件帧早就没了)钩子只能靠这份登记认人。
            # 宿主自己排的定时器/绑定不走门面,所以不会被误判。
            sticky = item in _AppFacade._BIND_CHANNELS
            def call_cb(*a,**k):
                # 逐个参数登记:原来只认第一个可调用参数,`after(0, a, b)` 这种
                # 多回调写法会漏登记(`after` 只跑第一个还看不出问题,`bind` 会漏掉)。
                for arg in a:
                    if not callable(arg):
                        continue
                    try:
                        if is_plugin_frame_on_stack():
                            if sticky:
                                mark_bind_owner(sb,arg)
                            else:
                                mark_callback_owner(sb,arg)
                    except Exception:
                        logging.exception('登记回调归属失败,按未登记处理')
                return target(*a,**k)
            return call_cb

        def call(*a,**k):
            return target(*a,**k)
        return call

    def __getattr__(self,item):
        sb,app = object.__getattribute__(self,'_d')
        if item in _AppFacade._ALLOW and app is not None:
            return self._delegate(item)
        sb.violation('host_attr',f'插件不能访问 pro.app.{item}',None)
        raise SandboxDenied(
            f'插件不能访问 pro.app.{item}'
            f'(Tk 的 Tcl 通道沙盒挡不住,所以这里只放行白名单方法)')

    def __repr__(self):
        sb,app = object.__getattribute__(self,'_d')
        return f'<sandbox app for {sb.name}>'


class HostFacade:
    """插件看到的 pro。

    旧版把整个 Tkapp 交给插件,于是 pro.player.music_player(能放任意 URL/文件)、
    pro.app.tk.eval("exec ...")、pro.env_dict(注册表)、pro.plugin_list(别人的命名
    空间)全敞着 —— 等于绕开前面所有能力检查。现在只给这几样:
        pro.menu            加菜单项
        pro.app             白名单方法(窗口标题/几何/after/destroy...)
        pro.music_dict      播放列表的深拷贝快照(改了不影响播放器)
        pro.plugin_names    已加载插件的名字(不给对象)

    第四批加固(`facade_slots`):原来 `_sb`/`_pro` 也挂在 `__slots__` 上,于是
    `pro._pro` 一句就把**整个原宿主对象**拿了回去 —— `env_dict`(注册表)、
    `plugin_list`(别人的命名空间)、`music_player` 全回来,门面等于没装
    (实测 `pro._pro.env_dict` 直接读到宿主内容)。现在它们只存在 `_d` 里;
    `_pro` 连槽都没有,读它会照常触发 `__getattr__` 撞白名单。
    """

    __slots__ = ('_d','menu','app')

    def __init__(self,sb,pro):
        object.__setattr__(self,'_d',(sb,pro))
        self.menu = _MenuFacade(sb,getattr(pro,'menu',None))
        self.app = _AppFacade(sb,getattr(pro,'app',None))

    def __getattribute__(self,name):
        if name == '_d':
            _facade_leak(self,'pro',name)
        return object.__getattribute__(self,name)

    @property
    def music_dict(self):
        sb,pro = object.__getattribute__(self,'_d')
        try:
            return copy.deepcopy(pro.music_dict)
        except Exception:
            logging.exception('取播放列表快照失败,返回空表')
            return {}

    @property
    def plugin_names(self):
        sb,pro = object.__getattribute__(self,'_d')
        try:
            return [getattr(p,'name','') for p in pro.plugin_list]
        except Exception:
            return []

    def __getattr__(self,item):
        sb,pro = object.__getattribute__(self,'_d')
        sb.violation('host_attr',f'插件不能访问 pro.{item}',None)
        raise SandboxDenied(
            f'插件不能访问 pro.{item};可用的是 pro.menu / pro.app / '
            f'pro.music_dict / pro.plugin_names')

    def __repr__(self):
        sb,pro = object.__getattribute__(self,'_d')
        return f'<sandbox host facade for {sb.name}>'


# ---------------------------------------------------------------- 审计钩子

# 门面 / 宿主替插件做事时置位:这期间审计钩子放行(权限已经查过,也避免递归)
_FRAME_LOCAL = threading.local()
_FRAME_TAGS = {}          # '<plugin 名字 ' -> SandBox
_FRAME_DIRS = []          # [(规范化插件目录, SandBox)]
_HOOK_INSTALLED = False

# 实测:CPython 的审计表里没有 os.stat/os.lstat(它们不产生事件),
# 所以"探测文件是否存在/多大"在内省路径下挡不住 —— 这是已知缺口,
# 写在 SANDBOX.md 的"已知的坑"里,别指望这里。
_FS_READ_EVENTS = ('os.listdir','os.scandir')
_FS_WRITE_EVENTS = ('os.mkdir','os.rmdir','os.remove','os.utime','os.chmod',
                    'os.truncate','os.link','os.symlink')
# 第三批加固(module_globals):补上"起线程"事件。插件的帧身份是靠 co_filename
# 认的,而 co_filename 是它自己传给 compile 的 —— `compile(src,'<not-a-plugin>')`
# 之后在新线程里执行,栈上就没有任何插件帧,钩子会判定"不是插件干的"直接放行
# (plugin/escape2 第 12 步,实测真 os.system 跑通)。把线程启动也算进 proc,
# 这条路至少要先拿到 proc 授权。CPython 3.14 的事件名是
# `_thread.start_joinable_thread`;老的 `_thread.start_new_thread` 一起留着兼容。
_PROC_EVENTS = ('os.system','os.exec','os.spawn','os.posix_spawn','os.startfile',
                'os.fork','os.forkpty','subprocess.Popen','ctypes.dlopen','pty.spawn',
                '_thread.start_new_thread','_thread.start_joinable_thread')
_NET_EVENTS = ('socket.__new__','socket.connect','socket.bind','socket.getaddrinfo',
               'socket.gethostbyname','socket.sendto')

_O_WRITE_FLAGS = 0
for _flag in ('O_WRONLY','O_RDWR','O_CREAT','O_APPEND','O_TRUNC'):
    _O_WRITE_FLAGS |= getattr(os,_flag,0)


# ---------------------------------------------------------------- 注册表完整性
#
# 审计钩子要判断"这一帧是不是插件",就得知道有哪些插件 —— 而这个"知道"本身
# 是进程内的数据,插件跟它同进程,总能摸到(模块全局、__globals__ 都行)。
# 逃逸样本的做法是清空 `_FRAME_TAGS`/`_FRAME_DIRS`:钩子于是认不出插件帧,
# 对所有后续事件失明。
#
# 这里加的是一道"记账":每次合法注册都会在闭包私有的集合里记一笔,钩子每次
# 干活前先比对"我记的数量"和"表里现在有多少"。少了就是有人清过表,于是
# 按记账**立刻恢复**那张表、拒绝当下这一次操作,并留一条审计。
# 注意别做成"拒绝一切":宿主自己的 after/winfo/logging 也会撞上审计钩子,
# 那样插件清一次表就能把播放器一起拖垮(实测会崩在 b.py 的 on_resize)。
# 诚实说明:同进程里这仍然不是边界 —— 插件把凭据/函数对象都摸到了,反复清表
# 就能反复让插件自己的那次操作失败并刷审计。它的价值是"把静默失明变成会报警
# 的拒绝",同时不让宿主陪葬。
class _FrameRegistrar:
    """闭包私有的注册记账(插件拿不到这个对象)。

    第三批加固(module_globals):这里原来 `count` 是普通属性、`boxes` 是普通
    dict,于是逃逸样本 `g['_frame_registrar'].count = 0` **再**清空
    `_FRAME_TAGS`/`_FRAME_DIRS`,`tampered()` 就恒为 False,钩子从此认不出插件帧、
    对所有事件静默放行(plugin/escape2 第 10 步,实测能读 C:\\Windows)。
    现在:
      * `count` 只增不减 —— 往小改会被记成"永久处于被篡改状态",`tampered()`
        于是永远走"按记账恢复 + 继续按调用者判定"那条路(插件那一下照样被拒,
        宿主不受影响);
      * `boxes` 只给只读副本,插件 clear 它不再能抹掉内部记账。
    """

    def __init__(self):
        self.tags = set()
        self._boxes = {}
        self._count = 0
        self._forced = False
        self.armed = False

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self,value):
        """只许往上走:往小改 = 试图致盲钩子,直接记成永久被篡改。"""
        try:
            value = int(value)
        except Exception:
            self._forced = True
            return
        if value < self._count:
            self._forced = True
            return
        self._count = value

    @property
    def boxes(self):
        """只读副本:`g['_frame_registrar'].boxes.clear()` 不再能清掉记账。"""
        return dict(self._boxes)

    def notify(self,box):
        tag = box.frame_tag
        if tag in self._boxes:
            return                                  # 同一个插件只记一笔
        self.tags.add(tag)
        self._boxes[tag] = box
        self._count += 1

    def arm(self,boxes=()):
        """装钩子时对齐一次:如果之前就有插件注册过(钩子装晚了),补记。"""
        for box in boxes:
            self.notify(box)
        self.armed = True

    def sample_box(self):
        """随便挑一个已注册的沙盒,用来把"注册表被清"写进它的审计里。"""
        for box in self._boxes.values():
            return box
        return None

    def rebuild(self,tags,dirs,norm_fn):
        """按记账把注册表恢复回原样,返回恢复的插件数。

        恢复之后这一次的操作照样会被拒(调用者正要拿"恢复后的表"去查,
        而恶意那次至少已经被记了一笔);但宿主自己的后续操作不受影响 ——
        这一点很关键:不恢复就等于"插件清一次表,播放器陪着一起瘫"。
        """
        for tag,box in self._boxes.items():
            tags[tag] = box
        dirs[:] = [(norm_fn(box.plugin_dir),box) for box in self._boxes.values()]
        return len(self._boxes)

    def tampered(self,live_count):
        """表里的条目比记账少(或计数被人往小改过) => 被清过/被换过。"""
        return self.armed and (self._forced or live_count < self._count)


_frame_registrar = _FrameRegistrar()


# ---------------------------------------------------------------- 帧身份(第六批)
#
# 第三批那条路(伪造 `co_filename` + 换个执行上下文)暴露了一个更根本的问题:
# "这一帧是不是插件"原来靠**文件名前缀**认,而文件名是插件自己传给 `compile()`
# 的字符串 —— 被审查方指定的东西不能当身份。
#
# 这里换成**代码对象身份**:宿主编译插件源码时,那棵 code 树是宿主手里唯一的
# 一份;插件想让"未注册的 code"看起来像插件代码,只能改它的 `co_filename`,
# 改不了"这个对象当初是谁注册的"。
#
# 表本身仍然在模块 globals 里(同进程,插件内省拿得到,和 `_AUTH` 一个层级)——
# 诚实说明见文件头:把它搬到"插件改不了的地方"只有独立进程能做到。这条改动的
# 价值是**判据不再是字符串**;`_pending_after` 的计数被插件改大也只是让它自己
# 的计划成功,不会让别的判定失明。
class _CodeLedger:
    """插件 code 对象的归属表 + 宿主替插件排的 `after` 回调的临时归属。

    * `boxes_by_id` / `_series`:注册了哪些 box(和 box 自己的 `_code_series`
      对账,用来发现"表被清过"),清过就 rebuild 回去并记账(同第三批的处置:
      把静默失明变成会报警的拒绝,而不是拒绝一切把宿主拖垮);
    * `code_owner`:code 对象 -> box。用 code 对象**本身**当键,所以只能由
      注册这一侧填,插件伪造不了;
    * `pending`:code 对象 -> 还剩几次执行算它的。给 `after/after_idle` 这条
      通道用(回调不是宿主当面编译的,注册不到 `code_owner` 里,只能"登记一次
      回调的执行次数")。
    """

    # 上限只是"别让插件靠刷 compile 把内存顶爆",不是安全机制:
    # 到顶之后新 code 不再登记(判定退回"按文件名 + 未注册就记一条取证"),
    # 宿主自己的判定不受影响。
    _MAX_CODES = 20000
    _MAX_PENDING = 4096

    def __init__(self):
        self.boxes_by_id = {}
        self._series = 0
        self.code_owner = {}
        self.pending = {}
        self._queue = []
        self._forced = False
        self._warned_frame = set()

    # ---- box 侧记账(和 box._code_series 对账) ----

    def remember_box(self,box):
        if id(box) in self.boxes_by_id:
            return
        self.boxes_by_id[id(box)] = box
        self._series += 1

    def series(self):
        return self._series

    def tampered(self,live_count):
        """表里的 box 比记账少 => 被清过(处置见钩子:恢复 + 继续判定)。"""
        return self._forced or live_count < self._series

    def rebuild(self):
        for box in self.boxes_by_id.values():
            _PLUGIN_BOXES[id(box)] = box
        return len(self.boxes_by_id)

    # ---- code 对象注册 ----

    def register_code(self,box,code):
        if type(code) is not type((lambda: 0).__code__):
            return 0
        added = 0
        stack = [code]
        while stack:
            one = stack.pop()
            if type(one) is not type((lambda: 0).__code__):
                continue
            if self.code_owner.get(one) is None:
                if len(self.code_owner) >= self._MAX_CODES:
                    continue
                self.code_owner[one] = box
                added += 1
            for const in one.co_consts:
                if type(const) is type((lambda: 0).__code__):
                    stack.append(const)
                elif type(const) is tuple:
                    for inner in const:
                        if type(inner) is type((lambda: 0).__code__):
                            stack.append(inner)
        return added

    # ---- `after` 回调的临时归属 ----

    def note_pending(self,box,func):
        code = getattr(func,'__code__',None)
        if code is None:
            code = getattr(getattr(func,'__func__',None),'__code__',None)
        if code is None:
            return False
        if len(self.pending) >= self._MAX_PENDING and code not in self.pending:
            return False
        self.pending[code] = self.pending.get(code,0) + 1
        self._queue.append(code)
        self._prune()
        return True

    def bump(self,code):
        """回调真的跑起来了:这次算它的,返回"已经算过几次"(查不到返回 0)。

        计数本身照旧递减(它记的是"还欠几次"),返回值给 `box_for_code` 判断
        要不要把这个 code 直接转正进 `code_owner`(见 `_PCALLS_TO_OWN`)。
        """
        left = self.pending.get(code)
        if left is None:
            return 0
        if left <= 1:
            del self.pending[code]
        else:
            self.pending[code] = left - 1
        return left

    def _prune(self):
        if not self._queue:
            return
        if len(self._queue) > 4 * max(len(self.pending),1) + 64:
            self._queue = [c for c in self._queue if c in self.pending]
        if len(self._queue) > 8 * self._MAX_PENDING:
            self._queue = self._queue[-self._MAX_PENDING:]

    # ---- 取证:文件名自称是插件、code 却不在表里 ----

    def note_fake_frame(self,box,label):
        key = (id(box),label)
        if key in self._warned_frame:
            return
        self._warned_frame.add(key)
        try:
            box.violation(
                'fake_frame',
                f'有代码把 co_filename 写成了插件帧名({label}),但它的 code 对象'
                f'不是宿主编译插件时的那一份;判定按宿主处理(只记一次)',
                label)
        except Exception:
            pass


_ledger = _CodeLedger()
# id(box) -> box。第六批把 `_FRAME_TAGS`(文件名前缀表)之外的"code 身份"也
# 登记在这里;`_FRAME_TAGS` / `_FRAME_DIRS` 照旧保留给 `_box_for_frame` 的
# 兼容路径(宿主自己排版面帧时仍然按目录/前缀认)。
_PLUGIN_BOXES = {}

# `after` 回调的归属:code 对象 -> box。和 `_ledger.code_owner` 分开放,因为它来源
# 不同(门面替插件转交,而不是宿主编译)。
# **黏住不摘**:同一个回调被排多次(`after(0,cb)` 连排几次)时,计数一旦在第一次
# 执行时归零,第二次执行就会重新落回"认不出 → 当宿主",反而给出一条可反复利用的
# 路。所以这里只增不减:一个 code 对象一旦被证明是插件交来的,就一直算它;
# 内存由 `_CodeLedger` 的容量上限兜底(_MAX_PENDING)。
_pending_owner = {}

# `mark_callback_owner` 登记的回调,被钩子认到几次之后就"转正"进
# `_CodeLedger.code_owner`(见 `box_for_code`)。
_PCALLS_TO_OWN = 2

# ---------------------------------------------------------------- 第九批:回调归属
#
# 第八批为止,"把函数交给别的执行上下文"的通道只有 `after`/`after_idle` 挂了归属,
# 那在**一次性**通道上是对的:账本(`_CodeLedger.pending`)按"还欠几次执行"递减,
# 而 `after` 的回调本来也只跑一次。
#
# `bind` / `bind_all` 是**另一类**通道:回调挂在控件事件上,会反复触发。按次数
# 记账会在第二次执行时归零,又落回"认不出这个 code → 当宿主放行"(第六批给
# `after` 关上的那扇门,在 `bind` 上一直开着)。所以这里用一张**不同的表**:
#
#   * 键是**回调函数对象本身**(不是 code 对象):`types.FunctionType(code, g)`
#     这种"同一个 code、不同函数对象"的重组各自算各自的归属,不会被别人的归属
#     连坐;而且命中即**长期有效**(`_sticky`),不递减;
#   * 值是 box,用 `WeakKeyDictionary` 存:插件只要还持有这个回调就一直有效,
#     一旦丢掉引用(卸载/换绑)条目自动消失 —— 比"黏住不摘"的 `_pending_owner`
#     干净,也不会因为插件反复 `bind` 把内存顶爆;
#   * 只能拿**真正的函数/绑定方法**当键(要能弱引用),别的可调用对象(内建函数、
#     callable 实例)登记不了 —— 它们本来也拿不到"插件源码里的 code 身份"。
#
# 登记点仍在门面里(`_AppFacade._delegate`),条件不变:只有"这次门面调用确实是从
# 插件帧里发出来"才登记。宿主自己排的 `bind`/`after` 不走门面,不会被误判成插件。
_bind_owner = weakref.WeakKeyDictionary()

# 上面那张表的**反向**索引:回调的 code 对象 -> box(也是弱引用,**键弱引用**)。
# 为什么需要它:审计钩子把 `box_for_code` 用**默认参数**固化进了闭包
# (`_hook_frames_box(...,_code_fn=box_for_code,...)`),所以"只在模块层新加一个
# 查询函数"是看不见的 —— 归属必须并进 `box_for_code` 自己这条唯一的判据路上,
# 钩子、门面、`_box_for_frame` 才都会认。
_bind_codes = weakref.WeakKeyDictionary()


def mark_bind_owner(box, func):
    """给"会反复触发"的通道(`bind`/`bind_all`)登记回调归属。

    和 `mark_callback_owner` 的区别:那个走 `_CodeLedger.pending`(按"还欠几次
    执行"递减,给一次性回调用),这个走弱引用表 `_bind_owner`(命中即长期有效)。
    """
    if func is None:
        return False
    target = func
    if not hasattr(target,'__code__'):
        # 绑定方法/包装对象:认它背后的函数
        target = getattr(func,'__func__',None) or getattr(func,'func',None)
    try:
        _bind_owner[func] = box
    except TypeError:
        pass                              # 弱引用不了的对象(内建函数等):按未登记处理
    code = getattr(target,'__code__',None)
    if code is not None:
        try:
            if code not in _bind_codes:
                _bind_codes[code] = box
        except TypeError:
            pass
    return True


def register_plugin_code(box,code):
    """把宿主为插件编译出来的一棵 code 树登记成"这个插件的代码"。

    由 `SandBox.exec_plugin_code()`(宿主装载代码走的那条路)调用;宿主如果
    用的是**自己直接 `compile` + `exec`**(b.py 就是这样),也可以显式调它,
    装载点时机的差别只是"顶层那一帧算不算插件"(`SandBox.__init__` 会顺手
    注册 init 的顶层 code,所以 b.py 不改也够用)。
    """
    _ledger.remember_box(box)
    _PLUGIN_BOXES[id(box)] = box
    return _ledger.register_code(box,code)


def box_for_code(code):
    """这个 code 对象属于哪个插件;不是插件代码(或插件已卸载)返回 None。"""
    if code is None:
        return None
    # 第九批(bug 名 `bind_channel`):先问"这个 code 是不是插件通过门面
    # `bind`/`bind_all` 交出来的回调(`after` 那条走下面的 pending)。
    # 放在最前面有两个原因:
    #   * 事件回调会**反复触发**,不能按次数递减(见 `_bind_owner` 的说明);
    #   * 审计钩子把本函数按默认参数固化进了闭包,归属只有并进这条路才看得见。
    box = _bind_codes.get(code)
    if box is not None:
        return box
    box = _ledger.code_owner.get(code)
    if box is not None:
        return box
    if _ledger.pending.get(code):
        box = _pending_owner.get(code)
        if box is not None:
            # 命中几次之后就"转正"进 code_owner:同一个回调被排多次时,所有权
            # 不会再因为计数用完而丢(见上面 `_pending_owner` 的说明)。
            if _ledger.bump(code) >= _PCALLS_TO_OWN:
                _ledger.code_owner[code] = box
        return box
    return None


def box_for_callback(func,code=None):
    """这个**回调函数对象**属于哪个插件(按函数对象先查一次 `_bind_owner`)。

    审计钩子只需要"帧的 code 对象"那条路(`box_for_code` 里已并进 `_bind_codes`),
    所以本函数是给排查/自测用的:函数对象是**直接**归属,最强的那条证据 ——
    按函数对象查得到,就说明"这个回调确实是插件通过门面交出来的"。
    查不到时退回按 code 对象判(和 `box_for_code` 同口径)。
    """
    if func is None:
        return None
    try:
        box = _bind_owner.get(func)
    except TypeError:
        box = None
    if box is not None:
        return box
    if code is None:
        code = getattr(func,'__code__',None) or getattr(
            getattr(func,'__func__',None),'__code__',None)
    return box_for_code(code)


# ---------------------------------------------------------------- 第八批:插件自造门面帧
#
# `_guarded` 的豁免是审计钩子唯一的"这是门面替插件做的事"依据,而它原来没有
# 任何身份检查。`_plugin_code_at(n)` 是给 `SandBox._guarded` 用的**直接调用者**
# 身份判定:往上数第 n 层帧的 code 对象登记在插件身份账本里,就说明**插件自己**
# 在调(`box._guarded(fn)`),而不是门面内部方法在调(`fs_open` / `net_guard` /
# `_load_local_module` 的直接调用者是宿主方法)。
#
# 判据只认 code 对象身份(第六批的 `box_for_code`),不认 `co_filename` ——
# 文件名是插件自己写的,不能当身份。
def _plugin_code_at(depth=1,_code_fn=box_for_code):
    """往上第 depth 层帧的 code 对象是不是插件代码。

    depth=1 表示"`_plugin_code_at` 的调用者的调用者",也就是 `_guarded` 想看的
    "直接调用者"。拿不到帧(解释器边界)按"不是插件"处理 —— 宁可放行宿主,
    也不要因为探栈失败把宿主正常操作打死(钩子里已有的取舍,见其注释)。
    """
    try:
        frame = sys._getframe(depth + 1)
    except ValueError:
        return None
    if frame is None:
        return None
    return _code_fn(frame.f_code)
def mark_callback_owner(box,func):
    """宿主门面把插件交来的回调转交给 Tk 之前,登记"这个回调是哪个插件的"。

    只有"从插件代码帧里发出来的门面调用"才登记(宿主自己排的 `after` 不登记),
    所以宿主的定时器不会被误判成插件。
    """
    ok = _ledger.note_pending(box,func)
    if ok:
        code = getattr(func,'__code__',None) or getattr(
            getattr(func,'__func__',None),'__code__',None)
        _pending_owner[code] = box
        if len(_pending_owner) > 4096:
            for old in list(_pending_owner):
                if old not in _ledger.pending:
                    _pending_owner.pop(old,None)
    return ok



def _facade_enter():
    _FRAME_LOCAL.depth = getattr(_FRAME_LOCAL,'depth',0) + 1


def _facade_exit():
    _FRAME_LOCAL.depth = max(getattr(_FRAME_LOCAL,'depth',1) - 1,0)


def _always_readable(path):
    """解释器自己的目录(site-packages/stdlib)永远可读。

    否则插件界面一碰到 ttkbootstrap/PIL 读自带资源就会被钩子拦下。
    """
    for root in _ALWAYS_READABLE:
        if under(root,path):
            return True
    return False


def register_plugin_frames(box):
    _FRAME_TAGS[box.frame_tag] = box
    _FRAME_DIRS.append((_norm(box.plugin_dir),box))
    # 让审计钩子知道"又合法注册了一个插件" —— 钩子靠这个数字发现注册表
    # 被清空/替换过(逃逸样本的 _blind_audit_hook 就是.clear() 了那两张表)。
    _frame_registrar.notify(box)


def _box_for_frame(filename,code=None):
    """这一帧属于哪个插件。

    第六批的判据顺序(重要):
      1. **code 对象身份**(`box_for_code`):宿主为插件编译过的那棵 code 树 ——
         插件伪造不了,所以放在第一位;
      2. 文件名前缀 / 插件目录(兼容路径,给"宿主自己按文件路径排的插件帧"用);
      3. 名字自称是插件、code 却不在表里 => 记一条 `violation:fake_frame`
         (取证,不影响判权),仍然返回 None(按宿主处理)。
    """
    box = box_for_code(code)
    if box is not None:
        return box
    if not filename:
        return None
    for tag,ours in _FRAME_TAGS.items():
        if filename.startswith(tag):
            _note_fake_frame(ours,filename)
            return None
    for root,ours in _FRAME_DIRS:
        if root and under(root,filename):
            _note_fake_frame(ours,filename)
            return None
    return None


def _note_fake_frame(box,filename):
    """文件名自称是插件帧、但 code 对象没登记过 —— 记一次取证(不参与判权)。"""
    if box is None:
        return
    _ledger.note_fake_frame(box,filename)


def _plugin_box_on_stack():
    """从调用栈里找最近的插件代码帧(找不到就是宿主自己在访问)。"""
    try:
        frame = sys._getframe(1)
    except ValueError:
        return None
    depth = 0
    while frame is not None and depth < 200:
        box = _box_for_frame(frame.f_code.co_filename,frame.f_code)
        if box is not None:
            return box
        frame = frame.f_back
        depth += 1
    return None


def _is_pathlike(value):
    return isinstance(value,(str,bytes,os.PathLike))


def _audit_target(event,args):
    """把审计事件翻译成 (能力, 路径, 说明);不关心的返回 None。"""
    a = list(args)

    logging.debug(f"[{str(event)}]\n{str(a)}\n\n")
    if event == 'open':
        p = a[0] if a else None
        if not _is_pathlike(p):
            return None
        mode = a[1] if len(a) > 1 else None
        flags = a[2] if len(a) > 2 else None
        write = False
        if isinstance(mode,str):
            write = any(c in mode for c in ('w','a','x','+'))
        if isinstance(flags,int):
            write = write or bool(flags & _O_WRITE_FLAGS)
        return ('fs:write' if write else 'fs:read',os.fspath(p),f'open({mode!r})')
    if event == 'os.rename' or event == 'os.replace':
        paths = [os.fspath(x) for x in a[:2] if _is_pathlike(x)]
        return ('fs:write',paths,event) if paths else None
    if event in _FS_READ_EVENTS:
        p = a[0] if a else None
        return ('fs:read',os.fspath(p),event) if _is_pathlike(p) else None
    if event in _FS_WRITE_EVENTS:
        p = a[0] if a else None
        return ('fs:write',os.fspath(p),event) if _is_pathlike(p) else None
    if event in _NET_EVENTS:
        return ('net',None,event)
    if event in _PROC_EVENTS:
        return ('proc',None,event)
    return None


def is_plugin_frame_on_stack(depth=500):
    """宿主专用入口用:栈上只要有插件代码帧,就说明这次调用是插件发起的。

    它和审计钩子同源但更严:不看 `_FRAME_LOCAL.depth`,只看帧的文件名。
    插件从内省里偷到 `_HOST_TOKEN` 之后调 `grant`/`set_unsafe`,靠这一关挡住。
    """
    try:
        frame = sys._getframe(1)
    except ValueError:
        return False
    seen = 0
    while frame is not None and seen < depth:
        if _box_for_frame(frame.f_code.co_filename,frame.f_code) is not None:
            return True
        frame = frame.f_back
        seen += 1
    return False


def install_audit_hook():
    """装一次进程级审计钩子。装了它,插件即便通过内省拿到真的 os/socket,
    碰文件、联网、起进程也会被拦(门面之外的第二道闸)。

    判据(哪一帧属于插件、哪些目录永远可读)在这里**封进闭包**。
    逃逸样本原来靠清空模块级的 `_FRAME_TAGS` / `_FRAME_DIRS` 让钩子认不出
    插件帧(`_box_for_frame` 于是恒返回 None,钩子全程放行);现在:
      * 钩子读的是闭包抓到的注册表对象,换掉模块级变量没用;
      * 真把那两张表清空,`_registrar` 的记账会发现"表比我记得的少",
        于是**拒绝**这次操作并写审计 —— 静默失明变成会报警的拒绝。
    """
    global _HOOK_INSTALLED
    if _HOOK_INSTALLED:
        return False
    _HOOK_INSTALLED = True

    _tags = _FRAME_TAGS
    _dirs = _FRAME_DIRS
    _depth = _FRAME_LOCAL
    _under_fn = under
    _norm_fn = _norm
    _read_cap = None                           # 下面的可读白名单,装钩子时固化
    _o_write_flags = _O_WRITE_FLAGS
    _registrar = _frame_registrar
    # 第三批加固(module_globals):判权入口和事件表也一并固化进闭包。
    # 原来钩子里 `_auth_entry(box)` / `_auth_can(...)` / `event in _PROC_EVENTS`
    # 全是**全局名查找**,插件 `g['_auth_entry'] = <unsafe 记账>`(escape2 第 09 步)
    # 或 `g['_PROC_EVENTS'] = ()` 就能把钩子改掉;绑进闭包之后换 globals 无效。
    _entry_fn = _auth_entry
    _can_fn = _auth_can
    _proc_events = _PROC_EVENTS
    _net_events = _NET_EVENTS
    _fs_read_events = _FS_READ_EVENTS
    _fs_write_events = _FS_WRITE_EVENTS
    # "门面正在替插件做事"的帧指纹(见 _hook_in_facade_frame)
    _guard_code = SandBox._guarded.__code__
    _violation_code = SandBox.violation.__code__
    # 第十一批(性能,`hook_fastpath`):`_hook_target` 只认这几个事件名 —— 装钩子时
    # 固化成 frozenset,`_hook` 开头用它把"无关事件"在**碰栈之前**筛掉。
    # 必须固化成 frozenset(而不是每次现拼元组):这是每个审计事件都要走的一步,
    # 而元组 `in` 是线性扫描(实测 0.05µs/次 ×4 张表),frozenset 是一次哈希。
    # 集合内容 = 四张能力表 + open + 改名两个事件(其余事件 `_hook_target` 返 None)。
    _tracked_events = frozenset(
        _fs_read_events + _fs_write_events + _net_events + _proc_events
        + ('open','os.rename','os.replace'))
    _is_pathlike_fn = _is_pathlike
    # CPython 3.13+ 给 sys._getframe 也发了审计事件,而探栈必须用它 —— 这个
    # 重入标志防止"钩子 -> _getframe 事件 -> 钩子 -> …"无限递归(会静默栈溢出)。
    _frame_probe = [False]
    # 第十一批:探栈期间的**整体**重入标志,连"读 f_code 产生的
    # `object.__getattr__` 事件"也一起挡住(见 `_hook_in_facade_frame` 的说明)。
    _probe = [False]
    _registrar.arm(list(_tags.values()))       # 装钩子前就注册过的插件也算数
    _tamper_state = {'reported':False,'codes_reported':False}  # 各只报一次,别刷爆日志
    _led = _ledger                              # 第六批:身份账本(对象引用固化)

    # 只读白名单必须在装钩子时**固化成不可变的元组**:原来每次调用都去读
    # 模块级 `_ALWAYS_READABLE`,插件把它撑成所有盘根之后,钩子就会把
    # "读 C:\Windows\win.ini" 当"解释器自己的文件"放过去 —— 这是实打实漏掉的一条。
    for _p in (sys.prefix,sys.base_prefix,os.path.dirname(os.__file__)):
        if not _p:
            continue
        _one = _norm_fn(_p)
        if _one:
            _read_cap = (_one,) if _read_cap is None else (_read_cap + (_one,))

    def _hook_readable(path):
        for root in (_read_cap or ()):
            if _under_fn(root,path):
                return True
        return False

    def _hook_frames_box(filename,code=None,_code_fn=box_for_code,_led=_ledger):
        """闭包版 `_box_for_frame`:判据顺序同外层(第六批:先认 code 对象)。

        `_code_fn` / `_led` 用**默认参数**固化:插件把模块里 `box_for_code` /
        `_ledger` 这两个名字换掉不影响这里(第三批的教训)。

        * 表被清过 => 先按记账恢复(同第三批:恢复 + 继续判定,不拒绝一切);
        * 名字自称是插件、code 没登记 => 记一条取证,仍按宿主放行。
        """
        box = _code_fn(code)
        if box is not None:
            return box
        if not filename:
            return None
        for tag,ours in _tags.items():
            if filename.startswith(tag):
                _led.note_fake_frame(ours,filename)
                return None
        for root,ours in _dirs:
            if root and _under_fn(root,filename):
                _led.note_fake_frame(ours,filename)
                return None
        return None

    def _hook_box_on_stack():
        try:
            frame = sys._getframe(1)
        except ValueError:
            return None
        seen = 0
        while frame is not None and seen < 500:
            box = _hook_frames_box(frame.f_code.co_filename,frame.f_code)
            if box is not None:
                return box
            frame = frame.f_back
            seen += 1
        return None

    def _hook_target(event,args):
        """闭包版 `_audit_target`:走同一份事件->能力映射。"""
        a = list(args)
        if event == 'open':
            p = a[0] if a else None
            if not isinstance(p,(str,bytes,os.PathLike)):
                return None
            mode = a[1] if len(a) > 1 else None
            flags = a[2] if len(a) > 2 else None
            write = False
            if isinstance(mode,str):
                write = any(c in mode for c in ('w','a','x','+'))
            if isinstance(flags,int):
                write = write or bool(flags & _o_write_flags)
            return ('fs:write' if write else 'fs:read',os.fspath(p),f'open({mode!r})')
        if event in ('os.rename','os.replace'):
            paths = [os.fspath(x) for x in a[:2] if isinstance(x,(str,bytes,os.PathLike))]
            return ('fs:write',paths,event) if paths else None
        if event in _fs_read_events:
            p = a[0] if a else None
            if not isinstance(p,(str,bytes,os.PathLike)):
                return None
            return ('fs:read',os.fspath(p),event)
        if event in _fs_write_events:
            p = a[0] if a else None
            if not isinstance(p,(str,bytes,os.PathLike)):
                return None
            return ('fs:write',os.fspath(p),event)
        if event in _net_events:
            return ('net',None,event)
        if event in _proc_events:
            return ('proc',None,event)
        return None

    def _hook_in_facade_frame():
        """栈上有没有"门面正在替插件做真实调用"的帧。

        第三批加固(module_globals):这里原来读的是一个**可写的计数器**
        (`_FRAME_LOCAL.depth`),插件 `g['_FRAME_LOCAL'].depth = 5` 就让钩子对
        所有事件直接放行 —— 第二道闸一行代码全局失明(plugin/escape2 第 06 步,
        实测能列 C:\\Windows、能起进程)。现在改成看调用栈上有没有
        `SandBox._guarded` / `SandBox.violation` 的 **code 对象**:这两个 code
        在装钩子时就固化在闭包里,插件把 globals 里的名字换掉影响不到,
        而且没有"置一个数就全放行"的开关可以掰。

        (仍然只是一个门槛:插件能直接 `box._guarded(fn)` 从而真的产生
        `_guarded` 帧 —— 见文件头的"没堵住的"。)

        第十一批(性能,`hook_fastpath`):多加一个**探栈专用**的重入标志 `_probe`。
        动机(实测):读 `frame.f_code` 会发 `object.__getattr__` 审计事件,而那个
        事件又回到本函数 —— 于是"读一次 f_code"变成"再读一次 f_code",一次
        `open()` 在装钩子后能放大成上百个事件。加了 `_probe` 之后,探栈期间自己
        产生的审计事件**不再重入探栈**(仍会走 `_hook` 其余判定,不必担心漏判:
        那期间栈上若真有插件帧,`_hook_box_on_stack` 照样认得出它)。

        注意 `_probe` 与 `_frame_probe` 的分工:`_frame_probe` 防的是 `sys._getframe`
        自身的重入(3.13+ 它自己发事件,不加会无限递归崩栈);`_probe` 防的是
        `f_code` 读取的重入(不崩,但会把开销放大几十倍)。两个都不能省。
        """
        # 自 3.13 起 `sys._getframe` 自己就发审计事件,而这里非得用它探栈:
        # 不挡重入就是 钩子 -> _getframe -> 钩子 -> … ,实测直接静默栈溢出退出。
        if _frame_probe[0] or _probe[0]:
            return False
        _probe[0] = True
        _frame_probe[0] = True
        try:
            frame = sys._getframe(1)
            seen = 0
            while frame is not None and seen < 64:
                code = frame.f_code
                if code is _guard_code or code is _violation_code:
                    return True
                frame = frame.f_back
                seen += 1
            return False
        finally:
            _frame_probe[0] = False
            _probe[0] = False

    def _hook(event,args):
        # 第十一批(性能,`hook_fastpath`):先做**零探栈**的快筛。
        #
        # 为什么必须放在最前面:`_hook_in_facade_frame()` 要读 `frame.f_code` 才能
        # 认出"门面帧",而读 `f_code`/`sys._getframe` 在 3.13+ 自己就发审计事件 ——
        # 于是钩子对自己产生的每个事件都要再探一次栈,一次 `open()` 变成 138 个事件
        # (实测 0.635ms -> 0.280ms 就卡在这一步)。快筛只认"`_hook_target` 可能关心的
        # 事件名":不在表里、且第一个参数不是路径的事件,原逻辑也是返 None 放行,
        # 这里只是把这一步提前到"碰栈之前"。
        # 条件比原逻辑**严**(事件名不在表里但第一个参数是路径时,照旧走完整判定),
        # 所以不会在这条路上丢事件;`os.rename`/`os.replace` 的路径在第 2 个参数上,
        # 但它们在表里,不受影响。
        # 代价:无关事件不再做下面那两处防篡改对账 —— 那两处与事件类型无关,
        # 下一个被跟踪的事件照样会对账,不会长期失明。
        if event not in _tracked_events:
            if not args or not _is_pathlike_fn(args[0]):
                return
        # 门面/宿主替插件做的事:权限刚查过,放行(也避免 realpath 之类递归)
        if _hook_in_facade_frame():
            return
        _facade_enter()
        try:
            # 注册表被人清过/换过 => 这一下认不出插件帧了。
            # 处置是**恢复 + 继续按调用者判定**,不是"拒绝一切":
            #   * 恢复:不恢复的话宿主自己的 after/winfo/logging 也会撞
            #     SandboxDenied,插件清一次表就能把播放器一起拖垮
            #     (实测崩在 b.py 的 on_resize);
            #   * 继续判定:恢复之后这一帧照样能认出是不是插件 —— 是插件就
            #     按正常规则拒(它自己跑不掉),是宿主就放行(不误伤)。
            if _registrar.tampered(len(_tags)):
                restored = _registrar.rebuild(_tags,_dirs,_norm_fn)
                if not _tamper_state['reported']:
                    _tamper_state['reported'] = True
                    box = _registrar.sample_box()
                    if box is not None:
                        box.violation('registry',
                                      f'插件注册表被清空/替换过;已按记账恢复 {restored} 条,'
                                      f'本次调用继续按正常规则判定(此提示只记一次)',None)
            # 第六批:code 身份表也被清过 => 按记账恢复(和上面同一种处置)。
            # 不恢复的话,"插件帧"会全部认不出来 —— 那不是"更严",而是**失明**:
            # 钩子会把插件干的事当宿主放行,比原来更糟。
            if _led.tampered(len(_led.boxes_by_id)):
                restored_codes = _led.rebuild()
                if not _tamper_state['codes_reported']:
                    _tamper_state['codes_reported'] = True
                    box = _registrar.sample_box()
                    if box is not None:
                        box.violation('registry',
                                      f'插件 code 身份表被清空/替换过;已按记账恢复 '
                                      f'{restored_codes} 个盒子,本次调用继续按正常规则判定'
                                      f'(此提示只记一次)',None)
            target = _hook_target(event,args)
            if target is None:
                return
            box = _hook_box_on_stack()
            if box is None:
                return                          # 不是插件干的
            # 判权走闭包抓到的 _auth_can(读 _AUTH 记账),**不回调 box.can**:
            # 逃逸样本第 08 步把 box.can 换成恒真之后,门面和审计钩子会同时失明;
            # 现在钩子根本不看那个属性,换掉它只影响插件自己的自查。
            ent = _entry_fn(box)
            cap,path,what = target
            paths = path if isinstance(path,list) else [path]
            for one in paths:
                if cap == 'fs:read' and one and _hook_readable(one):
                    continue
                if not _can_fn(ent,cap,one):
                    box.violation('audit',f'绕过沙盒门面的 {what} 被审计钩子拦下',one)
                    raise SandboxDenied(
                        f'插件 {box.name} 的 {what} 绕过了沙盒门面,被审计钩子拒绝:{one}')
        except SandboxDenied:
            raise
        except Exception:
            # 钩子自己出问题不能把播放器带崩:记一次日志后放行
            if not getattr(_depth,'warned',False):
                _depth.warned = True
                logging.exception('沙盒审计钩子内部出错,该事件放行')
        finally:
            _facade_exit()

    globals()['_AUDIT_HOOK'] = _hook               # 方便自测/排查,插件改不了它的引用
    sys.addaudithook(_hook)
    logging.info('插件沙盒审计钩子已安装')
    return True


def _audit_hook(event,args):
    """保底包装:直接调本函数(而不是靠 addaudithook)时也走同一套判定。"""
    hook = globals().get('_AUDIT_HOOK')
    if hook is None:
        install_audit_hook()
        hook = globals().get('_AUDIT_HOOK')
    if hook is None:
        return
    return hook(event,args)


_ALWAYS_READABLE = tuple(_norm(p) for p in
                         (sys.prefix,sys.base_prefix,os.path.dirname(os.__file__))
                         if p)
if __name__ == "__main__":
    env = env_box()
    env_id = 'main'
    m = input('file path:')
    if not os.path.isfile(m):
        exit(1)
    cm = open(m,'r',encoding='utf-8').read()
    b = parse_policy(None,[],'.')
    box = env.create(env_id,'main','.',
                            b,
                            _host_token=_HOST_TOKEN)
    d = box.namespace
    for w in b.warnings:
        print(f'[沙盒] {"."}:{w}')
    
    

    try:
    
        # 先编译:语法错误在这里就能拿到,不用等回调里再炸
        code = compile(cm,f'<file main>','exec')
    except Exception as e:
        logging.exception('编译插件 init 代码失败')
    install_audit_hook()
    try:
    
        exec(code,d)
    except SandboxDenied as e:
        # 被沙盒挡下属于"预期内"的结果:一行干净提示,不吓人
        logging.warning('文件 的 init 被沙盒拦截:%s',e)
        print(f'[沙盒] 文件的 init 被拦截:{e}')
    except Exception as e:
        logging.exception('执行 代码失败')
        print(f'文件错误:{e}')
        traceback.print_exc()
    
