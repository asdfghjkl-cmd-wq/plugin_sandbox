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

_HOST_TOKEN = object()

ASK_YES = 'yes'
ASK_SESSION = 'session'
ASK_ALWAYS = 'always'
ASK_NEVER = 'never'

class SandboxDenied(Exception):
    pass

def _norm_uncached(path):
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

_NORM_CACHE = {}
_NORM_CACHE_MAX = 8192
_NORM_CWD = None

def _norm(path,_isabs=os.path.isabs):
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
        _NORM_CACHE.clear()
    _NORM_CACHE[key] = got
    return got

def _norm_cache_clear():
    _NORM_CACHE.clear()

_norm.cache_clear = _norm_cache_clear
_norm.__wrapped__ = _norm_uncached

def under(root, path):
    r = _norm(root)
    p = _norm(path)
    if r is None or p is None:
        return False
    if r == p:
        return True
    # S2:原来用 p.startswith(r + os.sep) 判包含。前缀比较在"根退化成卷根"
    # 时会被放大(C: + sep -> C:\ 会匹配整个 C 盘),也和 b.py 的 _is_within
    # 口径不一致(那边专门用 commonpath 并写了理由)。这里对齐成 commonpath:
    # 不同盘符/UNC 共享会抛 ValueError,那一定不是"之内"。
    try:
        return os.path.commonpath([r,p]) == r
    except (ValueError,OSError,TypeError):
        return False

def _mode_writes(mode):
    return any(c in mode for c in ('w','a','x','+'))

class Policy:

    _FREEZE_KEYS = frozenset(('fs_read','fs_write','net','proc','ask','unsafe',
                              'unsafe_requested','modules','modules_requested',
                              'plugin_dir','warnings'))

    def __init__(self,plugin_dir):
        self.plugin_dir = os.path.abspath(plugin_dir)
        self.fs_read = [self.plugin_dir]
        self.fs_write = []
        self.net = False
        self.proc = False
        self.ask = True
        self.unsafe = False
        self.unsafe_requested = False
        self.modules = []
        # 插件在 plugin.json 里只能"申请"模块:modules_requested 是插件填的,
        # modules 只有宿主 approve_modules() 之后才会非空
        self.modules_requested = []
        self.warnings = []
        self._frozen = False

    def __setattr__(self,name,value):
        if getattr(self,'_frozen',False) and name in self._FREEZE_KEYS:
            raise SandboxDenied(f'插件沙盒策略已封存,不能再改 {name}')
        object.__setattr__(self,name,value)

    def __delattr__(self,name):
        if getattr(self,'_frozen',False) and name in self._FREEZE_KEYS:
            raise SandboxDenied(f'插件沙盒策略已封存,不能再删 {name}')
        object.__delattr__(self,name)

    def roots(self,write):
        if write:
            return list(self.fs_write)
        return list(self.fs_read) + list(self.fs_write)

    def freeze(self):
        self.fs_read = tuple(self.fs_read)
        self.fs_write = tuple(self.fs_write)
        self.modules = tuple(self.modules)
        self.modules_requested = tuple(self.modules_requested)
        self.warnings = list(self.warnings)
        self._frozen = True

    def frozen(self):
        return bool(self._frozen)

    def snapshot(self):
        snap = Policy(self.plugin_dir)
        snap.fs_read = tuple(self.fs_read)
        snap.fs_write = tuple(self.fs_write)
        snap.net = bool(self.net)
        snap.proc = bool(self.proc)
        snap.ask = bool(self.ask)
        snap.unsafe = bool(self.unsafe)
        snap.unsafe_requested = bool(self.unsafe_requested)
        snap.modules = tuple(self.modules)
        snap.modules_requested = tuple(self.modules_requested)
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
        pend = [m for m in self.modules_requested if m not in tuple(self.modules)]
        if pend:
            out.append('申请额外模块:' + ','.join(pend) + '(未批准)')
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
                    # 只进 modules_requested:放行与否要宿主 approve_modules() 明示批准
                    p.modules_requested.append(item)
                else:
                    p.warnings.append(f'sandbox.modules 里的 {item!r} 不是合法模块名,已忽略')
            if p.modules_requested:
                p.warnings.append('sandbox.modules 只是申请,需要宿主 approve_modules() 明示批准')

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

_PROXY_DATA = weakref.WeakKeyDictionary()

def _free_method(func,name='open'):
    """把绑定方法换成"不带 __self__"的普通函数。

    沙盒里的 open 一律走 SandBox.fs_open,但直接把**绑定方法**交出去,插件一行
    `open.__self__` 就拿到整个 SandBox 对象(随后 object.__setattr__ 改 _ask 就能
    自我放行)。这里用闭包包一层:调用行为完全不变,但插件没法再顺着 __self__
    一步拿到宿主对象 —— 这正是 S1 在 SandboxView 上做过的同类处理。

    同进程内省仍能顺着 __closure__ 摸回去,那是 SANDBOX.md 已声明的固有上限;
    这里堵的是"完全不需要内省"的那条直连。故意不用 functools.wraps:它会挂上
    __wrapped__ 指回原绑定方法,等于把刚堵掉的门又开一条。
    name 要显式给:绑定方法的 __name__ 是 'fs_open',直接透传会让插件看到
    `open.__name__ == 'fs_open'`,与内建语义不符。
    """
    def _call(*args, **kwargs):
        return func(*args, **kwargs)
    _call.__name__ = name
    _call.__doc__ = getattr(func, '__doc__', None)
    return _call

_AUDIT_LOG = {}          # id(box) -> list,模块私有的审计记账
_NEVER_ASK_LOG = {}      # id(box) -> set,封存时从 box._never_ask 拷一份独立副本


def _audit_log(box,_logs=_AUDIT_LOG):
    """审计记录放在模块私有的表里,不放 box.events。

    box.events 是可变的实例属性,插件拿到 box 后一句 `box.events.clear()` 就能
    把审计轨迹抹掉(SANDBOX.md 55 行想守住的正是"拦得住也要记下");__setattr__
    只拦赋值,拦不住容器内容。同进程内省仍能摸到这张表,那属于已声明的固有上限。
    """
    log = _logs.get(id(box))
    if log is None:
        log = []
        _logs[id(box)] = log
    return log


def _safe_repr(value):
    """把任意值变成可打印的字符串,**绝不调用插件对象的 __str__/__repr__**。

    note/violation 的 code 对象在审计钩子的信任名单里(_hook_in_facade_frame 一见
    栈上有它们就整体放行),所以在它们的动态范围内对插件交来的对象做 str()/
    f-string 格式化,等于给插件开了一段免检区:它只要在 __str__ 里做 I/O,那次
    I/O 就不会被判权、也不留 violation。这里只认 str/数字,其余只报类型名。
    """
    if value is None or isinstance(value,(str,int,float,bool)):
        return value
    try:
        return '<%s>' % type(value).__name__
    except Exception:
        return '<不可打印对象>'


def _real_of(obj):
    try:
        return _PROXY_DATA[obj][1]
    except (KeyError,TypeError):
        return obj

def _is_child_module(label,value):
    name = getattr(value,'__name__',None) or ''
    return bool(label) and name.startswith(label + '.')

class _Proxy:

    __slots__ = ('__weakref__',)

    def __init__(self,sb,real,label,allow=None,wrap=None,deny=(),extra=None):
        merged = dict(wrap or {})
        if extra:
            merged.update(extra)
        _PROXY_DATA[self] = (
            sb,
            real,
            label,
            None if allow is None else frozenset(allow),
            merged,
            frozenset(deny or ()),
        )

    def __getattribute__(self,name):
        if name == '_d':
            try:
                sb,_,label = _PROXY_DATA[self][:3]
            except (KeyError,TypeError):
                raise AttributeError(name)
            sb.violation('module_attr',f'插件不能访问 {label}._d',None)
            raise SandboxDenied(
                f'插件不能访问 {label}._d(那是门面的内部数据,拿走就等于把真模块交出去)')
        if name.startswith('__') and name.endswith('__'):
            # 这段判断原来只写在 __getattr__ 里,而 __getattr__ 仅在
            # __getattribute__ 抛 AttributeError 之后才被调用 —— __class__/
            # __init__/__repr__/__dir__/__getattr__ 这些名字都挂在 _Proxy 类型上,
            # 会被下面那句 object.__getattribute__ 直接命中,那段代码等于从未生效:
            # `os.__class__.__init__.__globals__` 一路通到本模块的 globals。
            raise AttributeError(name)
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
                wrap[item] = child
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

    __slots__ = ('name','can','describe','events')

    def __init__(self,sb):

        name = sb.name
        describe = sb.policy.describe
        events = sb.audit
        check = sb.can
        # S1:这里**不能**留任何指向宿主对象的引用。原来写的是
        #   self.can = sb.can ; self.describe = sb.policy.describe ...
        # 绑定方法自带 __self__,插件一行 `__sandbox__.can.__self__` 就拿到了
        # SandBox 本体(然后 __globals__ 拿到 _HOST_TOKEN/真 os)。
        # 更隐蔽的一版是把它们存成 _check 这类私有属性 —— 下划线只是命名约定,
        # 实例上照样 `view._check.__self__` 一步到位。
        # 所以改成:绑定方法只活在闭包格子里,实例属性一律是不带 __self__ 的
        # 普通函数。闭包仍能被 __closure__ 取出(同进程不可能根治),但少了
        # "属性 -> 宿主对象"这条最省事的直连。
        def _describe():
            return describe()

        def _events(limit=20):
            return events(limit)

        def _can(cap,target=None):
            return check(cap,target)

        self.name = name
        self.describe = _describe
        self.events = _events
        self.can = _can

    def __repr__(self):
        try:
            return f'<sandbox {self.name}: {self.describe()}>'
        except Exception:
            return f'<sandbox {self.name}>'

_AUTH = {}

def _auth_entry(box,_auth=_AUTH):
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
        # 宿主的三个回调入口也搬进记账。guarded_names() 只拦 __setattr__,插件能用
        # object.__setattr__(box,'_ask',…) 或者 box.__dict__['_ask']=… 直接改写
        # 实例字典绕过去 —— 判权若还读实体属性,就等于把"用我自己的回调批准我
        # 自己"这条路原样留着。读记账这份,改写实体属性只留一条影子。
        'ask':getattr(box,'_ask',None),
        'persist':getattr(box,'_persist',None),
        'persist_deny':getattr(box,'_persist_deny',None),
    }
    _auth[id(box)] = ent
    return ent

def _auth_frozen(ent):
    return ent['frozen'] if ent['frozen'] is not None else ent['policy']

def _auth_domain(ent,cap,_frozen=_auth_frozen):
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
        if org is None:
            return bool(ent['session'][cap])
        return bool(ent['session'][cap]) and bool(org.get(cap))
    else:
        return None
    if keep is None:
        return roots
    return tuple(r for r in roots if r in base or r in keep)

def _auth_can(ent,cap,target=None,_under=under,_domain=_auth_domain,
              _frozen=_auth_frozen):
    pol = _frozen(ent)
    if pol.unsafe:
        return True
    if cap in ('fs:read','fs:write'):
        # 空路径按"没有目标"处理:under(root,'') 在 Windows 上会把空串归一成
        # 当前工作目录,于是空路径反而落进授权根 —— 与 b.py 的 _is_within
        # (空 -> False)以及 S2 注释自称的对齐口径正好相反。
        if not target:
            return False
        roots = _domain(ent,cap)
        return any(_under(r,target) for r in roots)
    if cap in ('net','proc'):
        return _domain(ent,cap)
    raise ValueError(f'未知能力:{cap!r}')

def _auth_snapshot_sets(ent):
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
    ent = _entry(box)
    ent['policy'] = box.policy
    _snapshot(ent)
    # "不再询问"在封存时拷一份**独立副本**进记账。box._never_ask 是可变的实例
    # 属性,__setattr__ 只拦赋值、拦不住 clear():插件清掉它,用户点过的"不再询问"
    # 就全部失效,同一个越权请求会被重新弹窗,再点一次"允许"就等于被绕过一次。
    ent['never_ask'] = set(getattr(box,'_never_ask',()) or ())
    box._policy_frozen = _frozen(ent)
    box._org = dict(ent['org'])
    return ent

def _auth_apply_grant(box,cap,target_root,_entry=_auth_entry,
                      _snapshot=_auth_snapshot_sets,_frozen=_auth_frozen):
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
        _snapshot(ent)
        # 封存后 guarded_names() 会让普通赋值抛 SandboxDenied(_policy_frozen/_org
        # 都在那个名单里),但这里是沙盒**内部**在同步影子副本,属于合法更新,必须
        # 用 object.__setattr__ 绕开自己的护栏。否则用户点"本次运行都允许/总是允许"
        # 会先改完 ent['session'](判权真正读的那份)再抛异常:授权没生效、note 走不到、
        # _persist 也走不到("总是允许"永远不落盘),还留下一条假的 tamper 报警。
        object.__setattr__(box,'_policy_frozen',_frozen(ent))
        object.__setattr__(box,'_org',dict(ent['org']))

def _auth_tamper(box,_entry=_auth_entry):
    ent = _entry(box)
    if ent['org'] is None:
        return
    live = box.policy
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

class SandBox:

    def __init__(self,env_id,name,plugin_dir,policy,_entry=_auth_entry):
        self.env_id = env_id
        self.name = name
        self.policy = policy
        self.plugin_dir = os.path.abspath(plugin_dir)
        self._norm_dir = _norm(self.plugin_dir)
        self._sealed_at = None
        self._policy_frozen = None
        self._org = None
        self._tamper_warned = set()
        self.namespace = {}
        self.events = []
        self._session = {'fs:read':set(),'fs:write':set(),'net':False,'proc':False}
        self._never_ask = set()
        self._ask = None
        self._persist = None
        self._persist_deny = None
        self._host = None
        self._facade = None
        self._local_modules = {}
        self._module_cache = {}
        self.__sealed = False
        self._code_series = 0
        self._identity_ok = True
        self._build_namespace()
        _entry(self)
        register_plugin_frames(self)
        _ledger.remember_box(self)
        _PLUGIN_BOXES[id(self)] = self
        self._register_own_code()

    def _own_sources(self):
        # 返回 ():插件没有可登记的源码;返回 None:读取/解析失败(身份登记失败)
        try:
            path = os.path.join(self.plugin_dir,'plugin.json')
            with io.open(path,'r',encoding='utf-8') as fp:
                n = _json.load(fp)
            if not isinstance(n,dict):
                print(f'[沙盒] 插件 {self.name} 的 plugin.json 不是对象,身份登记失败')
                return None
            out = []
            failed = False
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
                        failed = True
                        print(f'[沙盒] 读取 {fname} 失败,身份登记失败,该插件不应运行')
                        continue
                if src.strip():
                    out.append((src_key,src))
            if failed:
                return None
            return tuple(out)
        except Exception:
            print(f'[沙盒] 插件 {self.name} 的 plugin.json 读取/解析失败,'
                  f'身份登记失败,该插件不应运行')
            return None

    def _register_own_code(self):
        ok = True
        srcs = self._own_sources()
        for kind,src in (srcs or ()):
            try:
                code = compile(src,f'<plugin {self.name} {kind}>','exec')
            except Exception as e:
                ok = False
                print(f'[沙盒] 插件 {self.name} 的 {kind} 源码无法编译,'
                      f'身份登记失败,该插件不应运行:{e}')
                continue
            self.register_plugin_code(code)
        if srcs is None:
            ok = False
        self._identity_ok = ok

    @property
    def identity_ok(self):
        return bool(getattr(self,'_identity_ok',False))

    def guarded_names(self):
        return frozenset((
            'can','violation','note','events',
            '_policy_frozen','_org','_session','policy','_sealed_at',
            'namespace','_norm_dir','plugin_dir','name','env_id',
            # S3:这三个是宿主的回调入口,封存后不该再被换(装载期照常设置)
            '_ask','_persist','_persist_deny',
        ))

    def __setattr__(self,name,value):
        if name in SandBox.guarded_names(self) and getattr(self,'_sealed_at',None) is not None:
            raise SandboxDenied(
                f'插件 {self.name} 的沙盒已封存,不能再改 {name}'
                f'(判权入口/策略在封存之后就不可变)')
        object.__setattr__(self,name,value)

    def _plugin_caller(self):
        try:
            frame = sys._getframe(1)
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
        caller = self._plugin_caller()
        self.violation(what,
                       f'插件代码帧调用了宿主专用入口({what}),已拒绝',
                       getattr(caller,'name',None))
        raise SandboxDenied(
            f'插件 {self.name} 不能从插件代码里调用 {what}(只有宿主能)')

    @property
    def frame_tag(self):
        return f'<plugin {self.name} '

    def _guarded(self,func,*args,_auth=None,_entry=_auth_entry,_can=_auth_can,
                 _tamper=_auth_tamper,**kwargs):
        # 第 8 批把"插件直接调 _guarded()"堵在 _plugin_code_at(1),但当时还留了
        # 一个 _allow_plugin_caller=True 的豁免开关 —— 它是**方法参数**,插件自己
        # 传一个关键字参数就能把整道守卫短路:
        #     box._guarded(fn,_allow_plugin_caller=True)
        # 全仓库没有任何调用点需要它(宿主侧调用时栈上本来就没有插件帧,走不到
        # _plugin_code_at(1) 这条分支),所以直接删除,不再给调用方这个权限。
        if (_auth is None and _plugin_code_at(1)):
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
        return func(*args,**kwargs)

    def seal(self):
        self.policy.freeze()
        _auth_bind(self)
        self._sealed_at = True
        self.__sealed = True
        self.note('seal','*',None,f'策略冻结:{self.policy.describe()}')

    def is_sealed(self):
        return self.__sealed

    def _policy_for_can(self,_entry=_auth_entry,_tamper=_auth_tamper):
        ent = _entry(self)
        if ent['frozen'] is None:
            return self.policy
        _tamper(self)
        return ent['frozen']

    def grant(self,*args,_host_token=None,**kwargs):
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
        if _host_token is not _HOST_TOKEN:
            self.violation('set_unsafe','插件试图解除自己的沙盒限制',None)
            raise SandboxDenied(f'插件 {self.name} 不能解除自己的沙盒限制')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('set_unsafe')
        if self.is_sealed():
            raise SandboxDenied(f'插件 {self.name} 的沙盒已封存,不能再改')
        self.policy.unsafe = bool(value)
        self.note('unsafe','*',None,f'unsafe={bool(value)}')

    def approve_modules(self,names,_host_token=None):
        # host-only:插件在 plugin.json 里写的 modules 只是"申请",只有宿主能放行
        if _host_token is not _HOST_TOKEN:
            self.violation('approve_modules','插件试图给自己放行模块',None)
            raise SandboxDenied(f'插件 {self.name} 不能给自己放行模块(只有宿主能)')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('approve_modules')
        if self.is_sealed():
            raise SandboxDenied(f'插件 {self.name} 的沙盒已封存,不能再放行模块')
        cur = list(self.policy.modules)
        for item in (names or ()):
            if not isinstance(item,str) or not re.fullmatch(r'[A-Za-z_][\w.]*',item):
                self.violation('approve_modules',f'{item!r} 不是合法模块名,未放行',None)
                continue
            if item not in cur:
                cur.append(item)
        self.policy.modules = cur
        self.note('approve_modules','*',None,f'宿主放行模块:{",".join(cur) or "无"}')
        return tuple(cur)

    def _apply_grant(self,cap,target,persist=False,_entry=_auth_entry):
        # 用 _grant_scope 而不是 _grant_root:授权往往发生在文件被创建之前,
        # 那时 isfile 为假,必须把"即将新建的文件"归一成它所在的目录,
        # 否则会话里存的是文件路径,目录级的 under() 判定永远通不过。
        root = self._grant_scope(target) if cap in ('fs:read','fs:write') else None
        if cap in ('fs:read','fs:write'):
            self._session[cap].add(root)
            if cap == 'fs:write':
                self._session['fs:read'].add(root)
            self.policy.warnings.append(f'宿主额外授予 {cap} = {root}')
        elif cap in ('net','proc'):
            self._session[cap] = True
        else:
            raise SandboxDenied(f'没有这种能力:{cap!r}')
        _auth_apply_grant(self,cap,root)
        persist_fn = _entry(self).get('persist')
        if persist and persist_fn is not None:
            try:
                persist_fn(self.name,cap,root if target else True)
            except Exception:
                logging.exception('保存插件授权失败')

    def _grant_root(self,target):
        """授权**作用域**的判定基元,契约由 tests/security_check_fixed.py 固定:

        * 不存在的目标 -> 原样返回(不许上浮到父目录,否则"授权一个文件"会变成"授权整盘")
        * 已存在的目录 -> 原样返回
        * 已存在的文件 -> 返回所属目录(白名单是目录级的)

        注意它**不**负责"把即将新建的文件归一成目录"。要那个语义请用
        _grant_scope()。
        """
        if not target:
            return None
        target = os.path.abspath(os.fspath(target))
        if os.path.isfile(target):
            return os.path.dirname(target) or target
        return target

    def _grant_scope(self,target):
        """把一次授权归一成"实际会被放开的目录"。

        与 _grant_root 的差别只有一处:目标看起来是个**尚不存在的文件**时,
        它取父目录,而不是把文件路径本身当成授权根。

        为什么必须这样:fs_open 的判权是 under(root, path),粒度是目录。而授权
        发生在文件**被创建之前** —— 此时 os.path.isfile 为假,走 _grant_root 会把
        "…\\b.txt" 当作授权根;下一个文件 "…\\c.txt" 自然不在它下面,
        于是"用户刚点了允许写入、同目录的下一个文件又被拒",can() 也恒为假
        (tests/test_sandbox_core.py 的 t_fs_ask 实测)。
        """
        root = self._grant_root(target)
        if root is None:
            return None
        if root.endswith(os.sep) or os.path.isdir(root):
            return root
        # 剩下的是"看起来像尚不存在的文件"的情形,上浮到父目录。但必须确认父目录
        # **真实存在**且不是卷根,否则上浮会把一次授权放大成整个盘符:目标是不存在的
        # 目录 D:\music\newdir 时,dirname 得到 D:\,一次"总是允许"就放开了整个 D 盘;
        # 再叠上"不再询问"就是永久静音。
        parent = os.path.dirname(root)
        if not parent or parent == root:
            return root
        if not os.path.isdir(parent) or os.path.dirname(parent) == parent:
            return root
        return parent

    def set_ask(self,func,_host_token=None,_entry=_auth_entry):
        # S3:与 grant/set_unsafe 同口径。原先这三个 set_* 既没有宿主凭据、
        # 也不做插件帧检查,而 _ask 又不在 guarded_names() 里 —— 插件拿到 box
        # 后 `box.set_ask(lambda *a:'always')` 就能让 _ask_user 收到 ASK_ALWAYS,
        # 再走 _apply_grant 把自己永久授权,等于一条"用我自己的回调批准我自己
        # 的请求"的提权链。
        # 这里用「可选凭据 + 帧检查」而不是强制凭据:本仓库里 set_ask 还有
        # 十余处宿主侧/探针侧调用点,强制会让它们全部 TypeError。
        if _host_token is not _HOST_TOKEN:
            try:
                blocked = bool(is_plugin_frame_on_stack())
            except Exception:
                blocked = True
            if blocked:
                self.violation('set_ask',
                               '插件试图替换自己的权限询问回调(等于自我放行)',None)
                raise SandboxDenied(
                    f'插件 {self.name} 不能替换权限询问回调(只有宿主能)')
        self._ask = func
        _entry(self)['ask'] = func

    def set_persist(self,func,_host_token=None,_entry=_auth_entry):
        # 同上:换成别人的持久化回调就能把"总是允许"写进 config.json
        if _host_token is not _HOST_TOKEN:
            try:
                blocked = bool(is_plugin_frame_on_stack())
            except Exception:
                blocked = True
            if blocked:
                self.violation('set_persist','插件试图替换授权持久化回调',None)
                raise SandboxDenied(
                    f'插件 {self.name} 不能替换授权持久化回调(只有宿主能)')
        self._persist = func
        _entry(self)['persist'] = func

    def set_persist_deny(self,func,_host_token=None,_entry=_auth_entry):
        if _host_token is not _HOST_TOKEN:
            try:
                blocked = bool(is_plugin_frame_on_stack())
            except Exception:
                blocked = True
            if blocked:
                self.violation('set_persist_deny','插件试图替换"不再询问"持久化回调',None)
                raise SandboxDenied(
                    f'插件 {self.name} 不能替换"不再询问"持久化回调(只有宿主能)')
        self._persist_deny = func
        _entry(self)['persist_deny'] = func

    def remember_denied(self,cap,target,_host_token=None):
        if _host_token is not _HOST_TOKEN:
            self.violation('remember_denied',
                           '插件试图制造"不再询问"记录',f'{cap} {target or ""}')
            raise SandboxDenied(f'插件 {self.name} 不能伪造"不再询问"记录(只有宿主能)')
        if is_plugin_frame_on_stack():
            self.refuse_plugin_caller('remember_denied')
        key = self._ask_key(cap,target)
        self._never_ask.add(key)
        ent = _entry(self)
        never = ent.get('never_ask')
        if never is not None:
            never.add(key)
        self.note('ask_never_restored',cap,target,'按 config.json 恢复"不再询问"')
        return True

    def attach_host(self,tkaapp,facade=None,**kwargs):
        self._host = tkaapp
        if tkaapp is None:
            return None
        self._facade = HostFacade(self,tkaapp) if facade is None else facade
        self.namespace['pro'] = self._facade
        return self._facade

    def audit(self,limit=20):
        # 读模块私有的记账那份,不读 self.events:后者是插件能 clear() 的影子。
        return list(_audit_log(self)[-limit:])

    def note(self,action,cap,target,detail=''):
        # target/detail 一律不交给插件对象的 __str__(见 _safe_repr)。
        rec = {'plugin':self.name,'action':action,'cap':cap,
               'target':_safe_repr(target),'detail':_safe_repr(detail)}
        log = _audit_log(self)
        log.append(rec)
        if len(log) > 200:
            del log[:100]
        # 影子副本:保持 box.events 这个老接口仍能读,但清它不影响上面那份。
        try:
            self.events.append(rec)
            if len(self.events) > 200:
                del self.events[:100]
        except Exception:
            pass
        return rec

    def violation(self,action,detail,target):
        self.note('violation:'+action,'*',target,detail)
        # logging 的惰性 %s 和 f-string 都在本方法的动态范围内执行,同样不能碰
        # 插件对象 —— 先在这里转成安全字符串再传出去。
        logging.warning('插件 %s 触发沙盒拦截:%s(%s)',self.name,
                        _safe_repr(detail),_safe_repr(target))
        print(f'[沙盒] 插件 {self.name}:{_safe_repr(detail)}')

    def can(self,cap,target=None,_entry=_auth_entry,_can=_auth_can,
            _tamper=_auth_tamper):
        ent = _entry(self)
        if ent['frozen'] is not None:
            _tamper(self)
        return _can(ent,cap,target)

    def _ask_key(self,cap,target):
        if not target:
            return (cap,'')
        if cap in ('fs:read','fs:write'):
            # 与 _apply_grant 用同一个作用域口径,否则"不再询问"记下的键
            # 和实际授权出去的目录对不上
            root = self._grant_scope(target) or _norm(target)
            return (cap,_norm(root) or str(target))
        return (cap,str(target))

    def _ask_user(self,cap,target,detail,_entry=_auth_entry):
        pol = self._policy_for_can()
        if pol.unsafe:
            return True
        # 回调从记账读,不读 self._ask:封存后插件可以用 object.__setattr__ 或
        # box.__dict__ 改写实例字典(guarded_names 只拦 __setattr__)。
        ent = _entry(self)
        ask = ent.get('ask')
        if not pol.ask or ask is None:
            return False
        if threading.current_thread() is not threading.main_thread():
            self.note('ask_skipped',cap,target,'不在主线程,不能弹窗,直接拒绝')
            return False
        key = self._ask_key(cap,target)
        # 读封存时拷下来的独立副本(见 _auth_bind):box._never_ask 是可变的实例
        # 属性,插件 clear() 一下就能让已静音的申请重新弹窗。
        never = ent.get('never_ask')
        if never is None:
            never = self._never_ask
        if key in never:
            self.note('ask_muted',cap,target,'你之前选了"不再询问",直接拒绝')
            return False
        try:
            # target/detail 先转成安全字符串再交给宿主回调:弹窗会在 _guarded 的
            # 信任帧里对它们做 f-string 格式化,插件交一个自定义对象、在 __str__
            # 里做 I/O,就能借这次弹窗无判权地跑通。
            ans = self._guarded(ask,self,cap,
                                _safe_repr(target),_safe_repr(detail))
        except Exception:
            logging.exception('插件沙盒的授权询问失败,按拒绝处理')
            return False
        if ans == ASK_NEVER:
            never.add(key)
            self._never_ask.add(key)
            self.note('ask_never',cap,target,'用户点了"不再询问",以后这一类不再弹窗')
            pden = ent.get('persist_deny')
            if pden is not None:
                try:
                    pden(self.name,cap,
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
        self.note('denied_by_user',cap,target,detail)
        return False

    def deny(self,cap,target,what):
        self.violation('deny',f'{what or "操作"}需要能力 {cap},未获授权',target)
        raise SandboxDenied(
            f'插件 {self.name} 的 {what or "操作"} 需要 {cap} 能力,'
            f'而它没有被授权:{target if target is not None else ""}')

    def check_fs(self,path,write=False,what='',_entry=_auth_entry,_can=_auth_can):
        if isinstance(path,int):
            self.violation('fd','不支持用文件描述符访问文件',path)
            raise SandboxDenied('沙盒不允许用文件描述符(fd)访问文件')
        # 判权和"真正拿去打开/列目录"的必须是**同一个字符串**。原来这里把原对象
        # 交给 _can(内部 os.fspath 一次),又把原对象原样返回给调用方(内部再
        # fspath 一次) —— 插件只要自定义 __fspath__,就能第一次返回授权路径、
        # 第二次返回真正想动的路径。这里归一一次,后面一律只用这个结果。
        try:
            path = os.fspath(path)
        except TypeError:
            pass
        cap = 'fs:write' if write else 'fs:read'
        if _can(_entry(self),cap,path):
            return path,True
        if self._ask_user(cap,path,what or ('写入文件' if write else '读取文件')):
            return path,False
        self.deny(cap,path,what)

    def check_net(self,what='网络访问',_entry=_auth_entry,_can=_auth_can):
        if _can(_entry(self),'net'):
            return True,True
        if self._ask_user('net',None,what):
            return True,False
        self.deny('net',None,what)

    def check_proc(self,what='启动外部进程',_entry=_auth_entry,_can=_auth_can):
        if _can(_entry(self),'proc'):
            return True,True
        if self._ask_user('proc',None,what):
            return True,False
        self.deny('proc',None,what)

    def _auth_pair(self,allowed,durable,cap,target=None):
        return (cap,target) if (allowed and durable) else None

    def fs_open(self,file,mode='r',*args,**kwargs):
        if isinstance(file,int):
            self.violation('fd','不支持用文件描述符打开文件',file)
            raise SandboxDenied('沙盒不允许用文件描述符(fd)打开文件')
        # open(..., opener=cb) 会让**插件提供的回调**在 _guarded 的动态执行期内
        # 运行,而审计钩子的豁免判据是"调用栈上有 _guarded 的 code 对象" —— 整段
        # 执行都在豁免范围里,于是 cb 能无判权、无审计记录地对任意路径做 I/O
        # (夹带)。插件没有任何合理理由传自定义 opener,直接拒绝。
        # opener 是 open() 的第 8 个参数,对应 *args 的第 6 个(索引 5)。
        if kwargs.get('opener') is not None or len(args) >= 6:
            self.violation('opener','插件试图用自定义 opener 夹带文件操作',file)
            raise SandboxDenied('沙盒不允许给 open() 传 opener(它会绕开逐次判权)')
        write = _mode_writes(mode)
        cap = 'fs:write' if write else 'fs:read'
        path,durable = self.check_fs(file,write,f'open({mode!r})')
        got = self._guarded(_builtins.open,path,mode,*args,
                            _auth=self._auth_pair(True,durable,cap,path),**kwargs)
        if write:
            # 写操作可能新增/删除符号链接或 junction,realpath 结果会变,缓存要失效
            _norm_cache_clear()
        return got

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
        self._guarded(lambda:None,
                      _auth=self._auth_pair(True,durable,'fs:read',top))

        def _gen():
            for root,dirs,files in os.walk(top,*args,**kwargs):
                dirs[:] = [d for d in dirs if self.can('fs:read',os.path.join(root,d))]
                yield root,dirs,files
        return _gen()

    def fs_write_call(self,func,what,path,*args,**kwargs):
        p,durable = self.check_fs(path,True,what)
        got = self._guarded(func,p,*args,
                            _auth=self._auth_pair(True,durable,'fs:write',p),**kwargs)
        # 写成功后清 realpath 缓存(新建/删除链接、junction 会让旧结果陈旧)
        _norm_cache_clear()
        return got

    def refuse_module_call(self,what,detail):
        """明确禁用某个门面成员:记一条 violation 再拒绝,而不是静默 AttributeError。"""
        self.violation(what,detail,None)
        raise SandboxDenied(detail)

    def fs_makedirs(self,path,*args,**kwargs):
        """makedirs 的判权版:它会为每一级缺失的父目录各发一次 mkdir。

        整段 os.makedirs 跑在 _guarded 的豁免帧里,审计钩子会把期间所有
        'os.mkdir'/'os.makedirs' 事件当成"门面自己发起的"放行,所以只校验传进来的
        那个路径 = 顺手放行授权根之外所有缺失父目录的创建。这里先把会被创建出来的
        每一级都判一次权(没授权时照常给用户弹窗),再交给真实现。
        """
        head = os.path.abspath(os.fspath(path))
        missing = []
        cur = head
        while cur and not os.path.isdir(cur):
            missing.append(cur)
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        for d in missing:
            self.check_fs(d,True,'makedirs')
        p,durable = self.check_fs(path,True,'makedirs')
        got = self._guarded(os.makedirs,p,*args,
                            _auth=self._auth_pair(True,durable,'fs:write',p),**kwargs)
        _norm_cache_clear()
        return got

    def fs_rename(self,src,dst,**kwargs):
        src,_ = self.check_fs(src,True,'rename')
        dst,durable = self.check_fs(dst,True,'rename')
        auth = self._auth_pair(True,durable,'fs:write',dst)
        if kwargs.pop('replace',False):
            got = self._guarded(os.replace,src,dst,_auth=auth)
        else:
            got = self._guarded(os.rename,src,dst,_auth=auth)
        _norm_cache_clear()
        return got

    def fs_probe(self,func,path,*args,**kwargs):
        if not self.can('fs:read',path):
            self.note('probe_denied','fs:read',path,'只读探测被拒,返回空值')
            return False
        try:
            return func(path,*args,**kwargs)
        except OSError:
            return False

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

    def os_module(self):
        wrap = {
            'open':_free_method(self.fs_open),
            'listdir':self.fs_listdir,
            'scandir':self.fs_scandir,
            'stat':self.fs_stat,
            'walk':self.fs_walk,
            'mkdir':lambda p,*a,**k:self.fs_write_call(os.mkdir,'mkdir',p,*a,**k),
            # makedirs 会对"缺失的每一级父目录"各发一次 mkdir,而整段调用跑在
            # _guarded 的豁免帧里 —— 只校验叶子路径等于放行父目录的创建。
            'makedirs':self.fs_makedirs,
            'remove':lambda p,*a,**k:self.fs_write_call(os.remove,'remove',p,*a,**k),
            'unlink':lambda p,*a,**k:self.fs_write_call(os.remove,'unlink',p,*a,**k),
            'rmdir':lambda p,*a,**k:self.fs_write_call(os.rmdir,'rmdir',p,*a,**k),
            # removedirs 的语义是"删掉目标后继续删父目录",豁免粒度(整段调用)与
            # 判权粒度(叶子)错配,会删掉授权根之外的空目录。直接禁用。
            'removedirs':lambda *a,**k:self.refuse_module_call(
                'os.removedirs',
                'os.removedirs 会连带删除授权根之外的父目录,已禁用;请逐级用 os.rmdir'),
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
        return _Proxy(self,os.path,'os.path',allow=allow,wrap=wrap,
                      deny={'sameopenfile','samestat','samefile','lexists',
                            'expandvars','expanduser'})

    def sys_module(self):
        wrap = {'argv':list(sys.argv)}
        allow = {'version','version_info','platform','maxsize','float_info','int_info',
                 'byteorder','getdefaultencoding','getfilesystemencoding','getrecursionlimit',
                 'getswitchinterval','stdout','stderr','stdin',
                 'executable','hexversion','api_version','implementation'}
        deny = {'setrecursionlimit','modules','path','meta_path','path_hooks','path_importer_cache','exit','_getframe',
                'settrace','setprofile','addaudithook','breakpointhook','displayhook',
                'excepthook','unraisablehook','__interactivehook__','intern','getrefcount',
                'set_coroutine_origin_tracking_depth','_xoptions','dont_write_bytecode'}
        return _Proxy(self,sys,'sys',allow=allow,wrap=wrap,deny=deny)

    def io_module(self):
        allow = {'BytesIO','StringIO','BufferedReader','BufferedWriter','BufferedRWPair',
                 'TextIOWrapper','UnsupportedOperation','SEEK_SET','SEEK_CUR','SEEK_END',
                 'DEFAULT_BUFFER_SIZE','IOBase','BlockingIOError'}
        return _Proxy(self,io,'io',allow=allow,wrap={'open':_free_method(self.fs_open)})

    def builtins_view(self):
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
                          wrap={'FLAC':lambda *a,**k:self._guarded_mutagen(mutagen.flac.FLAC,*a,**k)}),
            'id3':_Proxy(self,mutagen.id3,'mutagen.id3',
                         wrap={'ID3':lambda *a,**k:self._guarded_mutagen(mutagen.id3.ID3,*a,**k)}),
        }
        # 仍然存在的口子(未修,记在案):mutagen 的其它子包(mp3/mp4/easyid3/
        # oggvorbis…)里同样有"会打开文件"的类,它们既不在这张 wrap 表里、也不在
        # 任何 allow 白名单里,被 _Proxy 当成普通子模块原样交出去 —— 那些构造
        # 不会走 check_fs(收不到弹窗),只能靠审计钩子事后硬拒。
        return _Proxy(self,mutagen,'mutagen',wrap=wrap)

    def guarded_image_open(self,fp,*args,**kwargs):
        auth = None
        if isinstance(fp,(str,bytes,os.PathLike)):
            fp,durable = self.check_fs(fp,False,'PIL.Image.open')
            auth = self._auth_pair(True,durable,'fs:read',fp)
        return self._guarded(_PILImage.open,fp,*args,_auth=auth,**kwargs)

    def guarded_mutagen_file(self,filething,*args,**kwargs):
        return self._guarded_mutagen(mutagen.File,filething,*args,**kwargs)

    def _guarded_mutagen(self,real_fn,filething,*args,**kwargs):
        """按"真构造函数 + 目标路径"判权(照 guarded_image_open 的写法)。

        原来 id3.ID3 / flac.FLAC 也被 wrap 到 guarded_mutagen_file,而后者固定调
        mutagen.File —— 门面名字承诺的是 ID3 标签对象/FLAC 对象,返回的却是"按
        内容猜出来"的 FileType(格式不符时是 None),ID3(path,v2_version=4) 这类
        构造参数还会直接 TypeError。
        """
        auth = None
        if isinstance(filething,(str,bytes,os.PathLike)):
            filething,durable = self.check_fs(filething,False,'读取音频标签')
            auth = self._auth_pair(True,durable,'fs:read',filething)
        return self._guarded(real_fn,filething,*args,_auth=auth,**kwargs)

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
        return _Proxy(self,real,name,allow=None,wrap=wrap,deny=deny)

    def imagetk_module(self):
        return self.safe_module('ImageTk',_PILImageTk)

    def module_builders(self):
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
            for name,mod in self._PASSTHROUGH.items():
                if '.' in name:
                    continue
                self._module_cache.setdefault(name,self.safe_module(name,mod))
        return self._module_cache

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

    _SUBMODULE_PACKAGES = ('tkinter','ttkbootstrap','PIL')

    @staticmethod
    def _dotted_exists(obj,name):
        real = _real_of(obj)
        for part in name.split('.')[1:]:
            try:
                real = getattr(real,part)
            except AttributeError:
                return False
        return True

    def _resolve_module(self,name):
        root = name.split('.')[0]
        built = self.module_builders().get(root)
        if built is not None:
            if '.' not in name:
                return built
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
            return self.safe_module(name,self._PASSTHROUGH[name])
        if root in self._PASSTHROUGH:
            if root in self._SUBMODULE_PACKAGES:
                try:
                    mod = _importlib.import_module(name)
                except Exception:
                    return None
                self.note('import_submodule','*',name,
                          f'{root} 的子模块,只提供界面/工具能力')
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
            return self._attach_fromlist(name,obj,fromlist)
        top = name.split('.')[0]
        if top == name:
            return obj
        topobj = self._resolve_module(top)
        return obj if topobj is None else topobj

    def import_local(self,name):
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
            # 插件本地模块的 code 也要登记进 code 账本:否则它在栈上是一棵"不
            # 认识的 code",_guarded 的直接调用者判据(_plugin_code_at(1))会把
            # "从本地模块里调 box._guarded()"当成宿主调用而放行(第 8 批逃逸的
            # 本地模块路径)。顺手也消掉 _box_for_frame 那条基于文件名的兜底
            # 认帧 —— 它会额外留一条假的 violation:fake_frame。
            register_plugin_code(self,code)
            exec(code,mod.__dict__)
        except Exception:
            del self._local_modules[name]
            raise
        return mod

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
        b['open'] = _free_method(self.fs_open)
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
        # S6:原来是把 __builtins__ 直接写进调用方传进来的 dict。插件可以把
        # **别人的**字典当 globals 传进来(捕获到的帧的 f_globals、_AUTH、
        # _FRAME_TAGS……),于是这个"防御动作"反而改写了宿主的数据结构。
        # 改成:只认自己的命名空间,别处的 dict 复制一层再注入。
        if isinstance(globals,dict) and globals is not self.namespace:
            g = dict(globals)
        else:
            g = self.namespace
        g['__builtins__'] = self.restricted_builtins()
        return g

    def sandbox_eval(self,source,globals=None,locals=None):
        g = self._scope(globals)
        if type(source) is type((lambda: 0).__code__):
            register_plugin_code(self,source)
        else:
            # 同 sandbox_exec:字符串源码自己编译并登记,否则它的帧在 _guarded
            # 的直接调用者判据里认不出来。
            source = compile(source,f'<plugin {self.name} eval>','eval')
            register_plugin_code(self,source)
        return _builtins.eval(source,g,g if locals is None else locals)

    def sandbox_exec(self,source,globals=None,locals=None):
        g = self._scope(globals)
        if type(source) is type((lambda: 0).__code__):
            register_plugin_code(self,source)
        else:
            # 字符串源码原来交给 exec 内部编译,那棵 code 树不在账本里,于是
            # exec("box._guarded(...)") 的帧被判成"不是插件"而放行。这里自己
            # 编译并登记,让判据继续按 code 对象身份工作(第 8 批逃逸的 exec 路径)。
            source = compile(source,f'<plugin {self.name} exec>','exec')
            register_plugin_code(self,source)
        return _builtins.exec(source,g,g if locals is None else locals)

    def exec_plugin_code(self,code,globals=None):
        register_plugin_code(self,code)
        g = self._scope(globals)
        return _builtins.exec(code,g,g)

    def register_plugin_code(self,code):
        return register_plugin_code(self,code)

    def sandbox_compile(self,source,filename=None,mode='exec',*args,**kwargs):
        if filename is None:
            filename = f'<plugin {self.name} exec>'
        return _builtins.compile(source,filename,mode,*args,**kwargs)

    def _build_namespace(self):
        ns = self.namespace
        ns['__name__'] = 'plugin_'+str(self.env_id)
        ns['__doc__'] = None
        ns['__builtins__'] = self.restricted_builtins()
        ns['__sandbox__'] = SandboxView(self)
        ns['SandboxDenied'] = SandboxDenied
        ns['open'] = _free_method(self.fs_open)
        facades = self.module_builders()
        for name,mod in self._PASSTHROUGH.items():
            if '.' not in name:
                ns[name] = facades.get(name) or self.safe_module(name,mod)
        ns['os'] = facades['os']
        ns['sys'] = facades['sys']
        ns['io'] = facades['io']
        ns['Image'] = facades['PIL']
        ns['ImageTk'] = self.imagetk_module()
        ns['mutagen'] = facades['mutagen']
        ns['plugin_dir'] = self.plugin_dir
        ns['__env_id__'] = self.env_id
        if self._host is not None:
            ns['pro'] = self._facade or self._host
        return ns

class env_box:

    def __init__(self):
        self.a = {}
        self._boxes = {}
        self.__sealed = False

    def create(self,env_id,name,plugin_dir,policy,_host_token=None,share=False):
        box = self._boxes.get(env_id)
        if _host_token is not _HOST_TOKEN:
            if box is None:
                raise SandboxDenied(f'只有宿主能创建插件沙盒(env_id={env_id!r})')
            box.violation('create','插件试图改造已有沙盒',env_id)
            self.a[env_id] = box.namespace
            return box
        if is_plugin_frame_on_stack():
            caller = box if box is not None else None
            target = caller or next(iter(self._boxes.values()),None)
            if target is not None:
                target.refuse_plugin_caller('env_dict.create')
            raise SandboxDenied('插件不能借 env_dict.create 改沙盒策略(只有宿主能)')
        if box is not None:
            self.a[env_id] = box.namespace
            if self.__sealed or box.is_sealed():
                return box
            old_dir = os.path.normcase(os.path.realpath(box.plugin_dir))
            new_dir = os.path.normcase(os.path.realpath(plugin_dir))
            if old_dir != new_dir:
                if not share:
                    # env_id 是宿主手里的唯一身份键:不同插件目录共用一个 env_id
                    # 等于把两个插件塞进同一个沙盒,默认绝不合并策略,直接拒绝
                    box.violation('create',
                                  f'env_id={env_id!r} 已被插件目录 {old_dir} 占用,'
                                  f'拒绝与 {new_dir} 共用沙盒',env_id)
                    raise SandboxDenied(f'env_id={env_id!r} 已被其它插件目录占用,拒绝共用沙盒')
                # 插件在 plugin.json 里写了 "share_env": true,宿主据此显式要求共用,
                # 于是复用已有的盒子(两个插件共享同一份命名空间)。
                # 策略**不合并**:以先装载的那个为准 —— 后装载的插件声明的权限不会
                # 因为共用而生效(fail-closed),只留一条 note 与一行提示。
                box.note('share_env',env_id,
                         f'{new_dir} 与 {old_dir} 共用沙盒(策略以先装载的为准)')
                print(f'[沙盒] {name} 通过 share_env 与 {old_dir} 共用环境 {env_id!r}'
                      f'(策略以先装载者为准)')
                return box
            # 同一个插件目录重复创建:返回已有盒子,不合并策略、不扩权
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

def _facade_leak(obj,label,name):
    sb = object.__getattribute__(obj,'_d')[0]
    sb.violation('host_attr',f'插件不能访问 {label}.{name}',None)
    raise SandboxDenied(
        f'插件不能访问 {label}.{name}'
        f'(那是门面的内部数据,拿走就等于把宿主交出去)')

class _MenuFacade:

    __slots__ = ('_d',)

    _ALLOW = ('add_command','add_separator','add_checkbutton','add_radiobutton')

    def __init__(self,sb,menu):
        object.__setattr__(self,'_d',(sb,menu))

    def __getattribute__(self,name):
        if name == '_d':
            _facade_leak(self,'pro.menu',name)
        return object.__getattribute__(self,name)

    def _delegate(self,item):
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

    __slots__ = ('_d',)

    _ALLOW = ('after','after_idle','after_cancel','title','geometry','deiconify',
              'withdraw','iconify','destroy','update','update_idletasks',
              'bind','unbind','bind_all','unbind_all','resizable','minsize','maxsize',
              'winfo_width','winfo_height','winfo_screenwidth','winfo_screenheight',
              'winfo_x','winfo_y','winfo_exists','attributes')

    _CALLBACK_CHANNELS = ('after','after_idle')

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
            sticky = item in _AppFacade._BIND_CHANNELS
            def call_cb(*a,**k):
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

_FRAME_LOCAL = threading.local()
_FRAME_TAGS = {}
_FRAME_DIRS = []
_HOOK_INSTALLED = False

_FS_READ_EVENTS = ('os.listdir','os.scandir')
_FS_WRITE_EVENTS = ('os.mkdir','os.rmdir','os.remove','os.utime','os.chmod',
                    'os.truncate','os.link','os.symlink')
_PROC_EVENTS = ('os.system','os.exec','os.spawn','os.posix_spawn','os.startfile',
                'os.fork','os.forkpty','subprocess.Popen','ctypes.dlopen','pty.spawn',
                '_thread.start_new_thread','_thread.start_joinable_thread')
_NET_EVENTS = ('socket.__new__','socket.connect','socket.bind','socket.getaddrinfo',
               'socket.gethostbyname','socket.sendto')

_O_WRITE_FLAGS = 0
for _flag in ('O_WRONLY','O_RDWR','O_CREAT','O_APPEND','O_TRUNC'):
    _O_WRITE_FLAGS |= getattr(os,_flag,0)

class _FrameRegistrar:

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
        return dict(self._boxes)

    def notify(self,box):
        tag = box.frame_tag
        if tag in self._boxes:
            return
        self.tags.add(tag)
        self._boxes[tag] = box
        self._count += 1

    def arm(self,boxes=()):
        for box in boxes:
            self.notify(box)
        self.armed = True

    def sample_box(self):
        for box in self._boxes.values():
            return box
        return None

    def rebuild(self,tags,dirs,norm_fn):
        for tag,box in self._boxes.items():
            tags[tag] = box
        dirs[:] = [(norm_fn(box.plugin_dir),box) for box in self._boxes.values()]
        return len(self._boxes)

    def tampered(self,live_count):
        return self.armed and (self._forced or live_count < self._count)

_frame_registrar = _FrameRegistrar()

class _CodeLedger:

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

    def remember_box(self,box):
        if id(box) in self.boxes_by_id:
            return
        self.boxes_by_id[id(box)] = box
        self._series += 1

    def series(self):
        return self._series

    def tampered(self,live_count):
        return self._forced or live_count < self._series

    def rebuild(self):
        for box in self.boxes_by_id.values():
            _PLUGIN_BOXES[id(box)] = box
        return len(self.boxes_by_id)

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

    def note_fake_frame(self,box,label):
        key = (id(box),label)
        if key in self._warned_frame:
            return
        self._warned_frame.add(key)
        try:
            box.violation(
                'fake_frame',
                f'有代码把 co_filename 写成了插件帧名({label}),但它的 code 对象'
                f'不是宿主编译插件时的那一份;按它自称的插件判权(fail-closed)(只记一次)',
                label)
        except Exception:
            pass

_ledger = _CodeLedger()
_PLUGIN_BOXES = {}

_pending_owner = {}

_PCALLS_TO_OWN = 2

_bind_owner = weakref.WeakKeyDictionary()

_bind_codes = weakref.WeakKeyDictionary()

def mark_bind_owner(box, func):
    if func is None:
        return False
    target = func
    if not hasattr(target,'__code__'):
        target = getattr(func,'__func__',None) or getattr(func,'func',None)
    try:
        _bind_owner[func] = box
    except TypeError:
        pass
    code = getattr(target,'__code__',None)
    if code is not None:
        try:
            if code not in _bind_codes:
                _bind_codes[code] = box
        except TypeError:
            pass
    return True

def register_plugin_code(box,code):
    _ledger.remember_box(box)
    _PLUGIN_BOXES[id(box)] = box
    return _ledger.register_code(box,code)

def box_for_code(code):
    if code is None:
        return None
    box = _bind_codes.get(code)
    if box is not None:
        return box
    box = _ledger.code_owner.get(code)
    if box is not None:
        return box
    if _ledger.pending.get(code):
        box = _pending_owner.get(code)
        if box is not None:
            if _ledger.bump(code) >= _PCALLS_TO_OWN:
                _ledger.code_owner[code] = box
        return box
    return None

def box_for_callback(func,code=None):
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

def _plugin_code_at(depth=1,_code_fn=box_for_code):
    try:
        frame = sys._getframe(depth + 1)
    except ValueError:
        return None
    if frame is None:
        return None
    return _code_fn(frame.f_code)
def mark_callback_owner(box,func):
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

def _always_readable(path):
    for root in _ALWAYS_READABLE:
        if under(root,path):
            return True
    return False

def register_plugin_frames(box):
    _FRAME_TAGS[box.frame_tag] = box
    _FRAME_DIRS.append((_norm(box.plugin_dir),box))
    _frame_registrar.notify(box)

def _box_for_frame(filename,code=None):
    box = box_for_code(code)
    if box is not None:
        return box
    if not filename:
        return None
    for tag,ours in _FRAME_TAGS.items():
        if filename.startswith(tag):
            _note_fake_frame(ours,filename)
            return ours
    for root,ours in _FRAME_DIRS:
        if root and under(root,filename):
            _note_fake_frame(ours,filename)
            return ours
    return None

def _note_fake_frame(box,filename):
    if box is None:
        return
    _ledger.note_fake_frame(box,filename)

def _plugin_box_on_stack():
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
    global _HOOK_INSTALLED
    if _HOOK_INSTALLED:
        return False
    _HOOK_INSTALLED = True

    _tags = _FRAME_TAGS
    _dirs = _FRAME_DIRS
    _depth = _FRAME_LOCAL
    _under_fn = under
    _norm_fn = _norm
    _read_cap = None
    _o_write_flags = _O_WRITE_FLAGS
    _registrar = _frame_registrar
    _entry_fn = _auth_entry
    _can_fn = _auth_can
    _proc_events = _PROC_EVENTS
    _net_events = _NET_EVENTS
    _fs_read_events = _FS_READ_EVENTS
    _fs_write_events = _FS_WRITE_EVENTS
    _guard_code = SandBox._guarded.__code__
    _violation_code = SandBox.violation.__code__
    _tracked_events = frozenset(
        _fs_read_events + _fs_write_events + _net_events + _proc_events
        + ('open','os.rename','os.replace'))
    _is_pathlike_fn = _is_pathlike
    _frame_probe = [False]
    _probe = [False]
    _registrar.arm(list(_tags.values()))
    _tamper_state = {'reported':False,'codes_reported':False}
    _led = _ledger

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
        box = _code_fn(code)
        if box is not None:
            return box
        if not filename:
            return None
        for tag,ours in _tags.items():
            if filename.startswith(tag):
                _led.note_fake_frame(ours,filename)
                return ours
        for root,ours in _dirs:
            if root and _under_fn(root,filename):
                _led.note_fake_frame(ours,filename)
                return ours
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
        if event not in _tracked_events:
            if not args or not _is_pathlike_fn(args[0]):
                return
        if _hook_in_facade_frame():
            return
        try:
            if _registrar.tampered(len(_tags)):
                restored = _registrar.rebuild(_tags,_dirs,_norm_fn)
                if not _tamper_state['reported']:
                    _tamper_state['reported'] = True
                    box = _registrar.sample_box()
                    if box is not None:
                        box.violation('registry',
                                      f'插件注册表被清空/替换过;已按记账恢复 {restored} 条,'
                                      f'本次调用继续按正常规则判定(此提示只记一次)',None)
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
                return
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
        except Exception as e:
            # S5:原来是"记一次日志然后放行"(fail-open)。这与整个系统的
            # fail-closed 取向相反,且 SANDBOX.md 自认"让钩子自己抛异常"
            # 就是一种绕法。这里改成拒绝这次操作:钩子判不了就不放行。
            logging.exception('沙盒审计钩子内部出错,已按拒绝处理(不再放行)')
            raise RuntimeError(
                f'沙盒审计钩子内部出错,拒绝该次 {event} 操作:{e}') from e

    globals()['_AUDIT_HOOK'] = _hook
    sys.addaudithook(_hook)
    logging.info('插件沙盒审计钩子已安装')
    return True

def _audit_hook(event,args):
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

        code = compile(cm,f'<file main>','exec')
    except Exception as e:
        logging.exception('编译插件 init 代码失败')
    install_audit_hook()
    try:

        exec(code,d)
    except SandboxDenied as e:
        logging.warning('文件 的 init 被沙盒拦截:%s',e)
        print(f'[沙盒] 文件的 init 被拦截:{e}')
    except Exception as e:
        logging.exception('执行 代码失败')
        print(f'文件错误:{e}')
        traceback.print_exc()

