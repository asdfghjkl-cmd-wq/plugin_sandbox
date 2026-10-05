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
    if not r.endswith(os.sep):
        r += os.sep
    return p.startswith(r)

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

        self.name = sb.name
        self.can = sb.can
        self.describe = sb.policy.describe
        self.events = sb.audit

    def __repr__(self):
        return f'<sandbox {self.name}: {self.describe()}>'

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
        if target is None:
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
        box._policy_frozen = _frozen(ent)
        box._org = dict(ent['org'])

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
                 _tamper=_auth_tamper,_allow_plugin_caller=False,**kwargs):
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
        # 只有确定目标是已存在的文件时才收窄到父目录;目录原样;不存在时也原样
        # (宁可范围窄:上浮到父目录会把授权悄悄放大到整个目录)
        if os.path.isfile(target):
            return os.path.dirname(target) or target
        return target

    def set_ask(self,func):
        self._ask = func

    def set_persist(self,func):
        self._persist = func

    def set_persist_deny(self,func):
        self._persist_deny = func

    def remember_denied(self,cap,target,_host_token=None):
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
        logging.warning('插件 %s 触发沙盒拦截:%s(%s)',self.name,detail,target)
        print(f'[沙盒] 插件 {self.name}:{detail}')

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
            root = self._grant_root(target) or _norm(target)
            return (cap,_norm(root) or str(target))
        return (cap,str(target))

    def _ask_user(self,cap,target,detail):
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
        if type(source) is type((lambda: 0).__code__):
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
        ns['open'] = self.fs_open
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

    def create(self,env_id,name,plugin_dir,policy,_host_token=None):
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
                # env_id 是宿主手里的唯一身份键:不同插件目录共用一个 env_id
                # 等于把两个插件塞进同一个沙盒,绝不合并策略,直接拒绝
                box.violation('create',
                              f'env_id={env_id!r} 已被插件目录 {old_dir} 占用,'
                              f'拒绝与 {new_dir} 共用沙盒',env_id)
                raise SandboxDenied(f'env_id={env_id!r} 已被其它插件目录占用,拒绝共用沙盒')
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
        except Exception:
            if not getattr(_depth,'warned',False):
                _depth.warned = True
                logging.exception('沙盒审计钩子内部出错,该事件放行')

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

