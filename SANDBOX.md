# 插件沙盒

`plugin/` 下的插件现在跑在沙盒里。实现全在 [plugin_sandbox.py](plugin_sandbox.py),接入点在
[b.py](b.py) 的 `Plugin` / `Tkapp`。这份文档写给两类人:**装插件的人**(怎么授权、怎么撤销)和
**写插件的人**(能用什么、被拦了怎么办)。

## 三道闸

| 闸 | 实现 | 作用 |
|---|---|---|
| 能力策略 | `SandBox.can()` / `check_fs` / `check_net` / `check_proc` | 默认只允许插件**读自己的目录**;写文件、联网、起进程都要授权 |
| 宿主门面 | `HostFacade`(插件拿到的 `pro`) | 插件只能加菜单项、调白名单窗口方法、读播放列表快照;拿不到 `Tkapp`、`player`、`env_dict` |
| 审计钩子 | `install_audit_hook()`(`sys.addaudithook`) | 插件**绕开门面**(用内省拿到真的 `os`/`socket`/`subprocess`)去碰文件、网络、进程时,按同一套策略拦下 |

审计钩子只在"调用栈上确实有插件代码帧"时才动手,宿主(播放器自己)的访问不受影响。

## 不是安全边界(重要,请读完)

插件和播放器在**同一个进程、同一个解释器**里。下面这些能绕开上面三道闸 —— 这是方案的固有上限,不是待修的 bug:

* **内省**:`type(pro.menu).__init__.__globals__` 就是本模块的全局字典(含 `_HOST_TOKEN`);
  `__sandbox__.can.__self__` 直接是那个 `SandBox` 对象;异常回溯的 `f_globals` 也一样;
  `pro.app.after.__closure__` 能顺着闭包摸到真实控件;
* **Tcl 通道**:插件画界面必须能 `import tkinter`,而 Tcl 自己就能起进程、读写文件,且是 C 层调用,
  **不产生 Python 审计事件**;
* **C 扩展**:直接调系统接口的扩展不在审计事件范围内;
* **不在审计表里的事件**:`os.stat`/`os.lstat` 没有事件,所以"文件存不存在、多大"探测不到;
  读环境变量(`os.environ`)也不产生事件 —— 内省拿到真 `os` 之后,环境变量是读得到的。

所以沙盒的价值是:**默认拒绝 + 出事有日志 + 授权可追溯**,防的是"顺手越权"和事故,
不是"有备而来的恶意代码"。真隔离只能把插件放进单独进程,代价是插件不能再直接操作 Tk 界面。

### 已经堵掉的几条内省逃逸(2026-10 加固)

`plugin/escape` 是一个"越权样本/PoC"插件(默认 `can_exec:true`,要不要装载看你的
`allow_plugin`),它把上面那条内省链走了一遍。照着它做的加固:

| 逃逸手法 | 加固 |
|---|---|
| 偷 `_HOST_TOKEN` 后调 `box.set_unsafe(True,...)` 把自己放出来 | `set_unsafe`/`grant`/`env_box.create`/`env_dict.grant` 除凭据外**再加一道"调用栈上没有插件帧"**;插件从自己代码里调这些入口一律拒绝并记 `violation:set_unsafe` 之类 |
| 直接改 `box.policy.fs_read = ['C:\\']`、`policy.net/proc = True`(seal 只换了容器,没人拦赋值) | `Policy` 封存后(`freeze()`)拒绝一切改写;`SandBox.can()` 及审计钩子改读**封存时的只读快照** `_policy_frozen`,插件手上的 `policy` 只是展示用 |
| 往 `box._session` 里塞授权 | 封存时记下授权基线 `_org`(`policy ∪ 装载期已发的 session` 授权);出现基线外的条目会记一条 `violation:tamper`(判权仍按快照) |
| 撑大 `_ALWAYS_READABLE` 让钩子把"读任何文件"当白名单 | 钩子在装的时候就把解释器目录**固化成元组**存进闭包,并自己实现 `_hook_readable`,不再走模块级的 `_always_readable`(那条路每次调用都会重读 `_ALWAYS_READABLE`) |
| 清空 `_FRAME_TAGS`/`_FRAME_DIRS` 让钩子认不出插件帧 | 钩子闭包持有同一批表(换掉模块变量没用),另有 `_FrameRegistrar` 记账:表里的条目比记账少 => **按记账立刻把表恢复**,记一条 `violation:registry`(只报一次),然后**继续按调用者正常判定**——插件那一下照样被拒,宿主不受影响。注意千万别做成"拒绝一切":宿主自己的 `after`/`winfo`/`logging` 也走审计钩子,那样插件清一次表就能把播放器拖崩(实测崩在 `b.py` 的 `on_resize`) |

### 又一批:判权/审计"入口"本身也被锁了(2026-10)

上面那张表锁的是**策略数据**,但逃逸样本的最后几步证明判权**入口**还是普通实例属性:

| 逃逸手法 | 加固 |
|---|---|
| `box._policy_frozen = <unsafe 快照>`(判权快照是实例属性,谁都能换) | 判权数据整体搬进模块私有的记账表 `_AUTH`(`id(box) -> {policy, frozen, org, session, ...}`);封存后 `box._policy_frozen` / `box.policy` / `box._session` 只是**影子副本**,不参与判权。改它们只留一条 `violation:tamper` |
| `box.can = lambda cap, target=None: True`(门面和审计钩子都回调 `box.can`,换掉它 = **两道闸同时失明**) | 唯一判权实现在 `_auth_can()`(`SandBox.can()`、门面 `check_fs/check_net/check_proc`、审计钩子全走它);审计钩子在 `install_audit_hook()` 时就把 `_auth_can`/`_auth_entry` 收进闭包,**不再回调 `box.can`** |
| `box._session['fs:write'].add(r'C:\\')`(判权原来直接读这个 dict) | 封存时记账里存一份**独立的** session 副本,判权读它;`box._session` 变成影子。授权基线之外的条目只记 `violation:tamper` |
| `box.violation = lambda *a, **k: None`(拦得住但**记不下**) | `violation` / `note` / `events` 和 `can` 一起列进 `SandBox.guarded_names()`:封存后再赋值直接抛 `SandboxDenied` 并留痕 |
| 换掉 `box.can` 之后**门面自己**把真实 `open` 当"已授权"执行 —— `_guarded()` 又把审计钩子的 depth 置 1,钩子见 depth>0 就放行,**两道闸一起失效**(这条最阴:光把判权搬进记账还不够) | 门面里的判权不再调 `self.can`,一律走 `_auth_can()`;`_guarded()` 拿到 `_auth=(能力,目标)` 后会**先用记账复核**,"真授权才豁免审计钩子" |

`guarded_names()` 故意**不**锁 `_host`/`_facade`/`_ask`/`_persist`:那是宿主接口,封存之后宿主仍要合法地重挂(`b.py` 的 `Plugin.run()` 每次执行命令都会再 `attach_host` 一次);插件改了它们也拿不到额外能力。

`_guarded()` 的复核只对**记账里真有的授权**生效:用户在弹窗里点"只允许本次"属于不落账的一次性放行
(`check_fs` 的第二个返回值就是"是否记账授权"),那一次真实调用照样豁免审计钩子 ——
否则 `t_audit_allows_own_dir_and_facade` 那条"授权后仍被拦"的老坑会回来。

诚实说明剩下什么:同进程里插件终究能摸到那些对象,所以这仍然是"抬高门槛 + 会报警",
不是边界。`_AUDIT_HOOK` 内部出错时为了不把播放器带崩是**放行**的,所以"让钩子自己抛异常"
仍是一种绕法(会留下 `logging.exception` 记录)。

### 第三批:判权/审计依赖的**模块 globals** 本身可写(2026-10,`plugin/escape2`)

前两批把"策略数据"和"判权入口"都搬进了模块私有的 `_AUTH` 记账表 —— 但**记账表自己,
以及判权/审计用到的每一个函数,都还住在 `plugin_sandbox` 的模块 globals 里**。插件和它同进程,
一行内省就能拿到那个 dict,于是"模块私有"并不等于"插件改不了":

```python
g = type(__sandbox__).__init__.__globals__      # 就是 plugin_sandbox.__dict__
```

实测(`plugin/escape2`,自测 `dsh/escape2_selftest.py`)能真的走出去的路:

| 逃逸手法 | 为什么成立 | 拦住没 |
|---|---|---|
| `g['_FRAME_LOCAL'].depth = 5` | 审计钩子第一句就是 `if getattr(_depth,'depth',0): return`,而 `_depth` 抓的正是模块级 `_FRAME_LOCAL`。置位后**第二道闸对本线程全局失明**,真 `os` 全部放行 | ✗ 一行就够 |
| `g['_AUTH'][id(box)]['session']['fs:write'].add('C:\\')` | 记账表是普通 dict,`_auth_domain` 读的正是它;门面和钩子当场改判成"已授权" | ✗ |
| `g['_auth_entry'] = lambda box: <unsafe 记账>` | 钩子里 `ent = _auth_entry(box)`、门面里 `_auth_entry(self)` 都是**全局名查找**;换掉它 = 两道闸同时失明 | ✗ |
| `g['under'] = lambda r,p: True` | `_auth_can` 里 `any(under(r,target) ...)` 同样是全局名查找;只要 roots 非空就恒真(读权限尤其有效) | ✗ |
| 清空 `g['_FRAME_TAGS']`/`g['_FRAME_DIRS']` + `g['_frame_registrar'].count = 0` | 注册表的防篡改靠 `tampered()` 比对计数;把计数归零**再**清表,`_hook_frames_box` 恒返回 None,钩子认为"不是插件干的"直接放行 | ✗ |
| `compile(src,'<not-a-plugin>','exec')` + `g['threading']` 起一条新线程 | 钩子判断"这一帧是不是插件"靠 `co_filename`(`<plugin 名字 ` 前缀 / 插件目录),而 **filename 是插件自己传给 `compile` 的**;新线程的栈上只剩伪造帧,扫不到任何插件帧 → 判定"不是插件干的"放行 | ✗(第六批:`plugin_sandbox_fix_fake_filename.py` 把帧身份改成 **code 对象身份**,这条的"起线程"那一下也仍然要先拿到 proc 授权) |
| 同上,把回调交给白名单方法 `pro.app.after` | 真实 mainloop 里回调帧同样只有伪造文件名,而且 `after` **不产生审计事件**,连"拦 proc"这条退路都够不着 | ✗(真机;第六批给 `after`/`after_idle` 这条通道挂了**回调归属**,`plugin/test-1/a.py` + `dsh/fake_filename_selftest.py` 在真 Tk 主循环下实测由 OK 变 BLOCK) |

根因一句话:`install_audit_hook()` 只把**对象引用**收进了闭包。`_AUTH` 的**内容**、
`_auth_entry` / `under` / `_auth_frozen` 这些**函数本身**都不是闭包变量,替换或改写它们
不影响闭包,却影响所有按全局名查找的调用点。`_FrameRegistrar` 的计数校验同理 ——
计数和那两张表都是插件内省得到的对象上的普通属性。而最后一组更根本:**"插件帧"这个
身份本身是用 `co_filename` 字符串认的**,那是插件能自由指定的东西,所以它根本不是身份。

这不是"漏了一个补丁",而是方案定位的直接后果:**同进程内省拿得到 `__dict__`,所以模块里
没有真正的私有数据**。加固只能做成两件事:

1. 把内部调用点全部**固化**(默认参数 / 闭包),让"替换 globals 里的名字"不再影响判权;
2. 给记账加**完整性校验**,让"改写内容"变成会报警并当场拒绝的操作,而不是静默放行。

修复已经**并进 `plugin_sandbox.py` 本身**(2026-10 合并;过程中先在副本里验证过,
照 AGENTS.md 的约定当时没动原文件)。诚实说明:改完仍然不是边界 —— 置位
`_FRAME_LOCAL.depth` 这类手法只是从"一行静默失明"变成"会撞上校验并留 violation"。

### 第四批:宿主门面的内部数据直接挂在 `__slots__` 上(2026-10,`plugin/escape2`)

门面(`HostFacade` / `_AppFacade` / `_MenuFacade`)是插件唯一能看到宿主的地方,
白名单写得很紧 —— 但它把**真控件本身**放在 `__slots__` 的普通属性上:

    class _AppFacade:
        __slots__ = ('_sb','_app')      # ← 真 Tkapp 就躺在这儿

`__getattr__` **只对"找不到的属性"触发**。`_app` 是真实存在的 slot,
`pro.app._app` 根本走不到白名单那一句,于是:

| 逃逸手法 | 结果 |
|---|---|
| `pro.app._app` | 真 `Tk` 对象;`.tk.eval("exec ...")` 就是一条完整的 Tcl 起进程通道(实测 `expr 1+1` 返回 `2`) |
| `pro.menu._menu` | 真 `Menu` 控件,同一个 `.tk` 通道 |
| `pro._pro` | **整个原宿主对象**:`env_dict`(注册表)、`plugin_list`(别人的命名空间)、`music_player` 全回来了,门面等于没装 |

`_MenuFacade` 那句注释("不把绑定方法交出去,因为绑定方法的 `__self__` 是控件")
防的是**方法**,没防住**属性** —— 属性就是控件本身。`pro.app._app` 用自测夹具
(FakeApp)也能复现,`tk.eval` 那一步要真 Tk。

修复同样已并进 `plugin_sandbox.py`:真控件只存在一个"自己也会拦"的槽(`_d`)里,
插件读 `_app`/`_pro`/`_menu`/`_d` 照常撞白名单,并留一条 `violation:host_attr`。
复现脚本见下面自测一节的 `dsh/facade_probe.py`。

### 同批实测到两条"拦不住"的缺口(无解,不是漏补丁)

跟门面那两条一起跑出来的还有两条,性质不同 —— **CPython 根本没给这些操作发审计事件**,
第二道闸没有可挂的钩子:

| 手法 | 为什么拦不住 |
|---|---|
| 真 `os.environ` 读环境变量 | 读 `os.environ` 不产生任何审计事件;它是 `os` 模块上的普通对象,插件从内省拿到真 `os` 就能读。**第五批**把"不需要内省"的那几条路堵掉了(见下面第五批那一节),内省那条仍然通 |
| `os.stat` / `os.path.getsize` 探测目录外文件 | `_FS_READ_EVENTS` 只有 `os.listdir`/`os.scandir`;CPython 的审计表里**没有** `os.stat`/`os.lstat`(那条注释就写在 `_FS_READ_EVENTS` 旁边) |

实测:同一个插件帧里 `os.listdir('C:\Windows')` 被钩子拦下,而
`os.stat('C:\Windows\win.ini').st_size` 返回 `92`、`os.environ['PATH']` 直接读出来。

危害有上限:沙盒仍然拦得住**读内容**(`open`)和**列目录**,这两条只泄漏
"某个已知路径存不存在/多大"和进程环境变量(宿主可能在里面放了路径或凭据)。
真封死只有一条路:**把插件放进独立进程**,让它内省也摸不到宿主的地址空间。

另外,`plugin/escape2` 第 01/02 步(内省拿回 `SandBox`、从函数 `__globals__` 偷
`_HOST_TOKEN`)在加固前后都算"成功" —— 但那两步只是**拿到对象**,拿去用
(`set_unsafe`、换 `can`)都撞在第 03/05 步上。它们在清单里是"拿到",不是"越权"。

### 第五批:环境变量(`os.environ`)的可达路径(2026-10,bug 名 `environ`)

"读 `os.environ` 不产生审计事件"是真的,所以**审计钩子**这一道闸对它无解。但"钩子挂不上"
不等于"门面也拦不住" —— 实测(项目根目录跑,`plugin/escape2` 当插件目录)有三条**完全
不需要内省**的路,一行属性访问就能把 `PATH` 读出来:

| 手法 | 为什么成立 |
|---|---|
| `os._real.environ['PATH']`、`os._sb`、`os._wrap`、`os.path._real`(→`ntpath.os.environ`)、`sys._real.modules`、`io._real`、`Image._real`、`mutagen._real` | `_Proxy` 把真模块/沙盒/包装表放在**普通 `__slots__` 属性**上,而 `__getattr__` 只对"找不到的属性"触发 —— 和第四批门面(`pro.app._app`)是同一个 bug,只是当时只修了三个宿主门面,没修模块门面 |
| `os.path.expandvars('%PATH%')`、`os.path.expanduser('~')`、`Image.os.environ` | `expandvars`/`expanduser` 本来就是"读环境变量"的入口却在 allow 名单里;`Image` 是 `allow=None` 的门面,`PIL.Image` 的全局里挂着真 `os`,门面照原样交出去 |
| `logging.os.environ`、`random._os.environ`、`tkinter.sys.modules`、`tkinter.filedialog.os`、`ttkbootstrap.filedialog.os`、`ttkbootstrap.style._compat.os`、`ImageTk.Image.os` | `_PASSTHROUGH` 把 `json`/`logging`/`tkinter`/`ttkbootstrap`… **真模块**直接交给插件;真模块的全局里挂着 `os`/`sys`/子模块。从命名空间出发只顺着"模块属性"走一遍(BFS,深度 4)就能列出 **23 条**到达 `os.environ` 的链路 |

修法在副本 `plugin_sandbox_fix_environ.py`(原文件照 AGENTS.md 不动):

1. `_Proxy` 的内部数据(`_real`/`_sb`/`_label`/`_allow`/`_wrap`/`_deny`)从实例槽搬到
   **模块私有的弱引用表 `_PROXY_DATA`**,实例上**一个属性都不留**:`os._real`/`os._sb`/
   `os._wrap`/`os._d` 统统落到 `__getattr__`,被"下划线开头的名字一律不给"挡下并记
   `violation:attr`。**这里故意没沿用第四批的 `_d` 槽写法** —— 槽是类上的描述符,
   `type(o)._d.__get__(o)` / `object.__getattribute__(o,'_d')` 两头都能绕过
   `__getattribute__`(第四批那三个宿主门面现在还能这么读走真 Tkapp,见"已知的坑");
2. 门面**不再交出外来模块句柄**:取到的属性是模块对象时,只有"门面自己的子模块"
   (按模块名前缀判定:`tkinter.filedialog`、`ttkbootstrap.dialogs`、`PIL.ImageDraw`…)
   才递归包一层同样的门面交出去,其它模块(`os`/`sys`/`threading`/`fnmatch`/`logging`…)
   直接拒并记 `violation:module_attr`;
3. `os.path.expandvars`/`expanduser` 从 allow 名单挪进 deny;
4. **直通模块也套门面**:所有 `_PASSTHROUGH`(`json`/`logging`/`tkinter`/`ttkbootstrap`…)、
   `PIL.*` 子模块、`ImageTk` 全部走 `safe_module()`,规则同第 2 条;`urllib.parse` 也从
   "真模块"改成门面。`_resolve_module` 相应改成"先顺着门面属性把子模块门面拿到",保证
   `from tkinter.simpledialog import askstring` 这类写法仍然拿得到子模块(而 `import a.b`
   要的顶层包由 `import_module` 按 `__import__` 的契约返回)。

副本实测:`plugin/escape2` 当插件目录、在插件帧里跑,上面三类 **25 条读法全部 BLOCK**;
宿主侧顺着 **90 个 `allow=None` 门面**把每个属性都取一遍,**0 条**还能拿到真模块/`environ`;
24 条白名单用法(`os.path.join`/`os.listdir`/`open`/`logging`/`json`/`urllib.parse`/
`tkinter.ttk`/`filedialog`/`simpledialog`/`ttkbootstrap.dialogs`/`Image`/`ImageTk`/`mutagen`/
`io`/`sys.version`/`time`)与 10 种 import 写法全部照旧可用。`dsh/facade_probe.py`(16/17 全
BLOCK)与 `dsh/escape2_selftest.py`(ok=2 / blocked=11 / na=1)和原文件逐项一致,没有退化。

诚实说明仍然没堵住的:

* **内省**:`type(__sandbox__).__init__.__globals__['os'].environ`(escape2 第 13 步)、
  `os.path.join.__globals__['os']`、任何函数/类的 `__globals__`/`__closure__` 照样读得到环境
  变量 —— 根因和第三批一样(同进程里模块 globals 就是插件读得到的普通 dict),只有独立进程
  能封死;
* `os.stat`/`os.lstat` 没有审计事件那条**本批没动**(只修 `environ`)。

**合并要点**:直通模块套门面会改变 `import`/命名空间里"安全模块"的**身份**(`is`),功能不变。
`dsh/fix_regression.py` 拿副本跑四个套件,只有 `tests/test_sandbox_core.py` 的两个用例报错,
正好是这 6 行身份断言(原文件与测试文件按 AGENTS.md 都没动,合并时要一起改):

| 行 | 现在 | 改成 |
|---|---|---|
| 352 | `assert box.import_module('json') is json` | `assert box.import_module('json') is box.module_builders()['json']`(再加一句 `dumps` 的功能断言) |
| 386 | `assert box.import_module('tkinter.simpledialog') is tkinter` | `... is box.module_builders()['tkinter']` |
| 387 | `assert box.import_module('tkinter.simpledialog', fromlist=('askstring',)) is sd` | `assert (...).askstring is sd.askstring` |
| 399 | `assert ns['tkinter'] is tkinter` | `assert ns['tkinter'] is box.module_builders()['tkinter']` |
| 406 | `assert ns['_sub'] is sd` | `assert ns['_sub'].askstring is sd.askstring` |
| 407 | `assert ns['_ttk'] is tkinter.ttk` | `assert ns['_ttk'].Style is tkinter.ttk.Style` |

其余断言(353、371、388/389、400、410 的"没在白名单里的包照样拒",以及另外三个套件)
在新实现下全部通过。副本文件头的"合并说明"一节列了同样的 6 行,可以直接抄。

### 第七批:判权路径的 `realpath` 成了热点(2026-10,性能)

第六批把帧身份从 `co_filename` 换成了 **code 对象身份**,这一步本身很便宜(一次
字典查找),但它把"扫栈"这条路的真实开销暴露出来了:审计钩子每扫一帧,都要经过
`under()` 判一次"这一帧的文件是不是在插件目录/解释器目录里",而 `under()` 每次调
**两次** `_norm()` —— `_norm()` 里面有 `os.path.realpath()`。

Windows 上 `realpath` 是系统调用(`nt._getfinalpathname`),实测单次约 **0.24ms**。
`is_plugin_frame_on_stack()` / `_hook_box_on_stack()` 允许把栈扫到 **500 帧**,
于是结果很夸张:

| 场景 | 优化前 | 优化后 |
|---|---|---|
| `env_box.create()` 建一个盒(装一个插件) | **144 ms** | **1.07 ms**(≈135×) |
| 装载(create + `__init__` + code 登记) | 150 ms | **1.96 ms**(≈77×) |
| 插件帧上真 `os` 越权被拒(扫栈+判权+记 violation) | 1003 µs | **83 µs**(≈12×) |
| 宿主自己 `open()` 一次(栈上没有插件帧) | 143 µs | 139 µs(不变) |

定位过程(`dsh/_bench_steps*.py` 是当时的探针,`dsh/fake_filename_bench.py` 是可复跑的基准):
先是 cProfile 显示"10 次 create 花 260ms",其中 **920 次 `nt._getfinalpathname` 占掉
219ms**;而单独的 `SandBox(...)` 构造只要 1.7ms —— 差别就在 create 会先调一次
`is_plugin_frame_on_stack()`,那一下把栈上几十帧、每帧两个 `_norm` 全算了一遍,
而且**同一个插件目录在每一帧上都被重新 realpath 了一次**。

修法就一条:**给 `_norm` 加按路径的记忆化**(`_NORM_CACHE`,上限 8192,满了整体清)。
为什么这是安全的:

* `_norm` 是**判权的输入**(把路径规范化),不是判权结果 —— 缓存它只会让同一个判断
  更快,不会把"越权路径"变成"授权路径";
* 键就是调用方给的路径,插件刷一堆不同路径最多把缓存挤出去,那时重新算,结果依旧相同;
* 缓存要罩住**入参转换**:`_norm` 对非 str(PathLike / 不可哈希对象)有明确的兜底
  (返回 `None`),所以先 `os.fspath` 再进缓存,免得把 `TypeError` 变成"判权抛异常";
* **相对路径的坑**:`realpath('a.txt')` 依赖当前工作目录,所以每次比一下 `os.getcwd()`
  (便宜),变了就整体清空 —— 宁可重算,也不能拿"旧 cwd 下的绝对路径"去判权。
  绝对路径(宿主传进来的 `plugin_dir`、审计事件的路径基本都是绝对路径)不受影响。

回归:`dsh/norm_cache_test.py` 专测上面这几条(cwd 切换、绝对路径、PathLike、
非路径入参);四个套件的结论与本批之前**逐项一致**。
另外**没做**的:宿主自己 `open()` 那条路每次都是**新路径**(临时文件名),缓存命不中,
所以它没变快 —— 要再快就得把 `under()` 的 root 侧预归一化,那是下一轮的事。

### 第十一批:`open()` 一次触发上百个审计事件(2026-10,性能,主题 `hook_fastpath`)

上一节最后那句"要再快就得把 `under()` 的 root 侧预归一化"是当时的猜测。这一轮
用临时基准(在钩子外面**再挂一个钩子**数审计事件)量下来,宿主自己 `open()` 慢的
**真正原因不是缓存命不中,而是审计钩子被自己产生的事件反复唤醒**:

装钩子之后,一次普通 `open()` 触发 **138 个**审计事件,而真正的 `open` 只有 1 个:

| 事件名 | 每次 `open` 的次数 | 哪来的 |
|---|---|---|
| `open` | 1 | 真的那一次 |
| `object.__getattr__` | ~122 | 钩子找"门面帧"时,每扫一帧读一次 `frame.f_code` |
| `sys._getframe` | ~15 | 钩子探栈自己 |

关键在于 3.13+ **读 `frame.f_code` 也会发审计事件**:`_hook` 的第一件事就是
`_hook_in_facade_frame()`(必须读 `f_code`),于是那个事件又回到 `_hook`、再读一次
`f_code`……一次 `open()` 就这样放大成上百次完整判定。

| 场景 | 优化前 | 优化后 | 无钩子基线 |
|---|---|---|---|
| 宿主自己 `open()` | 0.635 ms | **0.280 ms** | 0.154 ms |
| 宿主自己 `os.listdir()` | 0.504 ms | **0.166 ms** | 0.101 ms |
| 单次 `open` 触发的审计事件 | 138 | **21** | 1 |
| 扫一次栈找插件帧 | 129.6 µs | **19.3 µs** | — |

(上表两列同口径。基准为了数事件会**再挂一个 spy 钩子**,栈因此更深;另一套更浅的
栈上量出来是 **34 → 9** 个事件 —— 两套各自内部同口径,绝对值不必横着比。扣掉基线的
净开销:`open` 0.485ms → 0.126ms(≈3.9×),`listdir` 0.417ms → 0.065ms(≈6.5×)。
那几个测量脚本是临时的,量完按用户要求删掉了;数字留在这里当记录。)

改动已并进 `plugin_sandbox.py`(**判权逻辑一字未动**;当时先在副本
`plugin_sandbox_opt_hook.py` 里改并验证,逐项等价之后才合并)。三处:

1. **无关事件在碰栈之前就返回**。`_hook_target()` 只对少数事件名返回非 None
   (`open` / `os.rename` / `os.replace` / 四张能力表),装钩子时把这几个名字固化成
   `_tracked_events`(frozenset,顺带把原来每事件的元组线性查表也变成一次哈希),
   `_hook` 开头判断"事件名不在表里 **且** 第一个参数不是路径"就直接 return。
   同一个事件原逻辑也是返 None 放行 —— 这里只是把这一步提前到**读栈之前**。
   条件比原逻辑**严**(事件名不在表里、但第一个参数是路径时照旧走完整判定),
   所以不会在这条路上丢事件;`os.rename`/`os.replace` 的路径在第 2 个参数上,
   但它们在表里,不受影响。
2. **探栈期间不许重入探栈**。加一个探栈专用标志 `_probe`,`_hook_in_facade_frame`
   探栈期间自己产生的事件不再回到探栈(仍会走 `_hook` 其余判定 —— 那期间栈上若真有
   插件帧,`_hook_box_on_stack` 照样认得出它)。它和原有的 `_frame_probe` 分工不同:
   那个防的是 `sys._getframe` 自身的无限递归(不加会静默崩栈),这个防的是 `f_code`
   读取的放大(不崩,但把开销翻几十倍)。**这两个标志都不能省**,也不能合并。

顺带修掉上一节留下的一处:`_hook_frames_box` 每扫一帧都要经 `under()` 调**两次**
`_norm`,而 `_norm` 原来**每次**都要 `os.getcwd()`(Windows 上是一次系统调用)。
`realpath` 对**绝对路径**的结果与 cwd 无关,所以现在只有相对路径(含 Windows 的
盘符相对路径 `C:foo`)才做那道 cwd 比较。`os.path.isabs` 按本文件的老规矩
**固化成默认参数**(`def _norm(path,_isabs=os.path.isabs)`),不新增可写的模块全局。

**等价性验证**(先在副本上与原文件逐项对比,合并进 `plugin_sandbox.py` 之后**又跑了一遍**,
两次结论完全一致):

* 四个套件(`--facade-fixture`):结论逐字相同,core 仍只剩既有的 `t_import` /
  `t_import_dotted`,其余三个 `FAILED: none`;
* `dsh/escape2_selftest.py` 仍是 `OK=2 / BLOCK=11 / N/A=1`;
* `dsh/norm_cache_test.py` 10 条全过 —— 含"换 cwd 后不能复用旧结果"那条(上面第 3 处
  改动正好动的是它,所以必须跑);
* `dsh/guarded_frame_probe.py` 仍是 `VERDICT = FIXED`,且正常门面路径
  (`fs_open` / `listdir` 读自己目录)仍可用;
* `dsh/bind_channel_probe.py` 仍是四组回调全 BLOCK、宿主自己的 `bind` 回调照常执行;
* `dsh/facade_probe.py` 仍是 16/17 全 BLOCK(只有既有的 os.environ / os.stat 两条开着);
* `dsh/fake_filename_selftest.py` 仍是 exit 0(拦住伪造帧、未误伤宿主的 `after`)。

**诚实说明**:这条快筛只跳过了"本来就要放行"的事件,不改变任何一次插件的判权;
但无关事件不再做那两处**防篡改对账**(注册表 / code 账本)—— 那两处与具体事件无关,
下一个被跟踪的事件照样会对账,所以不会长期失明。

## 写插件:能声明什么

`plugin.json` 新增 `sandbox` 段(不写就是最严的默认值):

```json
{
  "name": "myplugin",
  "can_exec": true,
  "init_file": "a.py",
  "sandbox": {
    "fs_read":  [".", "../music"],   // 相对插件目录,也可以写绝对路径;默认 ["."]
    "fs_write": [],                  // 默认空:要用就在运行期向用户申请
    "net":  false,                   // socket / urllib / http
    "proc": false,                   // subprocess / os.system / ctypes
    "ask":  true,                    // 被拒时是否弹窗请求授权
    "unsafe": false,                 // true = 申请完全不受限制(装载时要用户确认)
    "modules": ["numpy"]             // 额外放行的顶层模块(不受门面代理,慎用)
  }
}
```

历史字段仍然兼容:`"privilege": ["no_sandbox_really"]` 等价于 `unsafe: true`;
`"privilege": ["built"]` 只打印提示(常用内置函数本来就可用)。未知键、类型写错都只会**更严**。

`unsafe` 与 `sandbox.unsafe` 都只是**申请**:只有你在装载确认框里点"是"、且名字进了
`config.json` 的 `plugin_unsafe` 之后才真的生效。

## 写插件:能用什么

插件命名空间里的东西(`from b import *` 那行会被自动去掉,也不需要写):

| 名字 | 说明 |
|---|---|
| `pro.menu` | `add_command` / `add_separator` / `add_checkbutton` / `add_radiobutton` |
| `pro.app` | 白名单:`after` `after_idle` `after_cancel` `title` `geometry` `deiconify` `withdraw` `iconify` `destroy` `update` `update_idletasks` `bind*` `unbind*` `resizable` `minsize` `maxsize` `winfo_width/height/x/y/exists/screen*` `attributes` |
| `pro.music_dict` | 播放列表的**深拷贝快照**(改了不影响播放器) |
| `pro.plugin_names` | 已加载插件的名字列表(不给对象) |
| `__sandbox__` | `can(能力,路径)` / `describe()` / `events()` |
| `SandboxDenied` | 沙盒拒绝时抛的异常,可以精确 `except` |
| `open` `os` `sys` `io` `json` `re` `math` `random` `time` `datetime` `collections` `itertools` `functools` `string` `textwrap` `traceback` `logging` `tkinter` `ttkbootstrap` `Image` `ImageTk` `mutagen` | 受控门面或安全模块;`os.environ` `os.system` `sys.modules` `sys.exit` `import ctypes/shutil/importlib/pickle/vlc/b` 等都是拒的 |
| `plugin_dir` `__env_id__` | 自己的目录、自己的 env 号 |

`pro` 之外拿不到 `player` / `env_dict` / `plugin_list` / `config`。想加播放控制或读别人的命名空间,
现在没有这条路 —— 需要的话提需求,加白名单方法比敞开后门好。

被拒绝时抛 `SandboxDenied`;如果 `ask` 打开、当前在 Tk 主线程、且这个目标没问过,沙盒会**先问用户**
(允许本次 / 本次运行都允许 / 总是允许 / 拒绝,默认按钮是"拒绝")。子线程里不弹窗,直接拒。

写插件时的建议:动手前先 `__sandbox__.can('fs:write', path)` 自查;把 `SandboxDenied` 当"操作没发生"处理,
不要整段 `try: ... except Exception: pass` 吞掉。

## 注释
"""插件沙盒:用"能力(capability)"限制插件能碰的文件、网络与外部进程。

能力(默认都是关的,只有"读插件自己的目录"默认开):
    fs:read    读文件
    fs:write   写/删/改名
    net        网络(socket / urllib / http)
    proc       外部进程(subprocess / os.system / ctypes)

plugin.json 里的声明方式:
    "sandbox": {
        "fs_read":  [".", "../music"],   # 相对插件目录,也可以写绝对路径
        "fs_write": [],                  # 默认空:要用就得在运行期向用户申请
        "net": false,
        "proc": false,
        "ask": true,                     # 被拒时是否弹窗向用户请求授权
        "unsafe": false,                 # true = 完全不受限制(装载时需用户确认)
        "modules": ["numpy"]             # 额外放行的顶层模块(不受门面代理)
    }
历史遗留的 "privilege": ["no_sandbox_really"] 等价于 unsafe;其它取值只提示、不生效。

定位(重要):这是"能力约束 + 审计",不是安全边界。
    插件和播放器在同一个进程、同一个解释器里,所以下面这些路都能绕开本模块:
      * Python 内省(type(...).__mro__、__subclasses__、函数的 __globals__);
      * 插件为了画界面必然拿得到的 tkinter/Tcl 通道(Tcl 本身就能起进程);
      * 任何"给它一个路径它就去读"的第三方库。
    它挡的是"插件顺手读写文件、偷偷联网、起个进程"这类事故和明确越权,
    并把每次拒绝/授权都写进日志。要真正的隔离,只能把插件放进单独的受限
    进程里 —— 那样插件就无法直接操作 Tk 界面了,所以这里取舍是可用性优先。

加固(2026-10,副本随批次演进)
------------------------------------------------------------------
本文件是 **plugin_sandbox.py 的副本**(原文件照 AGENTS.md 不动)。原文件里已经并进了
第三批(`module_globals`)和第四批(`facade_slots`)两轮修复;本副本是**第九批
(bug 名 `bind_channel`)**的快照,专治"`bind`/`bind_all` 没挂回调归属,插件把
账本里没有的 code 对象当回调交出去就能越权"。想复现前几批,看第五批的
`plugin_sandbox_fix_environ.py`、第八批的 `plugin_sandbox_fix_guarded_frame.py`
(如果手上有)以及原文件自己的文件头。下面几节是**原文件里已有的**说明(第三批到
第八批),本批的说明在最后:"第九批:回调归属只挂了 `after`……"。

第三批:判权/审计依赖的**模块 globals**可写(bug 名 module_globals)
------------------------------------------------------------------
第三批的根因是:前两批把判权数据搬进了"模块私有的 `_AUTH`
记账表",但那张表、以及判权/审计用到的**每个函数**,都还住在模块 globals 里,
而插件同进程内省一行 `type(__sandbox__).__init__.__globals__` 就拿到了它。

针对 dsh/escape2_selftest.py 报出来的九条越权路径,本副本做了四处改动:

  1. **调用点全部固化**(默认参数 / 闭包变量),不再按全局名查找:
     `_auth_can` / `_auth_domain` / `_auth_entry` 里的 `_AUTH` / `under` /
     `_auth_frozen`,以及 `SandBox.can` / `_guarded` / `check_fs` / `check_net` /
     `check_proc`,还有钩子里的 `_auth_entry`、`_auth_can` 和那几张事件表。
     => 堵掉 escape2 的 08(替换 under)、09(替换 _auth_entry)。
  2. 判权只认**授权基线** `ent['org']`:直接往 `_AUTH[...]['session']` 里塞的
     条目不在基线里,判权当场忽略。
     => 堵掉 07(往 _AUTH 记账里塞授权)。
  3. 审计钩子不再读可写的 `_FRAME_LOCAL.depth`,改成看调用栈上有没有
     `SandBox._guarded` / `SandBox.violation` 的 **code 对象**(装钩子时固化在
     闭包里);`_FrameRegistrar.count` 改成只增不减、`boxes` 改成只读副本。
     => 堵掉 06(置位 depth)、10(清表 + 记账归零)。
  4. `_PROC_EVENTS` 收进 `_thread.start_new_thread` / `_thread.start_joinable_thread`,
     让"起新线程甩掉外层插件帧"变成需要 proc 授权。
     => 部分堵掉 12(伪造 co_filename + 新线程)。

诚实说明**没堵住**的:
  * 帧身份仍然是拿 `co_filename` 字符串认的 —— 插件能自由指定它,所以
    `compile(src,'<not-a-plugin>')` 照样骗得过 `_box_for_frame`;
  * 因此"伪造文件名 + 把回调交给 `pro.app.after`"(escape2 第 13 步)在真实
    mainloop 里仍然走得通:`after` 不产生审计事件,回调帧也没有插件帧名;
  * `_AUTH` 这本账仍在 globals 里,够狠的插件还能整体换成伪装对象(改动 1、2
    让它不容易骗过判权,但不是不可能);
  * `os.stat`/`os.lstat` 无审计事件、`os.environ` 可读(第五批已把"不需要内省"的
    几条路堵掉,见下)、Tcl 通道这几条(门面口子已关,真 Tk 仍然拿得到 —— 见下)
    **本批仍然一条没变**。

第四批:宿主门面的内部数据直接挂在 `__slots__` 上(bug 名 facade_slots)
------------------------------------------------------------------
门面(`HostFacade` / `_AppFacade` / `_MenuFacade`)是插件唯一能看到宿主的地方,
但真控件原来就放在 `__slots__` 的普通属性上,而 `__getattr__` **只对"找不到的
属性"触发** —— 于是 `pro.app._app`、`pro.menu._menu`、`pro._pro` 全都绕过了白名单
(实测:拿到真 `Tk` 后 `.tk.eval("expr 1+1")` 返回 `2`,`pro._pro.env_dict` 直接
读到宿主内容)。修法是让实例上不再有插件读得到的内部属性:

  5. 三个门面的真控件与沙盒只存在 `_d` 这个**自己也拦**的槽里
     (`__getattribute__` 见到 `_d` 就记 violation 并拒);`_app` / `_menu` /
     `_pro` / `_sb` 连槽都不再存在,读它们照常触发 `__getattr__` 撞白名单。
     => 堵掉 16(`pro.app._app` 穿透)与 17(Tcl `exec` 通道)。

一句话:这批改动把"一行改 globals 就静默失明"变成"要绕过完整性校验、而且会留
violation",仍然只是抬高门槛 + 会报警,**不是边界**。要真隔离只能独立进程。

关于清单里的 01/02:内省拿回 `SandBox`、从函数 `__globals__` 偷 `_HOST_TOKEN`
这两步在加固前后都"成功",但它们只是**拿到对象** —— 拿去用(`set_unsafe`、
换 `can`)分别撞在第 03/05 步上。那两步不是越权,是前置。

第五批:一行属性访问就能读走环境变量(bug 名 environ)
------------------------------------------------------------------
"读 `os.environ` 不产生 Python 审计事件"是对的,所以审计钩子那一道闸对它**没有
任何办法** —— 但这不等于门面也拦不住。实测(原文件 `plugin_sandbox.py`,
`plugin/escape2` 当插件目录)有三类**完全不需要内省**的路:

  1. 门面内部数据在普通槽上:`os._real.environ`、`os._sb`、`os._wrap`、
     `os.path._real`(→`ntpath.os.environ`)、`sys._real.modules['os']`、`io._real`、
     `Image._real`、`mutagen._real`。`_Proxy` 把这些放在 `__slots__` 的普通属性上,
     而 `__getattr__` 只对"找不到的属性"触发。**和第四批宿主门面
     (`pro.app._app`)是同一个 bug**,只是当时只修了三个宿主门面。
  2. 门面里被放行的"读环境变量"入口:`os.path.expandvars('%PATH%')` 直接返回真 PATH,
     `os.path.expanduser('~')` 返回 `C:\\Users\\admin`;`Image.os.environ` ——
     `allow=None` 的门面把 `PIL.Image` 全局里的真 `os` 原样交了出去。
  3. 直通模块是**真模块**:`logging.os.environ`、`random._os.environ`、
     `tkinter.sys.modules`、`tkinter.filedialog.os`、`ttkbootstrap.filedialog.os`、
     `ttkbootstrap.style._compat.os`、`ImageTk.Image.os`。`_PASSTHROUGH` 把真模块
     直接塞进命名空间,而真模块的全局里挂着 `os`/`sys`/子模块 —— 从命名空间出发
     只顺着"模块属性"走一遍(BFS,深度 4)能列出 **23 条**到 `os.environ` 的链路。

本副本的四处改法:

  1. `_Proxy` 的内部数据(`_real`/`_sb`/`_label`/`_allow`/`_wrap`/`_deny`)从实例槽
     搬进模块私有的弱引用表 `_PROXY_DATA`,实例上**一个属性都不留**:
       * `os._real`/`os._sb`/`os._wrap` 这些名字落到 `__getattr__`,被"下划线开头的
         名字一律不给"挡下,记 `violation:attr`;
       * 这里**故意没沿用**第四批的 `_d` 槽写法:槽是类上的描述符,
         `type(pro.app)._d.__get__(pro.app)` 和 `object.__getattribute__(o,'_d')`
         都能绕过 `__getattribute__`(见 SANDBOX.md 的"已知的坑":第四批那三个宿主
         门面现在**仍然**能被这样读走真 Tkapp,本批没动它们);
       * `o._d` 本身也单独拦一条,只为了给插件作者留一句 violation。
  2. 门面**不再交出外来模块句柄**:取到的属性是模块对象时,只有"门面自己的子模块"
     (`tkinter.filedialog`、`ttkbootstrap.style`、`PIL.ImageDraw`…,按模块名前缀判定)
     才递归包一层同样的门面,其它模块一律拒,记 `violation:module_attr`。
     `Image.os`、`ImageTk.Image.os`、`tkinter.filedialog.fnmatch.os` 都是这么堵的。
  3. `os.path.expandvars`/`expanduser` 从 path 门面的 allow 名单挪进 deny。
  4. **直通模块也套门面**:所有 `_PASSTHROUGH`(`json`/`logging`/`tkinter`/
     `ttkbootstrap`…)、`PIL.*` 子模块、`ImageTk` 全部走 `safe_module()`,规则同上;
     `urllib.parse` 也顺手从"真模块"改成门面。`_resolve_module` 相应改成"先顺着
     门面属性把子模块门面拿到"(`from tkinter.simpledialog import askstring` 这类
     写法要的是子模块本身,而 `import a.b` 要的是顶层包 —— 后者是 `__import__` 的
     契约,仍在 `import_module` 里补上)。

实测结果(本副本,`plugin/escape2` 当插件目录,插件帧里跑):
  * 上面三类 25 条读法**全部 BLOCK**;宿主侧顺着 90 个 `allow=None` 门面把每个
    属性都取一遍,**0 条**还能拿到真模块/`environ`;
  * 24 条白名单用法(`os.path.join`、`os.listdir(插件目录)`、`open(插件目录里
    的文件)`、`logging.getLogger`、`json.dumps`、`urllib.parse`、
    `tkinter.ttk`/`filedialog`/`simpledialog`、`ttkbootstrap.dialogs`、
    `Image`/`ImageTk`/`mutagen`、`io.StringIO`、`sys.version`、`time.time`)
    全部照旧可用;10 种 import 写法(`import a.b`、`from a.b import x`、
    `from a import b`、`import os.path as ...`)全部照旧可用;
  * `dsh/facade_probe.py`(16/17 全 BLOCK)、`dsh/escape2_selftest.py`
    (ok=2 / blocked=11 / na=1,和原文件逐项一致)都没退化。

诚实说明仍然没堵住的(和 SANDBOX.md 的"已知的坑"一致):
  * **内省**:`type(__sandbox__).__init__.__globals__['os'].environ`(escape2 第 13 步)、
    `os.path.join.__globals__['os']`、任何函数/类的 `__globals__`/`__closure__`
    照样读得到环境变量 —— 根因是"同进程里模块 globals 就是普通 dict",和第三批
    同一个根因,只有独立进程能封死;
  * `_PROXY_DATA` 本身也在模块 globals 里,内省拿得到(和 `_AUTH` 一个层级);
  * `os.stat`/`os.lstat` 没有审计事件那条本批没动;
  * 第四批的宿主门面(`pro`/`pro.app`/`pro.menu`)仍然能被
    `type(pro.app)._d.__get__(pro.app)` 读出真 Tkapp(`.tk.eval('expr 1+1')` 返回
    `'2'`)—— 这是**本批顺手发现、按 AGENTS.md 先记进 SANDBOX.md、不在本副本里修**
    的另一个 bug(修法同改动 1:把 `_d` 也搬进模块私有的表)。

合并说明(必须一起改测试;原文件与测试文件按 AGENTS.md 都没动)
------------------------------------------------------------------
直通模块套门面会改变 `import`/命名空间里"安全模块"的**身份**(`is`),功能不变。
`dsh/fix_regression.py` 拿本副本跑四个套件,只有 `tests/test_sandbox_core.py`
的两个用例报错,正好是下面 6 行(都只是身份断言):

  t_import:
    352  assert box.import_module('json') is json
      →  assert box.import_module('json') is box.module_builders()['json']
         assert box.import_module('json').dumps({'a': 1}) == json.dumps({'a': 1})

  t_import_dotted:
    386  assert box.import_module('tkinter.simpledialog') is tkinter
      →  assert box.import_module('tkinter.simpledialog') is box.module_builders()['tkinter']
    387  assert box.import_module('tkinter.simpledialog', fromlist=('askstring',)) is sd
      →  assert (box.import_module('tkinter.simpledialog', fromlist=('askstring',))
                 .askstring is sd.askstring)          # 拿到的是子模块门面,别人仍是真函数
    399  assert ns['tkinter'] is tkinter
      →  assert ns['tkinter'] is box.module_builders()['tkinter']
    406  assert ns['_sub'] is sd
      →  assert ns['_sub'].askstring is sd.askstring
    407  assert ns['_ttk'] is tkinter.ttk
      →  assert ns['_ttk'].Style is tkinter.ttk.Style

其余断言(353、371、388/389、400、410 的"没在白名单里的包照样拒",以及另外三个
套件)在新实现下**全部通过**,不需要改。`dsh/fix_regression.py` 跑完会把结论写进
`dsh/_last_result.txt`。

第六批:帧身份靠 `co_filename`,而那是插件自己写的(bug 名 `fake_filename`)
------------------------------------------------------------------
本副本是**第六批(bug 名 `fake_filename`)**的快照,专治 `plugin/test-1/a.py`
拿出来的那条路:

    g = type(__sandbox__).__init__.__globals__      # 内省拿真 os(第五批的已知缺口)
    exec(compile(src,'<not-a-plugin>','exec'), ns)  # 帧名随插件写
    pro.app.after(0, ns['cb'])                      # 把函数交给真 Tk 主循环
    g['time'].sleep(0.2)

真实播放器里 `after` 是**异步**的:回调在 mainloop 下一轮才跑,那时插件的 init
帧早已返回,栈上只剩 `co_filename='<not-a-plugin>'` 那一帧。审计钩子判断"这一帧
是不是插件"靠的正是 `co_filename`(`<plugin 名字 ` 前缀 / 插件目录前缀),
于是它认定"不是插件干的",`proc:false` 的插件把 `os.system` 跑通了
(SANDBOX.md 第三批第 88 行早就记着这条,当时只能记 N/A —— 自测夹具的
`FakeApp.after` 是同步的,看不出差别;`dsh/fake_filename_selftest.py` 用真
`tkinter.Tk()` 把它复现出来了)。

根因一句话:**`co_filename` 是被审查方指定的字符串,它不能当身份**。

本副本的改法(两处,都不依赖 `co_filename`):

  1. **代码对象就是身份**(`_CodeLedger`):
     `SandBox` 在 `__init__` 里就把**本插件 init/command 的源码**读出来
     (`plugin_dir` + `plugin.json`,读法/加工与 `b.py` 的 `Plugin.__init__`
     逐条对齐),用宿主将要使用的同一个文件名 `<plugin {name} init>` 编译成
     code 对象并**注册**进一张模块私有的表 —— 于是 `b.py` 照旧
     `compile(...)` + `exec(...)` 时,它执行的就是登记过的那一棵,**宿主一行都不用改**。
     注册会把整棵 code 树(`co_consts` 里嵌套的函数/类 code 一起)记上,并记下它
     属于哪个 box。审计钩子 / `_box_for_frame` 现在**先按 code 对象查表**:
     命中 = 这次调用来自插件;查不到 = 宿主。
     code 对象是编译产物,插件伪造不了"这个对象当初是谁注册的";
     宿主自己 `compile` 插件代码时,也可以用 `SandBox.exec_plugin_code(code,ns)`
     交出去执行,由它补登记;

  2. **`after` 通道带归属**(`_pending_after` + `mark_callback_owner`):
     插件只能通过宿主门面 `pro.app.after/after_idle` 把函数交给 Tk,而门面
     每次调用都从插件帧里发出来(`is_plugin_frame_on_stack`)。门面于是顺手
     把"这个回调是哪个插件的"记进 `_CodeLedger.pending`。回调真正跑起来时,
     钩子按**回调函数自己的 code 对象身份**查到归属 —— 伪造的文件名、
     重新 exec 出来的 `cb` 都改不了这一步。

另外加了一条**取证**信号:文件名自称是某个插件(`<plugin 名字 `/插件目录前缀)、
但 code 对象不在表里时,记一次 `violation:fake_frame`(只记一次)。这不参与判权
(判权只认 code 身份),但能把"有人在伪造帧名"写进日志。

诚实说明(本批仍然挡不住的,和 SANDBOX.md"已知的坑"一致):
  * 插件内省拿到 `__sandbox__` 之后自己 `compile()` 造 code 再 `exec`,这棵 code
    树**没在表里** —— 它在**同步**调用里派不上用场(栈上外层那个已注册的插件帧
    还在,钩子照样认得出);只有"甩到另一个执行上下文"**并且**那个通道没带归属
    时才能溜过去;
  * 除了 `after/after_idle`,门面白名单里还有 `bind`/`bind_all`,以及将来任何
    "把函数交给别的执行上下文"的接口 —— 本批只给 `after` 两条挂了归属,别的
    通道要照同一套(`mark_callback_owner`)补齐;
  * `pro.app` 门面的 `_d` 槽仍能被 `type(pro.app)._d.__get__(pro.app)` 读走
    (第四批遗留,见 SANDBOX.md"已知的坑"),拿到真 Tkapp 之后 `.tk.eval` 是一条
    独立的 Tcl 通道 —— 那条路本副本没动;
  * 第三批那条"注册表被清空"的老路照旧只是"会报警的拒绝",不是边界。

合并说明(必须一起改测试;原文件与测试文件按 AGENTS.md 都没动)
------------------------------------------------------------------
本批**只加不减**:`_box_for_frame(filename)` 的签名保持兼容(多了一个可选参数),
纯宿主状态下的判定结果与原文件一致。
`b.py` **一个字没改** —— 登记是自己做的(`SandBox._register_own_code`),所以
`ESCAPE2_FIX` 指不指向这个副本,`b.py` 都照常工作(指回去就退化成"没有第六批加固")。

四个套件的现状(基线/本副本对比):
  * `test_sandbox_grants.py`:两边全绿;
  * `test_sandbox_core.py`:两边都只剩 `t_import` / `t_import_dotted` 两条失败
    (第五批遗留的身份断言,与本批无关);
  * `test_sandbox_integration.py` / `test_sandbox_facade.py`:原文件直接跑不能算数 ——
    integration 的插件清单要跟着 `plugin/` 目录加(仓库新加的 `plugin/test-1`),
    facade 的 `run_tagged` 是"手工 compile 出插件帧 + 裸 exec"(新判据下那不是
    插件代码)。两份只改夹具的副本在 `dsh/fake_filename_{integration,facade}_test.py`,
    用 `.\\dsh\\fix_regression.py --facade-fixture` 一起跑,结果全绿。
`dsh/fake_filename_selftest.py`(真 Tk 主循环复现)与 `dsh/fake_filename_probe.py`
(边界探针)同样认 `ESCAPE2_FIX`。

第八批:插件自己造一个"门面帧"(bug 名 `guarded_frame`)
==================================================================
本副本是**第八批(bug 名 `guarded_frame`)**的快照,治的是原文件
`plugin_sandbox.py` 里作者自己写下的一句自认(原文 2990-2991 行):

    仍然只是一个门槛:插件能直接 `box._guarded(fn)` 从而真的产生
    `_guarded` 帧 —— 见文件头的"没堵住的"。

这句话现在有**干净复现**了(`dsh/guarded_frame_probe.py`),而且比自认的更严重:
不只是"能不能产生帧",而是**产生帧之后就真的越权了**。

根因
------------------------------------------------------------------
第三批把审计钩子的判据从"可写的 `_FRAME_LOCAL.depth` 计数器"改成了
"调用栈上有没有 `SandBox._guarded` / `SandBox.violation` 的 **code 对象**"
(`_hook_in_facade_frame`;code 对象在装钩子时封进闭包,插件换 globals 没用)。
这个判据本身是对的 —— 但它有个前提没有落实:**谁都能产生那个帧**。

`_guarded` 是 `SandBox` 上的**公开方法**,而它的豁免逻辑是:

    auth = _auth
    if auth is not None:      # 只有传了 _auth 才复核授权
        ...
    _facade_enter()           # 无条件:钩子从此对这一帧"门面放行"
    try: return func(*args,**kwargs)

插件只要 `box._guarded(lambda: open(r'C:\\Windows\\win.ini'))`:
`_auth` 不传 => `None` => **整个授权复核被跳过**,然后 `_facade_enter()` 照开,
钩子看见 `_guarded` 的 code 对象就放行 —— 越权 `open` 当场成功。
`os.system` 同理。也就是说:**门面帧的判据是公开可产生的,那它就不是身份。**

实测(原文件,`dsh/guarded_frame_probe.py`,攻击代码已按真实路径
`compile` + `register_plugin_code` 登记成插件 code,所以钩子确实认它):

    |                    | 插件目录外读 win.ini | os.system |
    |--------------------|----------------------|-----------|
    | 插件帧里直接做      | BLOCK                | —         |
    | 插件帧里套 _guarded | **读到了**           | **执行了** |

对照组 BLOCK、攻击组得手 —— 归因干净,不是"什么都没拦"的假阳性。
(第一版探针就踩过这个坑:攻击代码没登记成插件 code,结果对照组也"成功",
那样的结果不能归因。探针现在自己会判 `INVALID`。)

本副本的改法(一处)
------------------------------------------------------------------
在 `_guarded` 开头补一道**直接调用者身份判定**:

    if (_auth is None and not _allow_plugin_caller
            and _plugin_code_at(1)):
        self.violation('guarded_frame', ...)
        raise SandboxDenied(...)

新增模块级 `_plugin_code_at(depth)`:拿"往上第 depth 层帧的 code 对象"去查
`box_for_code`(第六批的 code 身份账本)。判据只认 **code 对象身份**,
不认 `co_filename` —— 文件名是插件自己写的,不能当身份(第六批的教训)。

三个设计要点
------------------------------------------------------------------
1. **为什么是"直接调用者"而不是 `_plugin_caller()`(栈上有没有插件帧)**:
   合法宿主路径里插件帧**本来就在栈上** ——
   插件调 `pro.open(...)` 是  插件帧 -> `fs_open` -> `_guarded`;
   插件调 `import a`       是  插件帧 -> `_load_local_module` -> `_guarded`。
   用"栈上有插件帧"当判据会把这两条正常功能一起打死(实测会误伤
   `import` 插件自己的本地模块)。而插件**直接**调 `box._guarded(...)` 时,
   `_guarded` 的直接调用者就是**插件帧本身** —— 两者能精确分开。

2. **为什么还要限定 `_auth is None`**:
   `net_guard` / `proc_guard` 的 `func` 是**插件提供的可调用对象**
   (`os.system` 之类),那时 `_auth` 非 None,已经过 `_auth_can` 复核 ——
   合法路径,不该被本检查碰。插件自己调 `_guarded(fn)` 时拿不到
   `_auth_pair` 那种内部口径,`_auth` 一定是 None,绕过整个复核。
   所以"插件直接调用 + `_auth is None`"两条同时满足才是要堵的。

3. **`_allow_plugin_caller=True` 口子**:给宿主"明知要从插件帧里调、又确实
   不需要能力判定"的路径留的。目前**没有任何调用点用它**;
   将来要加必须写明理由 —— 这个口子等于自愿放弃这道闸。

验证
------------------------------------------------------------------
* `dsh/guarded_frame_probe.py` A/B:
  原文件 `VERDICT = BUG`(攻击组越权成功),本副本 `VERDICT = FIXED`
  (攻击组 BLOCK + 留 `violation:guarded_frame` 审计),而且**回归组不退化**:
  门面 `fs_open`(自己目录)、`fs_listdir`(自己目录)照旧可用。
* 四个套件(`dsh/run_regression_capture.py` 跑 `dsh/fix_regression.py
  --facade-fixture`)逐项对比原文件与副本:**判定行完全相同**,
  `test_sandbox_core.py` 仍只剩既有的 `t_import` / `t_import_dotted` 两条失败,
  其余三套全绿 —— 零回归。
* `dsh/escape2_selftest.py` 在副本上仍是 `OK=2 / BLOCK=11 / N/A=1`,逐项一致。

诚实说明:本批没堵住 / 只是抬高的
------------------------------------------------------------------
* **本批只堵"插件直接调 `_guarded`"这一条**。文件头前面几节列的缺口一条没动:
  内省(`__globals__` 拿 `os.environ`、拿 `_AUTH`、拿 `_ledger.code_owner` 本身)、
  `os.stat` 无审计事件、`pro.app._d` 描述符、Tcl 通道、`bind` 没挂归属 —— 照旧;
* `_plugin_code_at` 依赖 `box_for_code` + `_ledger.code_owner`,而**那张表仍在
  模块 globals 里**(同进程、插件内省拿得到,和 `_AUTH` 一个层级)。插件把
  `code_owner` 里的条目改掉/删掉,固然会触发第三批那套"按记账恢复"的对账
  (会报警),但"够狠的插件能不能让本检查恒为假"仍然没有从根上封死 ——
  和第六批自己的诚实说明一致:`_CodeLedger` 的价值是"判据不再是字符串",
  不是"判据拿不到";
* 所以本批的准确表述是:**把"一次方法调用就能造出被信任的门面帧"变成
  "要动到身份账本、而且会留 violation"**。仍然是抬高门槛 + 会报警,不是边界。
  真正的边界只有一条:把插件放进独立进程(见文件头开头的定位说明)。

关于合并:本批**只加不减**,`_guarded` 多了一个带默认值的参数,
所有既有调用点(16 处)不需要改;`b.py` 与 `tests/` 一个字没改。

第九批:回调归属只挂了 `after`,`bind` 那条路一直开着(bug 名 `bind_channel`)
==================================================================================
本副本是**第九批(bug 名 `bind_channel`)**的快照。根因一句话:

    "插件帧"的身份在第六批已经从 `co_filename` 换成了 **code 对象**,
    但**只有 `after`/`after_idle` 会给回调挂归属**;
    `bind`/`bind_all` 在**同一份白名单** `_ALLOW` 里,却没有 ——
    于是"账本里没有的 code 对象"当回调交出去,触发时插件帧早已返回,
    钩子只能把它当宿主放行。

Tk 触发绑定回调时(事件到达、mainloop 下一轮),栈上只剩回调自己那一帧:
`tkinter/__init__.py` 的 `__call__` → 回调。钩子问 `box_for_code(回调帧的 code)`:

    * 回调是插件源码里 `def` 出来的 => 它的 code 在 `_CodeLedger` 里 => 认得,拦得住;
    * 回调的 code **不在账本里** => 判定"不是插件干的" => **放行**。

而"不在账本里"的 code 有两种**不需要伪造文件名**的造法(比第六批那条更省事):

  1. **真 builtins 执行**:门面的 `exec`/`eval` 是 `sandbox_exec`/`sandbox_eval`,
     它们**顺手把执行过的 code 登记进账本**(所以"生成源码 + 门面 exec"这条
     自己就被认领了)。绕开的办法是内省拿**真** builtins:
     `type(__sandbox__).__init__.__globals__['_builtins']` —— 之后
     `REAL_EXEC(REAL_COMPILE(src,'<x>','exec'), ns)` 造出来的 code 账本完全看不到;
  2. **不生成源码,只换 code 对象**:`types.FunctionType(别的 code, globals)`
     (或者给已注册的函数换 `__code__`)—— 重组出来的函数对象没被登记过。

实测(`dsh/bind_channel_probe.py`,真 `tkinter.Tk()` 主循环,事件从宿主定时器
发出,所以触发时插件帧已返回;插件 `proc:false`,`os.system` 是真进程):

    | 绑上去的回调                              | 账本里有吗 | 结果           |
    |-------------------------------------------|-----------|----------------|
    | A 插件源码里 def 的普通函数                | 有        | BLOCK(对照组)  |
    | B 生成源码 + 门面 exec(`sandbox_exec` 登记)| 有        | BLOCK          |
    | C 生成源码 + **真 builtins.exec**          | 没有      | **越权成功**   |
    | D `FunctionType(真 code, globals)` 重组    | 没有      | **越权成功**   |

A/B 各留一条 `violation:audit`;C/D **一条记录都没有** —— 完全没被看见。

本副本的改法(一张表 + 两个人)
----------------------------------------------------------------------------------
1. 新增模块私有**弱引用**表 `_bind_owner`(`weakref.WeakKeyDictionary`),
   和 `_pending_owner` 分开放,因为**口径不同**:

   * 键是**回调函数对象本身**(不是 code 对象)。C/D 那类"共享同一个 code、
     但是不同函数对象"因此各算各的归属;而按 code 记账会让它们互相连坐;
   * 值是 box,命中即**长期有效**(不递减)。`after` 用 `_CodeLedger.pending`
     "还欠几次执行"是对的(一次性回调),但 `bind` 的回调会**反复触发** ——
     按次数记账会在第二次执行时归零,又落回"认不出 → 当宿主",等于没修;
   * 用弱引用:插件还持有回调就一直有效,卸载/换绑之后条目自动消失
     (不像 `_pending_owner` 那样"黏住不摘",也不会因为反复 bind 顶爆内存)。

2. `box_for_code()` 在查身份账本**之前**先查这份归属 —— 但注意归属要存**两张**
   弱引用表才行:

   * `_bind_owner`:回调**函数对象** -> box,给直接查询/排查用;
   * `_bind_codes`:回调的 **code 对象** -> box。这张是必需的 ——
     审计钩子把 `box_for_code` 用**默认参数**固化进了闭包
     (`_hook_frames_box(...,_code_fn=box_for_code,...)`,第三批就是这么防"换
     globals"的),所以"只在模块层新加一个按函数对象查的入口"**钩子根本看不见**
     (实测:第一版只加了 `mark_bind_owner`/`box_for_callback`,钩子那条路照样放行)。
     归属只有并进 `box_for_code` 这条**唯一的判据路**,钩子、门面、`_box_for_frame`
     才会都认。

   `after` 那条老路(`code_owner` / `pending` / `_PCALLS_TO_OWN`)完全不变。

3. 门面 `_AppFacade._delegate` 里新增 `_BIND_CHANNELS = ('bind','bind_all')`:
   走这条通道时,把**每一个**可调用参数逐个登记进 `_bind_owner`
   (顺手把 `after` 原来"只看第一个可调用参数"的写法也改成逐个 ——
   `after(0, a, b)` 这种多个回调的写法原来漏登记)。

登记条件不变,仍是"这次门面调用**确实从插件帧里发出来**"(`is_plugin_frame_on_stack`)
—— 宿主自己排的 `bind`/`after` 不走门面,不会被误判成插件;插件也伪造不了:
它交出去的函数对象就是它自己的。

验证
----------------------------------------------------------------------------------
* `dsh/bind_channel_probe.py`:A/B/C/D **四组全部 BLOCK**(原文件是 C/D 越权成功),
  而且**宿主自己的 `bind` 回调照常执行**(没有把宿主连坐);
* `dsh/fix_regression.py` 四个套件:与本批之前**逐项一致**
  (`test_sandbox_core.py` 仍只剩既有的 `t_import` / `t_import_dotted` 两条);
* `dsh/escape2_selftest.py` 仍是 `OK=2 / BLOCK=11 / N/A=1`,
  `dsh/facade_probe.py` 仍是 16/17 全 BLOCK —— 零回归。

诚实说明:仍然是"抬高门槛 + 会报警",不是边界
----------------------------------------------------------------------------------
* **本批堵的是"通道",不是"新 code 的执行"**:插件内省之后照样能拿真 builtins
  执行任意新 code(Escape2 第 13 步那类),`box_for_code` 对它仍然查不到 ——
  区别只在于:**它现在认得出"这个回调是插件通过门面交出来的"**
  (`_bind_owner` 按函数对象记账),所以"甩到别的执行上下文"这条退路不再自动放行;
* `_bind_owner` 本身也在模块 globals 里(和 `_AUTH`/`_ledger` 一个层级),
  够狠的插件内省拿得到、能往里面塞/删条目;
* **将来任何"把函数交给别的执行上下文"的新接口**(`bind_class`、自定义 Tk 命令、
  第三方库自己的回调注册)都要照同一套补归属 —— 本批只覆盖门面白名单里现有的
  `after` / `after_idle` / `bind` / `bind_all`;
* 文件头前面几节列的缺口(内省拿 `os.environ`、`os.stat` 无审计事件、
  `pro.app._d` 描述符、Tcl 通道)一条没动。

关于合并:本批**只加不减**,新增一个模块级函数与一张表,`box_for_code` 多查一张表,
门面多认两条通道;`b.py` 与 `tests/` 一个字没改。
"""
## 装插件:你会看到什么

* 装载白名单外的插件时,确认框会列出它申请的权限;
* 插件声明了 `unsafe` 时,会单独问一次"它将以播放器的全部权限运行…是否允许?";
* 插件运行期越界时弹窗,选"总是允许"会写进 `config.json`,以后自动生效。

`config.json` 里新增两个字段:

```json
{
  "plugin_unsafe": ["debug"],
  "plugin_grants": {
    "debug": {"fs_write": ["D:\\k\\music\\.venv"], "net": true}
  }
}
```

撤销授权:直接删掉对应条目(或整个字段)再启动即可。**白名单 `allow_plugin` 只管"要不要加载";
`plugin_grants` 才是"允许它碰什么"。**

## 已知的坑与行为约定

* 白名单是**目录级**的:对某个文件点"总是允许",实际放开的是它所在的目录,`config.json` 里记的也是目录;
* 共用同一个 `env_id` 的两个插件是同一个信任域,策略会**合并**(装载时打印合并结果),权限取并集;
* 只读探测(`os.path.exists` 这类)不弹窗,没权限就安静地返回 `False`/`0`;
* **`os.stat`/`os.lstat` 不产生 Python 审计事件**(CPython 的审计表里就没有),
  所以"内省 + stat"能探测到插件目录外文件是否存在、有多大 —— 挡不住,只能算已知缺口;
* `pro.music_dict` 是快照:读得到、改不动;
* **封存(`seal()`)之后 `can`/`violation`/`note`/`events`/`policy`/`_session`/
  `_policy_frozen`/`_org` 这些名字在 `SandBox` 上不可再赋值**(直接抛 `SandboxDenied`)。
  这是有意的:它们是判权与审计入口。宿主如果在封存后还需要改策略,那是设计外的用法;
  `_host`/`_facade`/`_ask`/`_persist` 不在这个名单里,因为 `b.py` 每次执行插件命令都会
  重新 `attach_host`;
* 判权数据放在模块私有的 `_AUTH` 里,**但"模块私有"挡不住同进程内省**:
  `type(__sandbox__).__init__.__globals__` 拿到的就是这个模块的字典,插件能读到
  `_AUTH` 本身并改写它的**内容**(见上面"第三批"第 07 步)。
  现在的 `plugin_sandbox.py` 用"授权基线过滤 + 调用点固化"把这条路抬高了,
  但抬高不是封死;
* **第四批那三个宿主门面的 `_d` 槽能被"类描述符"绕开(2026-10 实测,未修;bug 名 `facade_d_descriptor`)**:
  `pro.app._d` 确实被 `__getattribute__` 拦着,但 `_d` 本身是**类上的
  `member_descriptor`** —— `type(pro.app)._d.__get__(pro.app)`(或者
  `object.__getattribute__(pro.app,'_d')`,一个内置名就够,不需要内省)照样把
  `(sandbox, 真 Tkapp)` 交出来:实测
  `type(pro.app)._d.__get__(pro.app)[1].tk.eval('expr 1+1')` 返回 `'2'`,
  `type(pro)._d.__get__(pro)[1].env_dict` 直接读到宿主注册表。也就是说第四批堵掉了
  `pro.app._app` 这条**属性**路,但**描述符**那条没堵。
  第五批的模块门面(`_Proxy`)故意没沿用 `_d` 槽,就是为了避开这一类(数据放模块私有的
  弱引用表 `_PROXY_DATA` 里,实例上不留任何属性);宿主门面这一处按 AGENTS.md 只登记、
  不在 `plugin_sandbox_fix_environ.py` 里动 —— 想修就照第五批改动 1 把 `_d` 也搬进表里;
* 插件如果自己在 `plugin/` 里放 `helper.py` 之类的模块,可以 `import`,但它们同样在沙盒里执行;
* **越权弹窗"一辈子只弹一次"(2026-10 实测;bug 名 `ask_once`)**:
  `SandBox._ask_user()` 里原来有个 `_asked` 集合,按 `(能力, 归一化路径)` 记账,
  **弹过一次就不再弹**,第二次同类越权直接走 `deny()` 静默拒绝。实测(`dsh/ask_repeat_probe.py`,
  连续 5 次读同一个沙盒外文件):

  | 第一次用户的选择 | 之后 4 次同类越权的实际行为 |
  |---|---|
  | 允许本次(`ASK_YES`) | 只弹了 1 次窗,后 4 次**静默拒绝** |
  | 拒绝(`'no'`) | 只弹了 1 次窗,后 4 次静默拒绝 |
  | 本次运行都允许(`ASK_SESSION`) | 弹 1 次后记账,后 4 次直接放行(这条是对的) |

  问题在第 1、2 种:用户**再也没机会改主意**——想放行也只能看着它被拒。
  期望语义(用户确认):**每次越权都要弹窗,除非用户明确选了"不再询问"**;
  而当时的 `ASK_*` 常量只有 `yes`/`session`/`always`,宿主弹窗也只有
  "允许本次/本次运行都允许/总是允许/拒绝"四个按钮,**根本没有"不再询问"这个选项**,
  所以 `_asked` 事实上把"拒绝"和"只允许一次"都拖成了永久决定。

  **已修**(`ask_never`):`_asked` 改名成 `_never_ask`,只记**明确要求永不再问**的
  `(能力, 归一化目录)`;新增 `ASK_NEVER` 常量表示"不再询问";宿主用
  `set_persist_deny()` 把它写进 `config.json` 的 `plugin_deny`,装载时用
  `remember_denied()`(凭据 + "栈上没有插件帧"两道关)喂回来。
  现在的行为:`允许本次`/`拒绝` → **每次都弹**;`本次运行都允许`/`总是允许` →
  记账后不再弹;`不再询问` → 记进 `_never_ask` 并落盘,之后同一目录不再弹。
  实测 `dsh/ask_repeat_probe.py` 七个场景全过(A\~G 含"宿主恢复不再询问"与
  "插件伪造不再询问被拒");`tests/test_sandbox_core.py::t_fs_ask` 与
  `tests/test_sandbox_grants.py::t_ask_mapping` 的断言已同步(旧断言写的是
  "同一目标只问一次",与新语义直接冲突)。
  权衡:插件在循环里越权时会连着弹窗(用户要的就是"每次都问"),所以真正的护栏是
  "用户能点不再询问",而不是去重;真机连弹会打断用户,必要时可以让宿主侧自己限速,
  但**不能**再把"静默拒绝"当默认;
* **弹窗默认按钮 = 按钮列表的最后一个(2026-10 实测 `ttkbootstrap`)**:
  `ttkbootstrap/dialogs/message.py` 里是
  `for i, button in enumerate(self._buttons[::-1])` 加
  `elif self._default is None and i == 0` —— 也就是**没显式传 `default` 时,
  最后一个按钮拿到焦点、并绑定回车键**。所以 `_plugin_ask` 的按钮顺序不是随便排的:
  把"不再询问"这种**更永久**的选项放在最后,回车就会默认选中它 —— 所以这个顺序
  必须是有意为之,不能随手排。
  原来的 `t_ask_mapping` 特意断言 `buttons[-1] == '拒绝'`(注释"默认按钮是拒绝")
  就是在守这个设计意图。当前 `b.py::_plugin_ask` 的按钮顺序是
  `['允许本次','本次运行都允许','总是允许','不再询问','拒绝']` —— **"拒绝"在最后,
  所以默认(回车)还是"拒绝"**,这正是想要的效果;测试也重新断言了 `buttons[-1] == '拒绝'`
  (`'不再询问'` 的位置由这条断言间接守住)。
* **用户点了"允许本次",这一次操作却还是被拦(2026-10 实测;bug 名 `ask_once_exec`)**:
  `plugin/sandbox_demo` 的"越界试试"里那句 `os.system('ech hello')`,
  用户明明点了"允许本次",却拿到:

  ```
  [沙盒] 插件 sandbox_demo:门面准备执行 proc 操作,但记账里并没有这份授权(判权入口可能被换过)
  [sandbox_demo] 越界读取被拒(预期行为):插件 sandbox_demo 的 proc 操作没有授权(判权入口在封存后被改动过),已拒绝:None
  ```

  根因是两处口径打架:
    * `_ask_user()` 在 `ASK_YES`("允许本次")分支**故意不落账**(注释写着
      "一次性放行不落账") —— 它只返回 True,授权不写进 `_AUTH`;
    * 可 `proc_guard`/`net_guard` 却**无条件**把 `_auth=('proc',None)`/`('net',None)`
      交给 `_guarded` 复核,而 `_guarded` 的复核读的正是那份记账 → 账上没有 →
      判定"判权入口可能被换过" → 把**用户已经同意**的那一次打死。

  `fs:*` 那几条**没有**这个问题,因为它们走 `_auth_pair(...,durable)`,授权没落账
  时返回 None、跳过复核。也就是说:同样的"一次性放行",文件路径能跑,proc/net 跑不了。

  实测(`dsh/ask_once_exec_probe.py`):修复前 `proc + 允许本次` 和 `net + 允许本次`
  双双 FAIL(真实调用没执行、还各留一条假警报),`SESSION` 与 `fs` 对照组正常;
  **已修**(第十批):`check_net`/`check_proc` 改为返回 `(是否放行, 授权是否落账)`,
  `net_guard`/`proc_guard` 改用 `_auth_pair(ok,durable,'net'|'proc')`,与 `fs` 完全同口径。
  修复后探针 A\~E 全过(一次性放行真的执行、不再有假警报,该拒的仍然拒)。
  教训:凡是"执行前复核"的调用点,都必须用**同一个** `durable` 口径决定要不要复核,
  否则"用户同意"和"复核通过"会互相矛盾;
* 审计钩子装一次就撤不掉(进程级),这是 Python 的设计;
* **`co_filename` 不是身份(2026-10 实测并已在副本里收紧;bug 名 `fake_filename`)**:
  第六批之前,钩子判断"这一帧是不是插件"靠文件名前缀 / 插件目录前缀,而那是插件
  自己传给 `compile()` 的字符串。`plugin/test-1/a.py` 把它武器化成了真机版本:
  伪造 `co_filename` + `pro.app.after`(真 mainloop 是**异步**的,回调跑起来时插件
  帧早已返回),`proc:false` 的插件于是把 `os.system` 跑通
  (`dsh/fake_filename_selftest.py` 用真 `tkinter.Tk()` 复现;`plugin/escape2` 的
  第 12/13 步是同一根因,自测夹具同步所以只能记 N/A)。
  `plugin_sandbox_fix_fake_filename.py` 把判据换成 **code 对象身份**
  (`register_plugin_code` 登记宿主编译的那棵 code 树)+ 给 `after`/`after_idle`
  挂**回调归属**,实测这一路被拦。仍然没堵的:`bind`/`bind_all` 这类"把回调交给
  别的执行上下文"的通道没挂归属(本批只做了 `after` 两条);`pro.app._d` 描述符
  那条老路(上一段)照旧;
* **插件能自己造一个"门面帧",造出来就真的越权(2026-10 实测并已在副本里收紧;
  bug 名 `guarded_frame`)**:
  第三批把审计钩子的判据从"可写的 `_FRAME_LOCAL.depth`"换成"栈上有没有
  `SandBox._guarded` / `SandBox.violation` 的 **code 对象**"(`_hook_in_facade_frame`),
  判据本身是对的 —— 但**那个帧谁都能产生**:`_guarded` 是公开方法,而它只在
  `_auth is not None` 时复核授权,不传 `_auth` 就跳过整个复核并照开 `_facade_enter()`。
  于是插件一句 `box._guarded(lambda: open(r'C:\\Windows\\win.ini'))`
  就能让钩子把这次调用当"门面替插件做的事"放行。
  换句话说:**判据是公开可产生的,它就不是身份** —— 和 `co_filename` 那条同一个病。

  实测(`dsh/guarded_frame_probe.py`,攻击代码按真实路径 `compile` + `register_plugin_code`
  登记成插件 code,所以钩子确实认它):

  | | 插件目录外读 `win.ini` | `os.system` |
  |---|---|---|
  | 插件帧里**直接**做 | `BLOCK` | — |
  | 插件帧里套 `box._guarded(...)` | **读到了** | **执行了**(返回 0) |

  原文件里这句是**作者自己写在注释里的自认**(`plugin_sandbox.py` 2990-2991 行
  "仍然只是一个门槛:插件能直接 `box._guarded(fn)`");本批把它从"自认"
  变成"可复跑的复现",并且发现后果比自认的更重:不只是"能产生帧",而是**产生帧之后就真越权**。

  **已修**(`plugin_sandbox_fix_guarded_frame.py`):`_guarded` 开头加一道
  **直接调用者身份判定** —— 新增模块级 `_plugin_code_at(depth)`,拿"往上第 depth 层
  帧的 code 对象"查 `box_for_code`(第六批的 code 身份账本),判据只认 code 对象身份。
  触发条件是 `_auth is None and not _allow_plugin_caller and _plugin_code_at(1)`:
  * **必须是"直接调用者"**:合法路径里插件帧本来就在栈上(`插件帧 -> fs_open -> _guarded`、
    `插件帧 -> _load_local_module -> _guarded`),用 `_plugin_caller()`(栈上有插件帧)
    会把 `import` 插件自己的本地模块一起误伤;而插件直接调 `box._guarded(...)` 时,
    直接调用者就是插件帧本身,两者能精确分开;
  * **必须同时 `_auth is None`**:`net_guard`/`proc_guard` 的 `func` 是插件提供的
    可调用对象(`os.system` 之类),那时 `_auth` 非 None、已过 `_auth_can` 复核,
    属于合法路径,不该被碰;插件自己调 `_guarded` 拿不到 `_auth_pair` 那种内部口径,
    `_auth` 一定是 None;
  * `_allow_plugin_caller=True` 是给"宿主明知要从插件帧里调、又确实不需要能力判定"
    的路径留的口子,**目前没有任何调用点用它**,要加必须写明理由。

  验证:探针 A/B 从 `VERDICT = BUG` 变成 `VERDICT = FIXED`(攻击组 BLOCK 且留
  `violation:guarded_frame` 审计),回归组(门面 `fs_open`/`fs_listdir` 读自己目录)
  不退化;四个套件逐项对比原文件与副本**判定行完全相同**(core 仍只剩既有的
  `t_import`/`t_import_dotted`),`dsh/escape2_selftest.py` 仍是
  `OK=2 / BLOCK=11 / N/A=1` —— 零回归。

  **仍然没堵的(仍然是"抬高门槛 + 会报警",不是边界)**:
  `_plugin_code_at` 依赖的 `_ledger.code_owner` **仍在模块 globals 里**(同进程、插件
  内省拿得到,和 `_AUTH` 一个层级),够狠的插件改那张表固然会触发第三批那套
  "按记账恢复 + violation",但本检查"能不能被做到恒为假"没有从根上封死;
  本批**只堵"插件直接调 `_guarded`"这一条**,前面几节列的缺口(内省拿 `os.environ`、
  `os.stat` 无审计事件、`pro.app._d` 描述符、Tcl 通道、`bind` 没挂归属)一条没动。
* **`bind`/`bind_all` 没挂回调归属,插件因此能越权(2026-10 实测;bug 名 `bind_channel`)**:
  第六批把"插件帧"的判据从 `co_filename` 换成 **code 对象身份**,并给
  `after`/`after_idle` 挂了**回调归属** —— 但 `_AppFacade._CALLBACK_CHANNELS`
  只有 `('after','after_idle')`,而 `bind`/`bind_all` 在**同一份白名单**
  `_ALLOW` 里,**同一条路没上药**:Tk 触发绑定回调时插件帧早就返回,栈上只剩
  回调自己那一帧,钩子只能靠"这帧的 code 是否在身份账本里"认人。于是
  **账本里没有的 code 对象**当回调交出去,就被当成宿主放行 —— 第六批给 `after`
  关上的那扇门,在 `bind` 上一直开着。

  为什么"生成代码"能造出账本里没有的 code:门面的 `exec`/`eval` 是
  `sandbox_exec`/`sandbox_eval`,它们**顺手把执行过的 code 登记进账本**
  (所以"生成源码 + 门面 exec"这条自己就被认领了);要绕开身份,得用
  **真 builtins** 执行(内省 `type(__sandbox__).__init__.__globals__['_builtins']`),
  或者干脆不生成源码、只换一个 code 对象(`types.FunctionType(别的 code, globals)`)。

  实测(`dsh/bind_channel_probe.py`,真 `tkinter.Tk()` 主循环,事件从宿主定时器里
  发出、**每个事件连续触发 3 次** —— `bind` 的回调会反复触发,只挡第一次不算修好;
  插件 `proc:false`,探针是真 `os.system`):

  | 绑上去的回调 | 它的 code 在账本里吗 | 结果 |
  |---|---|---|
  | A 插件源码里 `def` 的普通函数 | 在 | **BLOCK**(对照组) |
  | B 生成源码 + 门面 `exec` | 在(`sandbox_exec` 自动登记) | **BLOCK** |
  | C 生成源码 + **真 builtins.exec** | 不在 | **越权成功 ×3**(marker 文件被造出来) |
  | D `FunctionType(真 code 对象, globals)` 重组 | 不在 | **越权成功 ×3** |

  A/B 各留 `violation:audit`(被拦下的 `os.system` 在探针里返回码都没拿到,
  所以计数是 0);C/D **一条记录都没有** —— "拦得住但记不下"的反面:
  完全没被看见。修复后同一探针 A/B/C/D **12 次触发全部 BLOCK**,
  留 12 条 `violation:audit`,宿主自己的 `bind` 回调照常执行。

  **已修**(`plugin_sandbox_fix_bind_owner.py`):给 `bind`/`bind_all` 也挂归属,
  但和 `after` 的口径**必须不同** —— `after` 是"一次性回调",账本按"还欠几次执行"
  递减;`bind` 的回调挂在控件事件上,会**反复触发**,按次数记账会在第二次执行时
  归零、又落回"认不出 → 当宿主"。修法:

  * 新增模块私有**弱引用**表 `_bind_owner`(`weakref.WeakKeyDictionary`,
    键是**回调函数对象本身**,不是 code 对象 —— C/D 那类"同一个 code、不同函数
    对象"因此各自算各自的归属,而且插件一丢掉引用、条目就自动消失,
    不会像 `_ledger.pending` 那样黏住不放);
  * **关键是归属必须并进 `box_for_code` 自己那条判据路**(另有一张反向弱引用表
    `_bind_codes`:回调的 code 对象 -> box)。为什么不能只在模块层新加一个
    "按函数对象查"的入口:审计钩子把 `box_for_code` 用**默认参数固化**进了闭包
    (第三批就是这么防"换 globals"的),钩子那条路**看不见**新函数 ——
    实测第一版只加了 `mark_bind_owner`/`box_for_callback`,钩子照样放行 C/D;
  * 门面 `_delegate` 里,`bind`/`bind_all` 的回调**逐个参数**登记归属
    (`after` 原来只认第一个可调用参数,顺手一起改成逐个);
  * 登记条件仍是"这次门面调用确实从插件帧里发出来"
    (`is_plugin_frame_on_stack`),所以**宿主自己**排的 `bind`/`after` 不会被误判;
    插件伪造不了:它交出去的函数对象就是它自己的。

  验证:探针 A/B/C/D **四组全部 BLOCK** 且宿主自己的 `bind` 回调照常执行;
  四个套件与 `dsh/escape2_selftest.py`、`dsh/facade_probe.py` 逐项无退化
  (详见副本文件头的"验证"一节)。

  诚实说明:这条路仍是"抬高门槛 + 会报警",不是边界。`_bind_owner` 本身也在
  模块 globals 里(和 `_AUTH`/`_ledger` 一个层级),够狠的插件内省拿得到它;
  另外**将来任何"把函数交给别的执行上下文"的新接口**(比如 `bind_class`、
  自定义 Tk 命令)都要照同一套补归属 —— 本批只覆盖门面白名单里现有的
  `after`/`after_idle`/`bind`/`bind_all`。

* **`plugin_sandbox.py` 里没有"插件自造 `_guarded` 帧"这条的回归用例**:
  `tests/test_sandbox_facade.py` 那几条(`t_audit_blocks_introspection` 等)走的都是
  "插件帧里直接做",没有一条会去调 `box._guarded(...)`;所以本批的洞在既有套件里
  **全绿也照样存在** —— 要复现/守住它只能用 `dsh/guarded_frame_probe.py`
  (`$env:GUARDED_FIX = 'plugin_sandbox_fix_guarded_frame'` 跑副本对比)。
  教训:套件全绿不等于没有洞,漏的是"用公开入口造出被信任的内部帧"这一类;
* `tests/test_sandbox_integration.py` 里写死了"会被装载的插件清单"和沙盒数量,
  所以 `plugin/` 下**新增一个会装载的插件**(现在的 `plugin/escape` 和
  `plugin/escape2`),那个套件的 `t_wired` 要跟着一起改;`test_sandbox_core.py`
  的 `t_escape_fixture` 按名字点 `plugin/nb`,别把那个夹具删了。

## 自测

```powershell
# 在项目根目录跑
python tests/run_all.py
```

`tests/` 下四个套件:核心能力(`test_sandbox_core.py`)、装载集成(`test_sandbox_integration.py`)、
运行期授权(`test_sandbox_grants.py`)、宿主门面与审计钩子(`test_sandbox_facade.py`,它会装进程级
审计钩子,所以排在最后)。也可以单独跑某一个。`plugin/nb/a.py` 是**越权样本夹具**(它在
`plugin.json` 里 `can_exec:false`,不会自动跑),测试里会被强制打开来验证它撞墙。

加固用的临时验证脚本(`.gitignore` 里的 `dsh*`)放在 `dsh/`:

```powershell
# 前两批(策略数据/判权入口)的逃逸样本,修复后应当"越权成功的项: 无"
.\.venv\Scripts\python.exe .\dsh\escape_selftest.py
# 只验审计钩子闭包与注册表记账
.\.venv\Scripts\python.exe .\dsh\hook_probe.py
# 专验两个曾经踩过的坑:清表之后宿主还能不能干活、撑大白名单还顶不顶用
.\.venv\Scripts\python.exe .\dsh\fix_check.py
```

第三/四批的样本是 `plugin/escape2`,配套三个脚本:

```powershell
# 越权样本:加固前实测 9 条"越权成功"(06~12 真的走出去了),
# 加固后应当只剩 2 条 —— 都是"拿到对象/偷到凭据"这类前置动作,不是越权
.\.venv\Scripts\python.exe .\dsh\escape2_selftest.py
# 门面穿透专项(第 16/17 步):pro.app._app / pro._pro / pro.menu._menu / Tcl eval,
# 应当全部 BLOCK,而白名单方法(pro.app.after 等)仍然可用
.\.venv\Scripts\python.exe .\dsh\facade_probe.py
# 完整的四个套件;默认跑当前的 plugin_sandbox.py
.\.venv\Scripts\python.exe .\dsh\fix_regression.py
```

`escape2_selftest.py` 认 `ESCAPE2_FIX` 环境变量(把 `sys.modules['plugin_sandbox']`
换成指定模块再跑同一套样本),想对比"加固前/后"时用它,平时不用设。
`facade_probe.py` 认 `FACADE_MODULE`,同理。

第五批(`environ`)的副本是 `plugin_sandbox_fix_environ.py`,用同样两个环境变量就能拿它跑同一批样本:

```powershell
$env:ESCAPE2_FIX = 'plugin_sandbox_fix_environ'
.\.venv\Scripts\python.exe .\dsh\fix_regression.py     # 只有 test_sandbox_core 的那 6 行身份断言要改
Remove-Item Env:\ESCAPE2_FIX
$env:FACADE_MODULE = 'plugin_sandbox_fix_environ'
.\.venv\Scripts\python.exe .\dsh\facade_probe.py       # 16/17 仍全 BLOCK
Remove-Item Env:\FACADE_MODULE
```

第六批(`fake_filename`,`co_filename` 不是身份)的复现/验证脚本(修复已并进
`plugin_sandbox.py` 本体,所以下面不设 `ESCAPE2_FIX` 跑的就是加固后的实现;
要比"加固前",才需要把副本模块名传给 `ESCAPE2_FIX`):

```powershell
# 复现/验证主路:真 tkinter.Tk() 主循环下,伪造 co_filename + pro.app.after
#   - 加固前 => exit 2,"拦不住"(marker 文件被 os.system 造出来)
#   - 现在   => exit 0,"拦住了伪造帧,而且宿主未被误伤"
.\.venv\Scripts\python.exe .\dsh\fake_filename_selftest.py
# 顺手探边界:门面 after / 真 Tcl 通道(.tk)都被拦;bind 那条本批没挂归属
.\.venv\Scripts\python.exe .\dsh\fake_filename_probe.py
# 四个套件:facade / integration 那两套的夹具换成 dsh/ 里的副本(原文件不动)——
# facade 原来手工 compile 插件帧,新判据下那种帧不算插件代码,夹具要像真实装载
# 那样登记;integration 只是把新加的 plugin/test-1 补进它自己写明"要跟着加"的清单。
# 结果:grants / facade / integration 全绿,core 只剩它那两条既有失败
# (t_import / t_import_dotted,和本批无关,基线一样红)
.\.venv\Scripts\python.exe .\dsh\fix_regression.py --facade-fixture
```

第七批(性能,`path_norm_cache`)的两个脚本:

```powershell
# 可复跑的基准:装载 / 宿主原生活动(浅栈·深栈)/ 插件越权被拒,单位 us/次。
# 优化前 ≈ 装载 150000、create 144000;优化后 ≈ 装载 1960、create 1070。
# 认 ESCAPE2_FIX 和 BENCH_LIMIT(单项秒数上限,默认 6s,超时标 SKIP 不卡死)。
.\.venv\Scripts\python.exe .\dsh\fake_filename_bench.py
# `_norm` 缓存的正确性:cwd 切换 / 绝对路径 / PathLike / 非路径入参,10 条断言
.\.venv\Scripts\python.exe .\dsh\norm_cache_test.py
# 越权弹窗语义(第十批 ask_once/ask_never):连续 5 次同类越权,看弹窗次数与放行次数。
# 期望值写在脚本的 EXPECT 里;A~G 七组全过才算 ok(含"宿主恢复不再询问""插件伪造被拒")。
.\.venv\Scripts\python.exe .\dsh\ask_repeat_probe.py
```

**宿主侧零改动**:先前那版修复是"`b.py` 装载时多调一次 `self._box.register_plugin_code(code)`",
但那要改 `b.py`(项目原有文件,按 AGENTS.md 不能直接动),所以改成**加固自己在
`SandBox.__init__` 里登记**:它本来就收得到 `plugin_dir`,于是自己读
`plugin.json`、按 `b.py` 的三处细节(`init_file`/`command_file` 覆盖字符串字段、
`.replace('from b import *','',1)`)取出源码,用同一个文件名
`<plugin {name} init>` 编译出**和宿主将要执行的那一棵等价**的 code 对象并登记。
`b.py` 一行没改,逃逸样本照样被拦(实测)。宿主若自己 `compile` 插件代码,还可以用
`SandBox.exec_plugin_code(code, ns)` 交出去执行,由它负责登记。

注意:`plugin/escape2/plugin.json` 现在是 `"can_exec": false`,而 `escape2_selftest.py`
按 `b.Plugin(..., set())` 装载、不会强制打开它,于是脚本会死在
`next(v for k, v in cmds.items() if '越权报告' in k)` 的 `StopIteration` 上 —— 这是**当前仓库状态**
的问题,不是沙盒的问题(拿 `plugin_sandbox.py` 跑也一样)。想看样本结论,把那个 `can_exec` 改成
`true`(或自测脚本里 `n.can_exec = True` 之后再 `init_i`);上面"ok=2 / blocked=11 / na=1"
就是这么测出来的,原文件与副本逐项一致。

这些脚本都只调用插件的报告回调/直接调函数,**不点任何菜单、不弹窗**,所以不会卡住。
另外 `dsh/` 下别用管道(`|`):这个工作区里管道会被沙盒判成 `file access denied`。
