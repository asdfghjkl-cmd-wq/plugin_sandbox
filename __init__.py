"""插件沙盒包。

实现在 ``plugin_sandboxa`` 里。本文件把属性访问**委托**给它,于是既有两种用法都成立:

* ``b.py``                -> ``from plugin_sandbox.plugin_sandboxa import ...``(走子模块)
* ``tests/`` 和 ``dsh/``   -> ``import plugin_sandbox as ps; ps.env_box``(走这里)

用委托而不是"把名字拷一份",是因为实现模块里有些名字是**运行期才出现或会被重新绑定**的
(``_AUDIT_HOOK`` 在 ``install_audit_hook()`` 里才创建、``_NORM_CWD`` 每次换 cwd 都会重新
赋值),拷一份就会读到过期值。
"""

from . import plugin_sandboxa as _impl


def __getattr__(name):
    return getattr(_impl, name)


def __dir__():
    return sorted(set(globals()) | set(dir(_impl)))
