# data-qd-178 · 邮件证据归档

把.eml的MIME正文、附件摘要、回复父链和原始字节存入独立SQLite档案，再按词或线程只读检索。

## 独立安装与测试

Python >=3.11，本批实测3.12.14。运行与unittest仅用标准库，构建工具精确固定。每仓独立venv，可复用公共下载缓存。

```sh
uv venv --python 3.12 .venv
uv pip install --offline --python .venv/bin/python -r requirements-build.lock
uv pip install --offline --python .venv/bin/python --no-build-isolation --no-deps .
uv pip check --python .venv/bin/python
.venv/bin/python -I -m unittest discover -s tests -v
```

以上离线命令需要缓存已有setuptools==80.9.0和wheel==0.45.1；无缓存时先准备这两个公共构建工具，不声称空缓存可离线安装。修改源码后重装本仓。

## 端到端演示

在仓库根目录执行，输出路径必须不存在。重复演示请换新路径。

```sh
.venv/bin/mail-archive import --source fixtures/mail --db run/mail.sqlite
.venv/bin/mail-archive search --db run/mail.sqlite --query harbor
.venv/bin/mail-archive thread --db run/mail.sqlite --message-id '<reply@example.invalid>'
```

预期：导入2封邮件、1个附件、1个线程；harbor搜索返回2条，agenda搜索0条（附件内容不进入正文）。

输入或业务规则无效、输出已存在时退出2，保留原目标；成功退出0。报告/数据库先完整生成再原子新建，无覆盖。run/为忽略目录。

## 契约与边界

详见[数据契约](docs/contract.md)。需SQLite支持FTS5。仅支持契约列明的邮件子集；不获取外链，不连接邮件服务，不提取附件到磁盘。

样例均为本仓原创合成数据，来源见[说明](fixtures/SOURCES.md)，代码/样例MIT许可。业务演示和测试不访问网络，不需要容器或外部服务。
