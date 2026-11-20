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

## 档案工作台演示（持续摄取 / 保全 / 复核清除）

工作台是独立数据库格式，与 v1 档案互不通用；把 v1 库传给 v2 命令退出 2 且原库不变。以下演示：旧回复 R 指向缺失的父邮件 P，保全锚点 A 起初不覆盖 R；P 迟到补链后 R 进入保全，原计划被整次阻断；解除保全后执行只清除原候选，迟到且同样到期的 P 不受影响。

```sh
.venv/bin/mail-archive vault-init --source fixtures/vault/batch1 --db run/vault.sqlite
.venv/bin/mail-archive hold-add --db run/vault.sqlite --hold-id LEGAL-1 --anchor '<anchor-a@example.invalid>'
.venv/bin/mail-archive retention-plan --db run/vault.sqlite --plan-id Q1 --before 2026-11-04T00:00:00Z
.venv/bin/mail-archive vault-ingest --source fixtures/vault/batch2 --db run/vault.sqlite
.venv/bin/mail-archive retention-apply --db run/vault.sqlite --plan-id Q1   # 退出2，stderr给出阻断JSON
.venv/bin/mail-archive hold-release --db run/vault.sqlite --hold-id LEGAL-1
.venv/bin/mail-archive retention-apply --db run/vault.sqlite --plan-id Q1   # 清除R，输出收据
.venv/bin/mail-archive retention-apply --db run/vault.sqlite --plan-id Q1   # 重试直接返回首次收据
.venv/bin/mail-archive retention-show --db run/vault.sqlite --plan-id Q1    # 冻结计划+原收据
.venv/bin/mail-archive vault-thread --db run/vault.sqlite --message-id '<parent-p@example.invalid>'
.venv/bin/mail-archive vault-search --db run/vault.sqlite --query ledger
```

预期：计划 `candidates` 只有 `<reply-r@example.invalid>`；摄取补入 `<parent-p@example.invalid>`（它回复锚点 A，A 始终未归档）后，R 沿补全的父链进入保全，执行整次阻断并列出 `blocked`；解除后执行 `purged` 只含 R；再次执行返回同一收据；线程中 R 为 `purged`（无 subject/sender 字段）且不断开与 P 的连接；`ledger` 搜索只剩 P——已清除载荷不可再检索。工作台身份为每次建库随机生成，计划与收据通过它绑定本工作台。

## 契约与边界

详见[数据契约](docs/contract.md)。需SQLite支持FTS5。仅支持契约列明的邮件子集；不获取外链，不连接邮件服务，不提取附件到磁盘。

样例均为本仓原创合成数据，来源见[说明](fixtures/SOURCES.md)，代码/样例MIT许可。业务演示和测试不访问网络，不需要容器或外部服务。
