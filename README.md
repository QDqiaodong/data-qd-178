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

## 外部审阅演示（脱敏交付 / 圈选回收 / 清除边界）

档案员在 vault 内登记审阅批次，外部审阅者只拿到不含内部 Message-ID 的脱敏交付件；回收意见时交付坐标精确回映到源正文。演示数据在 `fixtures/review/`：三封邮件中 `<review-b@…>` 回复 `<review-a@…>`（父在批次内），`<review-c@…>` 的父邮件未选入（其内部 ID 不得出现在交付件中）。SPEC 对交叠/相邻区间取并集，并同时保留正文里的字面量 `[REDACTED]` 与多字节日文。

```sh
.venv/bin/mail-archive vault-init --source fixtures/review/batch1 --db run/review.sqlite
.venv/bin/mail-archive review-open   --db run/review.sqlite --spec fixtures/review/spec.json
.venv/bin/mail-archive review-export --db run/review.sqlite --review-id EXTREV-1 --output run/package.json
.venv/bin/mail-archive review-return --db run/review.sqlite --review-id EXTREV-1 \
    --package run/package.json --feedback fixtures/review/feedback.json
.venv/bin/mail-archive review-notes  --db run/review.sqlite --message-id '<review-b@example.invalid>'
```

预期：登记摘要仅为 `{"review_id":"EXTREV-1","item_count":3}`；交付件 `format` 为 `mailroom-review-1`，项目按 `M0001..M0003` 排序，M0002 的 `parent_item_id` 为 `M0001`，M0001/M0003 为 `null`，且文件中找不到任何尖括号内部 ID 或 `unselected-grandparent`；交付摘要固定为 `d4804e6ea4a60f40a5099abd567d8e098ca1e80e713ece7e1f0381771483ee35`，文件为紧凑键排序 JSON、无尾随换行。回收收据的 `annotation_ids` 为 `["ANN-CRANE","ANN-JP","ANN-LITERAL"]`；notes 显示日文圈选交付 `[45,48)` 精确落回源 `[40,43)`，正文里未遮盖的字面量标记交付 `[31,41)` 落回源 `[26,36)`。换一个不存在的输出路径重复 `review-export` 得到字节相同的文件；同一 SPEC/FEEDBACK 重送返回同一摘要与收据。

清除边界：对演示 vault 执行一次 retention 清除后，`review-export` 退出 2 且不留半文件；已接受反馈用原 return_id 重送仍返回原收据，而新 return_id 的新意见整份拒绝；`review-notes` 仍可凭源身份查到坐标，但任何返回都不含正文、主题或发件人。

## 契约与边界

详见[数据契约](docs/contract.md)。需SQLite支持FTS5。仅支持契约列明的邮件子集；不获取外链，不连接邮件服务，不提取附件到磁盘。

样例均为本仓原创合成数据，来源见[说明](fixtures/SOURCES.md)，代码/样例MIT许可。业务演示和测试不访问网络，不需要容器或外部服务。
