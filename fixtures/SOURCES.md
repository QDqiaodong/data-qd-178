本目录数据为本项目原创合成样例，采用仓库 MIT 许可；不含真实客户、人员或运营数据。样例无需联网生成或下载。

- `mail/`：v1 档案演示，两封港口修复主题邮件，其一含纯文本附件。
- `vault/batch1/`、`vault/batch2/`：工作台演示的两批邮件。第一批只有回复 R（父邮件 P 缺失）；第二批补入 P，且 P 回复保全锚点 A（A 始终不到达），用于演示迟到补链把 R 拉入保全、阻断清除计划。
- `review/batch1/`：外部审阅演示的三封合成邮件（选入批次的父子对加一封父邮件未选入的邮件），正文含交叠遮盖目标、字面量 `[REDACTED]` 与日文多字节字符。`review/spec.json` 与 `review/feedback.json` 是对应的登记 SPEC 与回收反馈，摘要与坐标均由测试独立核算。
- `collection/baseline/`、`collection/package-x/`、`collection/package-y/`：多保管人采集包演示。基线只有回复 R（父 P 缺失）；`package-x` 价值高但带来会让 R 闭环的 P；`package-y` 价值低但带来另一版本的 P，P 回复锚点 A。`collection/manifest.json` 是严格清单，测试独立核对选择、来源与收据。
