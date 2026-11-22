# 离线邮件证据档案 v1

输入目录只读取当前层1..2000个*.eml，拒绝源目录和邮件符号链接；单封≤2MB，合计≤40MB。标准库email按MIME解析，不获取外链，不执行HTML、不把附件名用作磁盘路径。Message-ID严格为一对尖括号包住的无空白身份；一封只能有一个In-Reply-To父身份。重复Message-ID（即使内容相同）和父链环使整个导入失败。缺少父消息时以外部父ID作为线程根，源parent_id不丢失。Date必须可解析并带时区，以UTC存储；搜索结果和线程按实际时间、ID排序，而非输入文件名排序。

multipart遍历只将非附件text/plain正文纳入检索；HTML、内联图片和附带文件名的纯文本不进正文。附件记录解码字节数、SHA256、媒体类型、原文件名；原始整封邮件bytes和源SHA同时存入messages，附件原始编码可由整封源复核。未知/非法正文编码拒绝，解析器报告缺陷时拒绝。仅支持常见MIME邮件子集，不声称完整验证RFC、S/MIME、嵌套message/rfc822或多父References线程。

SQLite FTS5索引主题及纯文本正文；query≤200字符，提取字母/数字词作为literal AND，不接收FTS操作符；最多100条。thread按指定已存在消息返回同根所有消息，允许线程根为外部未归档ID。两个只读命令独立读取SQLite，不再打开源邮件。源附件保存在原始消息中，不单独提取二进制文件。

完整解析及建库后，通过同目录临时SQLite+原子硬链接发布到新文件；已有目标（包括符号链接）拒绝，失败不替换原档案，临时文件清理。import成功退出0，输入/SQLite/路径失败退出2。后续不维护增量摄取、身份合并、保留期限或外部邮件服务。需要Python SQLite内置FTS5。

# 档案工作台 v2（vault）

工作台是独立数据库格式：`vault_meta` 标记 `mailroom-vault`，表名带 `vault_` 前缀，与 v1 档案互不通用、不迁移。把 v1 库传给任何 v2 命令（或反向）退出 2，原库逐字节保留。`vault-init` 完整建库后经同目录临时文件+原子硬链接发布到原本不存在的路径；之后任何命令都不再读取历史源目录。无需后台服务、网络、并发写入或附件提取。

## 摄取（vault-init / vault-ingest）

批次约束与 v1 相同：当前层 1..2000 个 `*.eml`、拒绝源目录与邮件符号链接、单封 ≤2MB、合计 ≤40MB、同一 MIME 子集、带时区 Date、单 In-Reply-To 父身份、批内 Message-ID 唯一（重复即整批失败）。摄取成功输出三个按 ID 排序的数组：

- `inserted`：新 Message-ID，完整载荷（原始 bytes、主题、发件人、正文、附件描述、FTS）入库，状态 `live`。
- `unchanged_live` / `ignored_purged`：跨批同一 Message-ID 且原始 SHA256 相同视为重送，只确认身份；live 归前者，已清除归后者且不恢复任何载荷。
- 跨批同一 Message-ID 但 SHA256 不同：整批拒绝，即使解析出的正文相同也不覆盖。

新批父链与全部已存身份（含已清除节点）一起解析线程根并检测环；跨批构成的环使整批回滚。迟到父邮件到达后，所有消息的 thread_id 依完整图重算归属，不把新批作为独立线程集合拼入。每次摄取是单个事务：要么全部生效，要么完全不生效。

## 线程身份

与 v1 语义一致：完整父链尽头的无父消息 ID，或第一个尚未归档的父 ID（外部根）。已清除的身份节点仍参与补链与环检测。

## 保全（hold-add / hold-release）

保全 ID 与计划 ID 各自独立、大小写敏感，格式 `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`。锚点采用既有 Message-ID 语法，可以尚未到达，也可以已清除。一项有效保全覆盖锚点本身，以及沿父链能到达该锚点的全部已归档后代；外部缺失父 ID 也能匹配锚点。覆盖在每次需要时按当前完整父图动态计算，随迟到补链和后续摄取变化，不冻结登记当天的线程根或成员列表。多项有效保全取并集，解除一项不解除其他项。同 ID 同锚点重复登记是成功重试；同 ID 换锚点、或重新启用已解除 ID 均拒绝。解除未知 ID 拒绝，重复解除成功。保全只阻止尚未执行的清除，不能恢复之前已清除的内容。

## 清除计划（retention-plan / retention-show）

`--before` 是 ISO 8601 日期时间：`YYYY-MM-DDTHH:MM:SS`，必含秒，可含最多六位小数，时区为 `Z` 或 `±HH:MM`；按实际时刻比较，输出规范化为 UTC。到期集合 = 创建时已存在、尚未清除且 `sent_at < before` 的邮件（等于截止点不属于到期）。未受保全的写入 `candidates`（`id` + 原始 `sha256`）；受保全的写入 `held`（另附当时实际覆盖它的全部保全 ID，排序）。计划文档绑定工作台持久身份（vault）、计划 ID 与规范化截止点，候选与保全项均按 ID 稳定排序，不含正文、主题、发件人或原始字节；创建空计划合法。同计划 ID 与相同实际截止时刻重试返回首次保存的原计划，即使期间摄取、保全或清除已改变；换截止时刻拒绝。`retention-show` 输出 `{"plan": 冻结原计划, "receipt": 原执行收据或 null}`，永远展示冻结文档，不用当前状况重算，且为只读操作。

## 执行（retention-apply）

清除范围只来自冻结计划的 `candidates`；`held` 项即使保全已解除也不加入，创建后新摄取的到期邮件也不加入；无关摄取与无关保全变化不把计划作废。执行前以当前完整父图和当前全部有效保全重新检查仍未清除的候选：只要有一个目前受保全，整次拒绝，stderr 输出 `{"error":"held","blocked":[{"id","holds"}]}`（按候选顺序、保全 ID 排序），退出 2，库中不留半次清除或成功收据；阻断保全解除后可再次尝试。

成功清除是应用数据层清除：删除该邮件原始 bytes、主题、发件人、正文、全部附件描述及 FTS 检索内容，只保留 Message-ID、parent_id、sent_at、原始 SHA256 与 `purged` 标记；不证明 SQLite 空闲页、文件系统快照或外部副本不可恢复。不清除其他邮件，不把有后代的邮件整棵子树顺带清除。候选若已被另一份计划清除，记为 `already_purged`。收据含 `vault`、`plan_id`、排序后的 `purged` 与 `already_purged`，只覆盖冻结候选。载荷移除、索引更新与首次成功收据在同一事务提交。成功后再执行同一计划直接返回首次收据，不再判断当前保全、不更改分类、不纳入后来摄取的数据；该重试规则优先于当前保全检查。未知计划拒绝。计划与收据只留身份/处置信息，不作为已清除载荷的备用副本。

## 查询（vault-search / vault-thread）

`vault-search` 沿用 v1 的 literal AND、≤200 字符、≤100 条上限，只返回仍有载荷的命中；清除后不能通过主题或正文再检索到该邮件。`vault-thread` 对已存在的活邮件或清除身份均可查询，返回当前同根全部节点，按 sent_at、ID 排序：每项含 `id`、`parent_id`、`thread_id`、`sent_at`、`status`（`live`/`purged`）；仅 live 项另给 `subject`、`sender`，purged 项不含这两个字段。未知 Message-ID 拒绝。中间节点已清除不断开后代，保全状态不作为查询过滤条件。查询与计划查看不修改数据库。

## 退出码与失败语义

所有成功命令退出 0；无效路径/输入、身份冲突、环、未知对象、保全阻断或数据库错误退出 2。变更失败保留上次完整可读状态；成功输出丢失时，重启后上述重试规则仍成立（计划与收据均已持久化）。

# 离线外部审阅（review-open / review-export / review-return / review-notes）

外部审阅在既有 vault 之上运行，不引入网络、并发写入或邮件服务，也不改变摄取、线程、保全与清除的任何既有契约。v1 档案与不存在的库对新命令一律拒绝，且不会被创建或改写。新功能按需在当前 vault 增加 `vault_review_*` 持久表，无需重新导入邮件；从未用过审阅功能的 vault 里这些表不存在，`review-notes` 对已存在身份仍返回空数组且不触发任何建表或写入。

## 登记（review-open）

SPEC 是严格 JSON 对象，恰含 `review_id`、`messages`，不接受任何未声明字段。批次 ID、回传批 ID（return_id）与意见 ID（annotation_id）均为大小写敏感的 `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`。`messages` 含 1..200 个对象，每项恰含 `message_id` 与 `redactions`；Message-ID 沿用尖括号原语法、批内不得重复，且登记时必须是当前 `live` 邮件（已清除或未知身份拒绝）。`redactions` 为至多 100 个 `[start,end]`，端点必须是非布尔整数（JSON 的 `true/false` 与浮点数拒绝），按已归档 `body` 字符串的 Unicode 码点下标、左闭右开，满足 `0 <= start < end <= len(body)`。不做换行、空白或 Unicode 规范化。区间允许乱序、相交或相邻：先求并集并把相邻区间合并，每个合并区间无论长度都整体替换为字面量 `[REDACTED]`（10 个 ASCII 字符），其余字符原样保留。空正文只能配空区间列表。

登记把批次绑定到 vault 持久身份、选中的 Message-ID 集合、登记当时的完整源 SHA256、正文 SHA256（正文按 UTF-8 字节计摘要）以及规范化（合并后）区间，并按源 Message-ID 排序分配批次内公开编号 `M0001`、`M0002`……。审阅表只保存坐标、摘要、公开编号与审阅者主动提交的意见文本；正文、主题、发件人、原始邮件字节与脱敏正文从不复制进新表、登记摘要、日志或收据，因此现有清除仍能真正移除源载荷，审阅数据不会成为载荷备份。

`review-open` 在登记前先在内存生成完整交付件并确认其紧凑 JSON 编码不超过 8,000,000 字节，超限整次拒绝且不建任何审阅表。成功摘要只含 `review_id` 与 `item_count`。同一 `review_id` 配等价规范 SPEC 的重试返回首次摘要：消息数组顺序、区间数组顺序以及同一并集的不同拆法都不构成变更；选中身份集合或合并后区间不同则拒绝，旧批次不可覆写。等价重试先于当前 live 检查，所以源邮件后来被清除不影响返回原登记摘要。

## 交付件格式与摘要口径（review-export）

交付件是严格 JSON，恰含 `format`（固定 `mailroom-review-1`）、`review_id`、`items`、`package_sha256` 四个键。每个 item 恰含 `item_id`、`parent_item_id`、`text`，按公开编号排序；`text` 即按登记区间生成的脱敏正文。仅当直接父邮件也在本批选中集合中时 `parent_item_id` 才是父邮件的公开编号，否则为 `null`：未选祖先的内部 ID、外部父 ID 都不会出现，交付件里也不存在任何内部 Message-ID 映射、主题、发件人、附件、源时间、源摘要、vault 身份或原始字节。正文里偶然出现的 `[REDACTED]` 字面量属于普通原文，不做额外自动内容审查或替换。

`package_sha256` 的口径固定：取除该字段外的交付件对象，按 `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)` 编码为 UTF-8 后计算 SHA256。交付文件本身也采用同一紧凑、键排序编码（含摘要字段，无尾随换行）。因此重复导出到不同新路径产生字节完全一致的文件与同一摘要。

导出只读取登记时那组邮件，后来的摄取不会扩大交付集合。每次导出都重新按保存的区间生成同一逻辑交付件，并逐封确认源邮件仍为 `live`、完整源 SHA256 与正文 SHA256 都与登记值一致；任一邮件已清除或任一摘要不一致则整次失败、不生成文件，既不删除缺失项继续，也不从旧交付件反灌恢复载荷。目标路径已存在（含符号链接，含悬空符号链接）时拒绝；完整内容先写同目录临时文件，再以硬链接原子发布到新路径，失败清理本次临时文件。每个对外可见的完整交付件都有持久登记与编号映射，不依赖进程内缓存，重启后仍可凭文件回收。已经发到外部的副本不属于本地清除能撤回的范围。

## 回收与坐标语义（review-return）

FEEDBACK 是严格 JSON，恰含 `review_id`、`package_sha256`、`return_id`、`annotations`。`annotations` 含 1..1000 项，每项恰含 `annotation_id`、`item_id`、`start`、`end`、`comment`。意见 ID 在整个审阅批次内全局唯一（跨不同回传批也不可复用），同一反馈内也不得重复；`comment` 必须是含非空白字符、长度不超过 2000 码点的字符串并原样保存。`start/end` 是针对该 item 已交付 `text` 的左闭右开非空码点区间。

圈选合法性不能只做端点或字符串搜索判断：系统在生成脱敏文本时为每段幸存原文维护“交付坐标→源坐标”的连续片段，插入的 `[REDACTED]` 标记不属于任何幸存片段。圈选必须完整落在某个幸存片段内；只要区间（含内部任意码点）碰到任何插入标记字符，整份反馈拒绝，不做截断、拆分或对遮盖原文的猜测。正文里未被遮盖的字面量 `[REDACTED]` 是正常幸存原文，可以圈选，并按其真实源坐标落回。合法意见精确换算为源正文区间：例如 `abcdefXYZghi` 遮盖 `[2,6)` 得到 `ab[REDACTED]XYZghi`，交付坐标 `[12,15)` 的 `XYZ` 落回源 `[6,9)`；同一交付位置会因前面多个不同长度遮盖产生累计位移，按实际片段映射处理。

回收先验证 SPEC/FEEDBACK 的严格结构、交付件自身摘要（外部文件自带摘要必须与其内容相符）、批次与公开编号，再用 vault 中的登记与当前 live 源正文重新生成预期交付件并做深度比较（含项目集合与顺序）。攻击者即使篡改 `text`、`parent_item_id`、项目集合或顺序后重新计算摘要，也会在与登记交付件的比对中被拒绝。FEEDBACK 必须绑定准确批次与实际预期交付摘要；不同批次的映射互不串用，即使正文相同、公开编号同为 `M0001` 也一样。回收不修改邮件载荷、线程、保全或清除状态。

接受的意见落库为：内部源 Message-ID、源完整 SHA256、源正文摘要、源正文区间，以及交付坐标、批次 ID、回传批 ID、意见 ID 与 comment。首次接受把全部意见与该反馈的成功收据在同一事务提交；收据仅含批次 ID、return_id、交付件摘要及排序后的意见 ID。同一 return_id 配等价规范 FEEDBACK（annotations 输入顺序可不同，comment、身份与坐标必须完全一致）重送返回首次收据且不新增意见；同 return_id 换内容拒绝。新 return_id 若引用任何已被别的回传批占用的意见 ID，整批拒绝，不会吞掉冲突只收其余项。

## 重试与清除边界

已接受反馈的真实重送仍须提交同一份逻辑交付件并通过严格结构、自身摘要与已保存交付身份检查；这些检查及回传身份完全匹配后直接返回原收据，且该短路先于源邮件当前 live 检查。因此源邮件在成功回收后被清除，收据不会丢失；但新 return_id 带来的新意见只要关联交付中的任一源邮件已清除，就整份拒绝、不写新意见。成功回收不产生保全效果，也不改变任何 retention 行为。系统从不保存交付正文作为重试捷径，重生成所需的一切只是登记坐标与（仍 live 时的）当前源正文。

## 查询（review-notes）

`review-notes --message-id` 是只读操作，按源邮件身份返回已接受意见，按 `review_id`、`return_id`、`annotation_id` 排序。输出只含意见身份、公开 item 编号、交付与源坐标、登记时的两个摘要与 comment，不含正文摘录、主题、发件人、原始邮件或任何源载荷；意见坐标不得用于重建载荷。邮件清除后仍可凭保留身份查到意见与坐标。未知源身份拒绝；身份存在但没有意见返回空数组；没有审阅表的合法 vault 同样返回空数组且不建表。

## 输入防护与失败语义

新输入 JSON 沿用既有防护：重复键拒绝、`NaN/Infinity/-Infinity` 等非有限数拒绝、文件上限 8 MB，此外拒绝上文未声明的任何字段。除 items 的既定顺序外，对象键顺序与不影响内容的空白不参与逻辑身份。登记与回收失败保持上次完整状态（单事务，无半批意见或半张收据）；成功输出丢失后可关闭程序再按身份重试。所有成功命令退出 0；输入、路径、格式、数据库错误、身份冲突、篡改、坐标不合法或源不可用一律退出 2。


# 多保管人取证包核对入档（collection-import / collection-show / vault-provenance）

本功能在既有 vault 之上运行，不引入网络、并发写入、外部求解服务或附件提取，也不改变摄取、线程、保全、清除与外部审阅的任何既有契约。它按需在当前 vault 增加本功能自己的持久表，无需重新导入邮件；从未用过本功能的 vault 里这些表不存在，`vault-provenance` 对已存在身份仍返回空数组且不建表。v1 档案与不存在的库对新命令一律拒绝，且不会被创建或改写。

## 清单（MANIFEST）

MANIFEST 是严格 JSON 对象，恰含 `intake_id` 与 `packages`，不接受任何未声明字段；沿用既有的重复键拒绝、`NaN/Infinity/-Infinity` 拒绝与 8 MB 上限。`intake_id`、`package_id`、`custodian` 均为大小写敏感的 `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`，三者名称空间彼此独立；`package_id` 只在一次 intake 内唯一，`custodian` 可跨包重复。

`packages` 含 1..18 项，每项恰含 `package_id`、`custodian`、`value`、`source`。`value` 为 1..1,000,000 的非布尔整数（JSON 的 `true/false`、浮点数、字符串拒绝）。`source` 为非空目录路径，相对路径以 MANIFEST 所在目录为基准解析。

每个 `source` 读取当前层 1..200 个 `*.eml`，沿用既有目录/文件规则：来源须为真实目录、拒绝目录与文件符号链接、单封 ≤2MB、同一 MIME 子集、带时区 Date、单 In-Reply-To 父身份、批内（即包内）Message-ID 唯一与无回复环。包内重复 Message-ID 或回复环使整次输入失败。所有包合计最多 600 个文件出现次数、原始字节合计不超过 40,000,000；即使多个包指向同一目录也逐包计数。必须完整读取并验证**所有**包，不能因为某包很可能不入选就跳过坏邮件——任何包内无效邮件都使整次输入失败。文件顺序与文件名不参与业务选择。

## 选择语义

以本次开始时 vault 已存的全部身份作为不可改写基线（含 `purged` 身份）。一个包的价值代表整批来源证明，不能为凑齐邮件而拆包挑项；包要么整体入档，要么完全不入档。

- 包中邮件与已存 Message-ID 的 `source_sha256` 不同 → 该包无法入选（`archived_identity_conflict`），即使解析后主题/正文相同也不算同版本。
- 与已存 `source_sha256` 相同 → 作为已有证据的来源佐证，不重复插入、不恢复 `purged` 载荷。
- 包与包之间同 Message-ID、同原始 SHA256 可共同入选，即使 `custodian` 相同也不额外合并包价值；同 Message-ID、不同原始 SHA256 的版本不能共同入选（`selected_identity_conflict`）。
- 包与包之间按解析后主题/正文相同不当作同版本。

还须检查完整父图：取全部已存身份及选包内真正新增的身份，以原 `parent_id` 连接；缺失父 ID 是外部节点，不因缺失而失败。联合图不得有环，包括经已存 live/purged 节点闭合的环，以及仅多个包合起来才形成的环（`reply_cycle`）。原包各自合法不等于联合可入档；不能仅做包间重复 ID 检查，也不能先分别调用旧摄取再把结果拼起来。任何选中包内的全部邮件都必须作为新身份或相同摘要的已有佐证得到处理，不能丢弃冲突项来保留该包价值。

在所有可行包集合中求全局最优，按以下优先级唯一决定：先最大化所选包 `value` 总和，再最大化所选包数量，最后比较各自按 `package_id` 升序排列的 ID 数组，选择字典序最小者。允许一个包包含别包全部邮件，或多个包只贡献重复字节，仍按整个包参与选择和计分。空集合始终可行；全部包都不合适时也成功保存空选择收据。结果必须精确最优，不能按 value 降序贪心、逐包先到先得或任意返回一个极大可行集合；选择顺序不能影响结果。求解在本节限定的有限范围内精确完成，不缩小范围、不降级近似。

## 收据与入档

成功向 stdout 输出 JSON 收据，恰含 `vault`、`intake_id`、`total_value`、`selected_packages`、`inserted`、`unchanged_live`、`ignored_purged`、`excluded`。`selected_packages` 为按 `package_id` 排序的所选包 ID 数组；三个邮件数组为所选包并集去重后的 Message-ID：本次新入档（`inserted`）、入档前已有且 `live`（`unchanged_live`）、入档前已有且 `purged`（`ignored_purged`），均按 ID 排序。

最优集合确定后，在同一事务中入档其全部新身份、原始载荷、附件描述与 FTS，更新受迟到父补链影响的存量 `thread_id`（与摄取相同的完整图重算），并登记全部选包对每个邮件身份的来源佐证以及首次成功收据。来源条目至少含 `intake_id`、`package_id`、`custodian`、`value`、`message_id`、`source_sha256`；同一 intake 下包内每个邮件只记一条（主键 `(intake_id, package_id, message_id)`）。原来的 live/purged 状态、跨批身份、保全和清除行为仍按原契约：相同摘要的 `purged` 身份只增加来源佐证、不复活；新父节点确实入档后，存量后代归根和当前保全覆盖随之改变，旧清除计划仍在执行时尊重新的当前覆盖。未选包不得留下正文、附件、FTS 或任何已采集来源条目。采集包文件路径只在本次核对期间使用，不作为永久读取依赖；收据与来源表不复制正文、主题、发件人、附件描述、原始字节或源目录路径，因此不构成已清除载荷的备份。

## excluded 与阻碍见证

`excluded` 按未选包 `package_id` 排序，每项含 `package_id`、`reason`、`witness`。`reason` 的判定方式：把该未选包整体加入最终选包集合，给出可复核的阻碍，按以下优先级：

1. `archived_identity_conflict`：包内至少一个版本与基线已有身份摘要不同，`witness` 为这些 Message-ID 的排序数组。
2. `selected_identity_conflict`：没有上述冲突，但与最终选包有不同版本冲突，`witness` 为这些 Message-ID 的排序数组。
3. `reply_cycle`：无摘要冲突但加入后形成环，`witness` 为一条闭合父链 ID 数组，首尾相同；旋转到环中最小 ID 开头，若有多条环取这些规范数组中字典序最小者。链中每一步必须是真实 `parent_id`，不可只列涉事包名。

正价值保证每个未选包都至少有一种上述阻碍。`witness` 只证明为何不能再加入某包，不代替全局最优选择本身。

## 重放与身份

`intake_id` 标识一次完整核对。规范请求由每包的 `package_id`、`custodian`、`value`，以及按 Message-ID 排序的原始 SHA256 身份清单组成；包数组顺序、文件名、目录位置或相对/绝对路径不同不影响请求身份，邮件原始字节一旦不同即算变更。同 `intake_id`、同规范请求重试返回首次收据，不重选、不重复记来源；先前排除的包后来因档案变化也不能改变原结果。已有成功重试仍完整验证输入文件及规范请求，但在确认身份相同后优先于当前档案选择和 live/purged 检查。相同 `intake_id` 换任一包元数据、邮件身份或摘要则退出 2。

## 只读查询

- `collection-show --intake-id`：返回该次 intake 首次保存的收据；不需要原目录。未知 `intake_id` 拒绝。
- `vault-provenance --message-id`：可查询 live 或 purged 身份，按 `intake_id`、`package_id` 排序返回 `{"message_id", "sources": [...]}`，没有来源返回空数组，未知 Message-ID 拒绝。只读命令不得因新表不存在而建表；未使用本功能的合法 vault 可对已有身份返回空数组。

## 事务与失败语义

新表按需加入已有 vault，不要求重导邮件；失败不能留下部分建表或半次入档。成功退出 0；无效输入、源读取、数据库错误或 intake 身份冲突退出 2；单个包业务上无法入选是正常核对结果，不是整个命令失败。载荷、附件、FTS、线程、来源条目和收据在同一次完整提交中落库；成功输出丢失可重试（返回首次收据），提交前失败可以修复环境后重投。不修改或重签已有外审交付件和原收据。

# 离线灾备取证恢复（recovery-*）

本节在既有 vault 之上增加离线灾备：事故前由管理员为正常源 vault 定期保存自包含检查点并导出清除权威清单；事故后即使原 vault 与全部邮件目录都已丢失，也能凭两份离线材料重建当时的业务记录，供调查人员只读回看。恢复副本只用于历史取证，不继续接收新业务，并在较新的合法清除事实下抑制相应载荷。

只使用 Python 标准库；不联网、不并发写、不做密码学签名、不自动寻找“最新”文件。v1 档案、缺失库与恢复副本上的 `recovery-enable`，以及未开启跟踪的正常 vault 上除 `recovery-enable` 外的全部新命令，一律退出 2 且不修改数据库。原 v1、正常源 vault、审阅与采集的全部既有接口和业务语义保持不变；未开启恢复跟踪的 vault 行为与加入本功能前完全一致。

## 身份与水位（recovery-enable / recovery-info）

`recovery-enable --db VAULT` 为一个已有正常 vault 开启恢复跟踪：在同一次提交中增加本功能自己的持久状态表，写入一个新的随机持久 `stream` 身份，并把当前完整已提交状态记为 `revision` 0。原 `vault` 身份不变，不要求重导入、重建或改写任何当前业务记录。对已开启的 vault 重试返回原身份与当前水位，不重新归零；开启操作不改变业务状态，因此不推进水位（仍为 0）。

开启后，每一次现有变更操作（`vault-ingest`、`vault-init` 之后的摄取、`hold-add`/`hold-release`、`retention-plan`/`retention-apply`、`review-open`/`review-return`、`collection-import` 等业务变更）若确实改变了业务持久状态，必须在**同一次 SQLite 提交**中把 `revision` 恰增加 1。一次操作改动很多行也仍只加 1。判定依据是事务内对已提交逻辑业务表的完整摘要比对，而不是进程内计数器，因此：

- 全部失败并回滚的操作、纯查询、导出文件、相同身份的成功重送（摄取重送、同计划重试、同保全重登记、审阅/采集的等价重试、已执行计划的收据重放等）都不改变业务状态，不推进水位；
- 空清除计划、首次接受空选包结果的采集、记录空收据的首次成功清除都是真实的新业务记录，都推进 1；
- 跟踪表自身的维护（enable、恢复副本的状态持久化）不属于业务状态，不递归计数；
- 该规则在 `vault._transact` 这一所有变更函数共用的提交点上实施，CLI 与既有 Python 调用（`vault.*`、`review.*`、`collection.*`）语义一致，不依赖进程内计数或逐个 CLI 覆盖。

`recovery-info --db VAULT` 只读返回恢复身份、当前水位与恢复来源，不建表、不推进水位、不重写数据库。

## 检查点（recovery-checkpoint）

`recovery-checkpoint --db VAULT --output FILE` 从一个一致的已提交业务状态（只读快照）生成一个自包含检查点并发布到新路径。文件是确定性的紧凑、键排序、无尾随换行的 UTF-8 JSON，格式为：

```
{"format":"mailroom-recovery-checkpoint-1",
 "vault":"<持久 vault 身份>","stream":"<持久 stream 身份>",
 "revision":<非负整数水位>,
 "tables":{ "<逻辑表名>": {"columns":[...],"blob_columns":[...],"rows":[[...],...]}, ... },
 "checksum":"<对除 checksum 外整个对象的规范化编码的 SHA256>"}
```

`tables` 恰含复原所需的全部当前逻辑记录，按固定表名与列集合：`vault_meta`；`vault_messages`（live/purged 身份、父链、线程、状态、live 载荷与原始 bytes、源摘要）；`vault_attachments`（附件描述）；`vault_holds`（保全及其解除状态）；`vault_plans`（冻结计划文档）与 `vault_receipts`（已存在的执行收据）；`vault_review_batches`/`vault_review_items`/`vault_review_annotations`/`vault_review_receipts`（审阅批次、公开编号、坐标、摘要、意见与回收收据）；`vault_collection_intakes`/`vault_collection_sources`（采集来源、规范请求与首次收据）。未使用的审阅或采集表在检查点里以空 `rows` 出现，因此空业务状态不会变成缺表错误。BLOB（原始邮件 bytes）以 base64 编码。FTS 索引不保存，恢复时由保留的 live 载荷重建。检查点不保存捕获前已经清除的源载荷，也不把 SQLite 空闲页、旧 FTS 段或 journal 残留当作逻辑记录。

格式校验：根对象必须恰含上述六个键；`format`、`vault`、`stream`、`revision`、`tables`、`checksum` 类型与取值严格；`checksum` 必须与内容一致；每张表必须恰含 `columns`/`blob_columns`/`rows`，列集合必须与格式固定集合完全一致（拒绝放大或伪造列）；purged 身份不得带载荷，live 身份必须有正文与原始 bytes；父/线程/Message-ID 语法、状态、摘要、附件引用、计划-收据约束、审阅/采集外键等业务不变量都会被校验。文件是否有效只由内容、格式与校验和决定，绝不以文件名或后缀判定。检查点只能在正常源 vault 上生成；恢复副本上 `recovery-checkpoint` 退出 2，不产生任何输出。

写出前先在内存中完整生成并以读者的同样规则校验，随后统计完整文件字节数，超过 512,000,000 字节则退出 2 且不发布；校验通过后才以同目录临时文件+硬链接发布到原本不存在的路径（包括拒绝悬空符号链接）。成功 stdout 为恰含 `vault`、`stream`、`revision`、`sha256`、`bytes` 的对象，`sha256`/`bytes` 是实际已发布文件的摘要与字节数。

## 清除权威清单（recovery-authority）

`recovery-authority --db VAULT --output AUTHORITY.json` 从正常源 vault 的一个一致已提交状态导出清除权威清单。清单是严格 JSON 对象，恰含 `format`、`vault`、`stream`、`revision`、`purged`：`format` 固定 `mailroom-recovery-authority-1`；`vault`/`stream` 是正常源 vault 的持久身份；`revision` 是同一已提交状态的非负整数水位；`purged` 是该状态下全部 `purged` 身份，按 Message-ID 排序，每项恰含 `message_id` 与 `source_sha256`。没有清除身份时仍输出对象且 `purged` 为 `[]`。

校验拒绝重复身份、未排序、额外字段、布尔或非整数水位、非法 ID 或非 64 位小写十六进制摘要；沿用既有的重复键拒绝、`NaN/Infinity/-Infinity` 拒绝与 8 MB JSON 防护。文件按 `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)` 的 UTF-8 字节编码，无尾随换行。生成端也检查完整文件不超过 8,000,000 字节，超限退出 2 且不发布；先完整生成并在内存校验后才以同目录临时文件+硬链接发布到新路径。成功 stdout 为恰含 `vault`、`stream`、`revision`、`sha256`、`purged_count` 的对象。

清单只含清除身份与源摘要，绝不含原始邮件、正文、主题、发件人、附件描述或意见文本。一次成功清除与其清除事实、水位推进及首次执行收据在同一事务提交，因此清单只会发布整次清除后的完整状态，不会公布半次清除；已执行清除的重送不推进水位、不改清单。

## 信任边界与外部摘要

正常源 vault 中已成功提交的清除是权威事实，`recovery-authority` 负责把它导出。操作者负责在事故前妥善保存最新一份合格清单，并在恢复时从可信事故记录取得两份文件的准确 SHA256 及要求的最小 `revision`。

`recovery-restore` 的两个 `--*-sha256` 参数都是对应文件**原始字节**的 SHA256（64 位小写十六进制），属于外部信任输入，不能用文件内自报摘要代替：程序对实际读入的字节计算 SHA256 并与参数比对。`--min-revision N` 是非负十进制整数，表示操作者已知必须覆盖的源水位。程序要求清单 `revision` 同时不小于 `N` 和检查点 `revision`，且 `vault`、`stream` 与检查点相同；缺失材料、文件摘要不符、异源（vault 或 stream 不同）、水位不足均退出 2。文件的键顺序或空白变化不改变业务结构，但会改变外部文件摘要，必须按实际提交字节核验。

清单若漏掉检查点中已经 purged 的身份，或与检查点同 ID 的 `source_sha256` 不同，整次拒绝。对清单中检查点里还没有的身份（事故后较晚创建或较晚清除），只核其结构与摘要格式，不凭空加入恢复库。相同 `vault`/`stream` 且相同 `revision` 声称同一已提交状态，此时清单的 purged 身份及摘要集合必须与检查点完全一致；不能把同水位下额外声明的清除当作将来事实接受。

软件不能仅凭水位与文件自身证明它在现实中全局最新：若某次清除在提交后、导出清单前就丢失了源库，旧清单不包含这次事实，程序无法发现不可见的事实。操作者不能把旧清单声明为最新后要求软件自行发现。缺少合格的可信材料时应停止恢复；本功能**不提供**忽略清单、降低水位或从检查点自造权威的兜底模式。原检查点文件、已交付的外部文件与其他离线副本不在本功能撤回或物理擦除范围内。

## 恢复（recovery-restore）

`recovery-restore --checkpoint FILE --checkpoint-sha256 HASH --authority AUTHORITY.json --authority-sha256 HASH --min-revision N --db NEW_VAULT` 核验两份离线材料后，恢复到原本不存在的新路径；目标已存在（含悬空符号链接）退出 2。

恢复以检查点时点为业务可见边界，再叠加权威清除：

- 检查点原有的 purged 身份保持 purged；
- 检查点时 live、且在清单里的身份改为 purged：移除其原始 bytes、主题、发件人、正文、全部附件描述与 FTS，保留原 Message-ID、`parent_id`、`thread_id`、`sent_at`、`source_sha256`（父图保持连通，后代不断链）；
- 没有被清单清除的 live 身份保留完整原载荷；
- 清单中的未来身份、后来才创建的保全/计划/执行收据/意见/来源/邮件都不能注入。例如某邮件在检查点后清除，本次不会伪造一条“检查点时已执行”的旧计划收据；
- 检查点已有的计划、收据、审阅与来源事实原样保留，即使其中某些邮件现被抑制。历史意见 `comment` 由审阅者主动提交、可能自行引文，按既有契约原样保留；不据此猜测或重建正文，也不自动删改用户意见。

恢复不先把旧检查点原样复制成磁盘数据库再清除：在通过可信清单确认需要抑制后，被抑制邮件的源载荷与派生索引内容不会被新写入目标文件、临时文件、磁盘临时库、journal、WAL 或 FTS 残留页（失败路径同样如此）。实现上，恢复在一个同目录临时数据库中**只插入允许保留的记录**：被抑制身份在插入前即改写成 purged 无载荷行，附件行与 FTS 行从不写入。读取原检查点、核验其内容与构建新库都在同一进程内完成；操作系统交换区、原备份文件与外部快照不在本要求范围。最终库由允许保留的记录构成，不以改 `status`、隐藏查询或 `DELETE` 后留自由页代替该约束。普通 live 邮件与保留的 comment 偶然含相同字符不算违规。

恢复库建成后，同一事务写入持久 `recovered` 标记与来源：`vault` 身份与 `stream` 不变，`revision` 表示检查点水位，另持久记录检查点与清单的实际文件 SHA256、清单水位、排序后的 `suppressed`（只列本次由检查点 live 改成 purged 的 ID，原本 purged 的不重复列）。数据、FTS 与 `recovered` 锁全部持久化并被重新读取核验后，才以硬链接发布到新路径。恢复副本可脱离全部输入文件再次启动，继续支持只读的 `vault-search`、`vault-thread`、`retention-show`、`review-notes`、`collection-show`、`vault-provenance` 与 `recovery-info`，返回值沿用旧接口；历史计划/收据不因抑制而重算，purged 节点保持父图连通，notes/provenance 仍可见。`review-export` 在副本上是“读取已登记源并向新文件交付”，允许运行，但任一来源被抑制仍按既有规则整批失败且无交付文件；全部来源仍 live 时字节与原登记一致。

副本永久标记为 `recovered`，正常源为 `source`。副本禁止全部数据库变更入口，包括 `vault-ingest`、`hold-add`/`hold-release`、`retention-plan`/`retention-apply`、`review-open`/`review-return`、`collection-import`、`recovery-enable`；即使请求是之前成功操作的真实重送，也先因 `recovered` 拒绝，不能返回成功收据后绕过只读模式。该限制在 `vault._transact` 与各自入口共同实施，覆盖 CLI 与既有库函数。副本也不能再导出 `recovery-checkpoint` 或 `recovery-authority`，以免成为看似正常的权威来源；`retention-show` 仍可查看已有成功收据。只读命令不触发任何懒建表、水位更新或数据库重写，空结果保持原接口形状（如 `review-notes`/`vault-provenance` 的空数组、`retention-show` 的 `receipt: null`）。

## 输出与失败语义

新命令所有成功 stdout 均为一个 JSON 对象：`recovery-enable`、`recovery-info`、`recovery-restore` 使用恰含 `mode`、`vault`、`stream`、`revision`、`checkpoint_sha256`、`authority_sha256`、`authority_revision`、`suppressed` 的对象——`source` 模式下后三个摘要/清单水位字段为 `null`、`suppressed` 为 `[]`；`recovered` 模式填写持久来源，数组为空时也保留。原命令输出形状不变。

检查点/清单完整生成核验后才发布到新路径；恢复库完整建成、数据与索引核验完成且 `recovered` 锁已持久化后才发布。失败不留下可误认成功的输出或本次临时文件，不改源库、输入备份或已有目标；成功输出丢失后可用新输出路径重试（不要求覆盖旧文件）。所有成功退出 0，格式/路径/来源/水位/身份/只读限制或数据库错误退出 2。无需抵御操作者手工改库或自行移除锁。

# 可续读 mboxrd 邮箱取证接入（mbox-scan / mbox-show / mbox-resolve / mbox-certify）

本节在既有 vault 之上增加物理邮箱台账：保管人可分多次追加同一个大邮箱文件，调查人员按明确的 mboxrd 子集逐记录入档；坏记录隔离为缺口而不中断后续证据，缺口经人工补正或豁免、来源封口且全部记录有最终处置后，才出具并冻结首次完整性凭据。仅用 Python 标准库，无网络、无并发写入、无后台服务。v1 档案与不存在的库对新命令一律拒绝，且不会被创建或改写；新表按需在当前 vault 创建，从未使用本功能的 vault 不报错、不建表。命令不改变 v1、vault、审阅、采集与恢复的任何既有契约，也不套用目录摄取的 40MB 总量或文件数上限。

## 明确的 mboxrd 子集与字节口径

不自动猜测邮箱格式。原始文件按字节处理：行以 LF 结束，可保留其前导 CR。完整 envelope 分隔行是从行首开始、前五字节恰为 ASCII `From ` 并以 LF 结束的整行，不校验行内寄件人与日期。除空文件外，第一行必须是这样的分隔行；文件开头不足一行时，仅当当前字节仍可能构成 `From ` 前缀才作为未完成尾部等待，明显不匹配则整次拒绝。每条记录从一个 envelope 行开头到下一 envelope 行开头，最后一条只能在来源封口后以 EOF 为结束。envelope 行不属于邮件原文；其后各行若行首是一个或多个 `>` 紧接 `From `，仅去掉最前面的一个 `>`，其余字节、换行与末尾是否换行原样保留（CR、UTF-8 与多段 MIME 不做规范化）。其他行不解转义；正文中未经转义的 `From ` 行按分隔行处理，操作者须提供符合本子集的文件。

解码后的邮件字节才是现有 MIME 解析、原始载荷与 `source_sha256` 的输入，仍受单封 2,000,000 字节上限。台账另对每条记录保存包含 envelope 的整个原始字节范围 `[start,end)` 的 `record_sha256`，两类摘要口径不同、不得混用。空文件合法；未完成的尾记录不占本次 limit、不占台账序号、不是隔离失败。

## 来源身份、承诺前缀与续扫

`source-id` 沿用工作台对象 ID 语法，大小写敏感，在一个 vault 内独立命名。FILE 必须是真实普通文件，拒绝符号链接；原路径与文件名不参与来源身份，文件可搬动后续扫。一次命令期间文件保持静止；只支持两次命令之间的追加，或对尚未承诺尾部的合法修改。

台账对每个来源持久公开 `next_offset`、`pinned_bytes`、`pinned_sha256`、`sealed` 以及封口后的 `source_bytes`/`source_sha256`。`next_offset` 是下一待处理记录的 envelope 起点（封口且全部扫描后等于文件长度）。续扫先逐字节复核此前承诺的原始前缀，比较的是真实字节 SHA256，不比较文件长度、mtime、inode、Message-ID 或解码摘要；承诺范围包含用来证明上一条记录结束的下一条完整 envelope 分隔行——仅锁到上一条 `end` 而允许该分隔行被改成普通正文会改变已入档记录边界，必须拒绝。源缩短到承诺长度以下、承诺字节被改写，均整次失败且不推进台账；承诺范围以后的未处理正文允许重写后再扫。空前缀的摘要是空字节 SHA256；没有已处理记录时 `pinned_bytes` 可为 0。

## scan 与封口语义

`mbox-scan --db VAULT --source-id ID --source FILE [--limit N] [--seal]` 登记或续扫一个来源，本次最多处理 N 条完整记录，N 是 1..100 的非布尔整数，默认 100；admitted 与 unresolved 都计入 limit。按物理记录顺序分配连续正整数 `record_number`，不允许跳号或因重试重记。未封口时，即使最后一封已能被 MIME 解析，只要后面没有完整 envelope 分隔行就不处理它，等待后续追加。到达当前可处理边界而无新记录、且没有新封口时是成功 no-op。

`--seal` 是操作者声明来源不再追加：本次把当前完整文件长度与原始 SHA256 一起持久绑定，此后包括未扫描部分在内全部不可变，`pinned_bytes`/`pinned_sha256` 随之成为整文件的长度与摘要；封口后的 FILE 必须与保存的全文件身份完全相同，任何追加都拒绝。封口让最后一条以 EOF 结束的记录可处理，但不绕过 limit，可分多次继续扫这份已固定文件。首次封口与本次入档、隔离和进度在同一事务成功或一起回滚；重复 `--seal` 不重新封口。空文件可封口并最终结案；非空文件若末尾只有没有 LF 的未完成 envelope 行（其行首仍可能成为 `From ` 前缀），不能封口，整次失败；最后一封邮件内容本身可以没有末尾 LF。

## 逐记录处置与隔离优先级

每条完整记录保存连续 `record_number`、原始范围、`record_sha256` 与固定结果。可隔离的单记录业务问题按优先级依次为 `oversize`、`invalid_mail`、`identity_conflict`、`reply_cycle`，台账写 `status=unresolved` 与 reason 后继续处理后面的完整记录。oversize 也必须完整跨过这条原始记录（原始范围与摘要照常落账），不能截取前 2MB 伪装合法邮件；坏记录不留下任何身份、线程改动、附件、FTS 或载荷，联合父图检查在插入后发现环时也撤回该记录的全部尝试。源读取失败、数据库错误、磁盘错误等环境故障不吞成隔离：整次命令失败，本次较早的合法记录、隔离记录、前缀、封口与恢复水位均不部分提交——一次 scan 是单个事务，不是每条记录各自提交。

解码后单封沿用现有 MIME、Date、Message-ID、附件摘要与单父链语义。相同 Message-ID 且相同解码邮件 SHA256 允许在本来源重复出现，每个物理记录各留台账但只入档一次；与 live 同字节记 `unchanged_live`，与 purged 同字节记 `ignored_purged` 且绝不复活载荷，新身份记 `inserted`。三种成功记录 status 均为 `admitted`，admission 保存具体分类。同 ID 不同字节记 `identity_conflict`；与存量或本次较早记录构成回复环记 `reply_cycle`，该记录不入档。迟到父邮件真正入档后，现有回复按完整图重新归根，当前保全覆盖随之改变；原清除计划仍按原规则重查当前覆盖，不为本接入模式绕行。扫描与处置不自动登记保全，不伪造 custodian、package 或 value，不改既有 collection 收据与 provenance 形状。

## 人工处置（mbox-resolve）

DECISION 是沿用项目重复键拒绝、非有限值拒绝与 8MB 防护的严格 JSON。补正对象恰含 `source_id`、`record_number`、`record_sha256`、`action`、`reason`、`replacement`，`action` 为 `replace`；豁免对象恰含前五项，`action` 为 `waive`。`record_number` 是非布尔正整数；摘要为 64 位小写十六进制，必须同时匹配该来源的那条隔离记录，不能拿另一来源的同序号代替。`reason` 是 1..2000 Unicode 码点且含非空白字符的字符串，原样保存。`replacement` 是真实、非符号链接的 `.eml` 普通文件，相对路径以 DECISION 所在目录为准；它是未经 mboxrd 包装的完整邮件，按已有单封限制与 MIME 规则验证。

补正不要求新邮件字节等于原坏记录，但必须同时保留原 `record_sha256`、补正原始 SHA256（`replacement_sha256`）、最终 Message-ID 与理由，凭据不能冒称原坏记录已原样入档；无需重读原 mbox，也不能覆盖原字节范围或摘要。补正作为整体通过当前 vault 的身份与父图检查后再完成处置：新邮件入档或同字节重送的分类与扫描一致，相同身份已 purged 时只确认身份不恢复。补正失败保持 unresolved、不留载荷与半次处置。豁免不入档任何邮件，仅把缺口标为 `waived`。成功补正 status 为 `replaced`，admission 保存该次补正实际的 inserted/unchanged_live/ignored_purged 分类；原扫描直接成功的为 `admitted`。首次补正或豁免与其成功收据在同一事务提交。已处置记录不得改决定；完全相同决定重送先返回原收据（补正重送仍读取并验证 replacement 的真实字节，以字节摘要、action、原样 reason 与原记录身份组成请求身份，文件名与路径不参与；豁免无需文件），该短路优先于邮件当前 live/purged 状态。原 admitted 记录不能用 resolve 改写。环境故障同样整次回滚。

## 凭据（mbox-certify）与只读视图（mbox-show）

只有来源已封口、`next_offset` 到达封口长度且没有 unresolved 记录时才能成功；单纯扫描至 EOF、仍有未扫完整记录或只有“坏记录已跳过”都拒绝，不得输出貌似完整的成功凭据。凭据恰含 `vault`、`source_id`、`source_bytes`、`source_sha256`、`records`；records 按 record_number 排序，逐项给 record_number、start、end、record_sha256、最终 status，以及 admitted/replaced 的 message_id、message_sha256、admission 和 replaced/waived 的 reason；replaced 另有 replacement_sha256，waived 不带邮件身份。空来源 records 为 `[]`。凭据证明固定原始邮箱的每条物理记录都已入档、补正或明确豁免，不证明没有豁免，也不证明邮件以后仍有载荷。成功后永远返回首次冻结凭据；后来的保全、清除、来源目录删除不能重算、失效或改分类，台账不复制邮件正文作为凭据备份。

`mbox-show` 只读返回恰含 `vault`、`source_id`、`next_offset`、`pinned_bytes`、`pinned_sha256`、`sealed`、`source_bytes`、`source_sha256`、`records`、`certificate` 的对象；未封口时 source_bytes/source_sha256 为 null，证书未创建时 certificate 为 null。records 按序列出公共记录身份与 status，unresolved 项给 reason，replaced/waived 项另保留 `initial_reason` 追溯首次隔离原因（证书记录不含该字段）。scan 成功返回同一最新 show 形状，resolve 返回对应最终记录对象，certify 返回凭据。所有输出都不含原邮件、主题、发件人、附件描述、原 envelope、解码正文、源文件路径或替换文件路径。查询与证书可脱离原文件再次启动；未知 source-id 拒绝。清除仍只清除原邮件载荷，不丢失台账身份，也不会从源路径或替换文件偷偷加载回来。

## 有界内存与失败语义

不对整个 mbox 套用 40MB 上限，也不把全文件或一条无限长坏记录读入内存。源字节以固定大小分块流式读取，内存中的源字节工作集有固定上界，与邮箱总长、已扫描前缀长度和超限记录长度无关；可正常持有当前合法单封（≤2MB）及现有业务元数据。超限记录在解码累计到达上限后继续流式读完并计算原始摘要，不保留多余字节。

所有变更经 vault 的单一事务提交点：已启用恢复跟踪的正常源上，一次 scan/resolve/首次 certify 若确实改变持久业务，revision 在同一提交恰增加 1；一次 scan 处理多条也只加 1。no-op、原决定重送、重复 certify、失败与 show 不增加；新来源首次登记（含空来源）是业务变化。未启用跟踪的 vault 可直接使用本功能。

## 恢复扩展

检查点格式在原六键结构不变的前提下扩展 `tables`：新增 `vault_mbox_sources`、`vault_mbox_records`、`vault_mbox_certificates` 三张逻辑表，列集合固定并随恢复校验不变量（封口状态、范围、摘要、status/reason/admission 取值、证书只引用封口来源等）。旧格式检查点不含这三张表，恢复时按空台账处理并继续按原契约恢复，不拒绝、不重签旧文件；未使用本功能的旧 vault/旧检查点不因缺表变成错误。完整检查点保存进度、承诺前缀、封口、隔离与处置、首次凭据，不保存外部源文件。恢复后 show 展示检查点时点的台账与凭据，后来才入档/处置/封口的记录不注入；权威清单抑制载荷不改写历史入档分类，凭据不因载荷被抑制而重算。recovered 副本仅允许 `mbox-show`；`mbox-scan`、`mbox-resolve`、`mbox-certify` 三个变更入口（含真实成功重送）在 CLI 与库函数层面都先拒绝。沿用抑制载荷不得回写恢复输出或暂存文件的原约束。

成功退出 0；结构、路径、来源身份、补正冲突、结案条件、只读限制或环境故障退出 2。可隔离的坏记录是 scan 的正常成功结果。失败保留上次完整可读状态，首次建表也不留下半次台账。
