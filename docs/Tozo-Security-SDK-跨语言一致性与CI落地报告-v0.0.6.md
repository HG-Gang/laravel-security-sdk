# Tozo Security SDK 跨语言一致性与 CI 落地报告

版本：v0.0.6（截至 2026-08-28 的状态修订）
编制日期：2026-08-28
执行依据：v0.0.5 报告 §6「生产准入建议」第 4、5 项
运行环境：PHP 8.0.2 当前 checkout；PHP 7.4.3 为此前 checkout 历史基线；Python 3.9.13、Go 1.25.7、PHPUnit 9.6.36

## 1. 本轮完成的两项建议

v0.0.5 报告列出的九项准入建议中，第 4、5 项在本机可执行，本轮已完成：

| 建议项 | 状态 | 产物 |
|---|---|---|
| 4. 第二语言实现消费向量 | **已完成，超出范围** | Python + Go 两种独立实现，均逐字节一致 |
| 5. CI 矩阵 | **已完成** | 四版本 PHP 矩阵 + 跨语言作业 + 分发检查 |

原建议是"一种语言"，实际做了两种。原因：Python 与 Go 的 URL/字符串处理与 PHP 差异方向不同（Python 的 `parse_qs` 折叠重复键，Go 的 `url.Values` 是无序 map 且 `QueryEscape` 把空格编码为 `+`），两者共同覆盖的规范歧义面比单一语言大得多。

## 2. 跨语言一致性验证

### 2.1 实现原则

两份实现**从零按 `protocol/README.md` 的文字规则编写，不移植 PHP 源码**。这是关键约束：如果照抄 PHP，通过只能证明"复制正确"，不能证明规范完备。

刻意避开各语言的便利函数：

| 语言 | 刻意不使用 | 若使用会怎样 |
|---|---|---|
| Python | `urllib.parse.parse_qs` | 重复键折叠成列表并丢失原始顺序 |
| Python | `quote()` 默认 safe 集 | 默认保留 `/`，与协议未保留字符集不符 |
| Go | `net/url.ParseQuery` | 返回 map，丢失重复键顺序，方括号键被当字面键名 |
| Go | `url.QueryEscape` | 空格编码为 `+`，协议要求 `%20` |
| Go | `map[string]interface{}` | 遍历顺序随机，无法复现 wire 字节 |

两份实现都只依赖标准库，便于任何环境复现。

### 2.2 结果

```text
PHP    7.4.3 / 8.0.2   115 断言   一致
Python 3.9.13           92 比对项  一致
Go     1.25.7           92 比对项  一致
```

统一入口：

```bash
composer run conformance
```

```text
[PASS] 冻结向量漂移检查
[PASS] PHP 向量测试
[PASS] Python 一致性
[PASS] Go 格式检查
[PASS] Go 静态检查
[PASS] Go 一致性
结论：PHP / Python / Go 三种实现与冻结向量逐字节一致
```

缺少 Python/Go 运行时时标注 `SKIP` 并说明原因，不伪装成通过。

### 2.3 本机制发现的规范缺陷（1 项）

**空 query 的 JSON 表示存在 PHP 语义泄漏**

初版向量中 `canonical_query_array[].input` 的空值写作 `[]`。PHP 的 `json_decode('[]', true)` 得到空数组，与空映射同型，PHP 侧 11 个用例全绿；但：

- Python 读到 `list`，`.items()` 抛 `AttributeError`
- Go 按 JSON 数组解析，与 `orderedEntries` 期望的对象不符

根因：PHP 数组不区分列表与映射，这一语义泄漏进了协议制品。JSON 无法表达"PHP 的空数组"这个既是列表又是映射的类型。

修复：生成器对该字段强制 `(object)` 转换，空 query 序列化为 `{}`。PHP 侧不受影响（`json_decode('{}', true)` 仍得 `[]`），其他语言得到明确的空映射。

**这条缺陷单靠 PHP 测试永远发现不了。** 它是跨语言验证的直接价值体现——也说明 v0.0.5 报告把"向量已冻结"当作跨语言就绪的判断是过早的。

### 2.4 防御深度：两道独立防线

| 防线 | 拦截对象 | 机制 |
|---|---|---|
| `vectors-check` | 实现悄悄改变协议行为 | 重新生成并与冻结文件逐字节比对 |
| Python / Go 一致性 | 向量被改写以迁就错误实现 | 独立实现不依赖 PHP，仍按正确规则计算 |

第二道防线是关键。**负向对照实测**：把 `canonicalQueryString` 的 `sort` 改为 `rsort`（悄悄反转 query 排序）后

- `vectors-check` → FAIL（检出漂移）
- 若攻击者继续执行 `composer run vectors` 覆盖向量以掩盖改动，Python 一致性 → **仍然 FAIL**：

```text
[signature.value] get with repeated query keys
    expected: 'aE5iIzOHP_y_Fj6eJ5BxwCfaSrvozt3mKJ3mkkbYdIw'
    actual:   'z2HFMKyLi8SDdiVFgfB_TBw5yK4wNpY3gLZGF0rFk9w'
```

恢复后两者均通过。单靠向量文件无法防止"改实现同时改向量"，独立实现才能。

## 3. CI 落地

`.github/workflows/ci.yml`，三个独立作业，任一失败阻断合并。

### 3.1 php 作业（5 个组合）

| PHP | 依赖策略 | 目的 |
|---|---|---|
| 7.4 | locked | 声明的最低版本，不允许 continue-on-error |
| 7.4 | **lowest** | 验证 `composer.json` 声明的依赖下限真实可安装 |
| 8.0 | locked | 当前主要开发版本 |
| 8.1 | locked | 上限兼容 |
| 8.2 | locked | 上限兼容 |

关键设计：

- `fail-fast: false` —— 需要同时看到所有版本结果，便于区分"版本特有"与"普遍"问题。
- `ini-values: error_reporting=E_ALL, display_errors=On` —— 把 deprecation 也暴露，避免 8.x 隐性不兼容被吞。
- 独立步骤断言 `platform_check` 门槛不高于 `70400` —— 直接防止 v0.0.5 修复的 R-1 类缺陷复发。
- `--prefer-lowest` 单列一行而非合并 —— 合并会让上限问题被下限成功掩盖。

### 3.2 protocol 作业

```text
冻结向量漂移检查 → Python 一致性 → Go gofmt + vet → Go 一致性
```

该作业**刻意不依赖 PHP SDK 的测试结果**：跨语言一致性必须由外部实现证明，不能由被验证方自证。

### 3.3 package 作业

| 检查 | 目的 |
|---|---|
| `git archive` 内容含 `protocol/test-vectors-v1.json` | 协议事实来源必须随包分发 |
| 归档不含 `tests/`、`docs/`、`.idea/`、`.claude/` | 缩小下游 vendor 体积 |
| `--no-dev` 安装后核心类可解析 | 生产 autoload 不得依赖 tests |

核心类清单覆盖八个类，含本轮之前新增的 `ResponseIntegrityMiddleware`——防止新增文件漏配 autoload。

### 3.4 本地等价入口

CI 逻辑全部固化为可本地执行的脚本，避免"只有 CI 能跑"：

```bash
composer run verify        # = php 作业的 lint + audit-style + test + vectors-check
composer run conformance   # = protocol 作业
```

## 4. 分发包裁剪

`.gitattributes` 的 `export-ignore` 规则：

| 路径 | 分发 | 理由 |
|---|---|---|
| `protocol/test-vectors-v1.json` | **保留** | 其他语言 SDK 需消费 |
| `protocol/README.md` | **保留** | 协议字节级规则说明 |
| `protocol/conformance/` | 排除 | Python/Go 验证实现只在本仓库 CI 运行 |
| `tools/` | 排除 | 开发期检查脚本，下游不需要 |
| `tests/`、`docs/`、`.github/`、`.idea/`、`.claude/` | 排除 | 开发期文件 |

同时强制 `eol=lf`：签名规范化串以 `\n` 连接，若某个环境把源码或向量文件检出为 CRLF，会导致签名原文字节不一致。这不是格式偏好，是正确性要求。

## 5. 新增产物清单

| 文件 | 说明 |
|---|---|
| `protocol/conformance/README.md` | 跨语言验证说明、不一致时的处置流程、已发现缺陷记录 |
| `protocol/conformance/python/tozo_protocol.py` | Python 独立实现（仅标准库） |
| `protocol/conformance/python/conformance_test.py` | Python 向量消费器 |
| `protocol/conformance/go/tozo_protocol.go` | Go 独立实现（仅标准库） |
| `protocol/conformance/go/conformance_test_main.go` | Go 向量消费器（保序 JSON 解析） |
| `protocol/conformance/go/go.mod` | Go module 定义 |
| `.github/workflows/ci.yml` | 三作业 CI 配置 |
| `tools/gen_vectors.php` | 向量生成器，支持 `--check` 漂移检查 |
| `tools/conformance.php` | 三语言一致性统一入口 |

`tools/lint.php` 与 `tools/audit.php` 在 v0.0.5 已加入。

## 6. 验证证据

```text
=== PHP 8.0.2 ===
lint            121 个文件，失败 0 个
audit-style     全部检查项通过
phpunit         OK (284 tests, 1151 assertions)
vectors-check   向量文件与当前实现一致

=== PHP 7.4.3 历史基线（此前 checkout，非本轮新鲜结果） ===
lint            107 个文件，失败 0 个
phpunit         OK (219 tests, 592 assertions；此前 checkout）

=== 跨语言 ===
Python 3.9.13   92 比对项，0 不一致
Go 1.25.7       92 比对项，0 不一致
gofmt           无需格式化
go vet          无告警

=== 配置 ===
composer validate       ./composer.json is valid
CI YAML 解析            3 作业（9 / 9 / 4 步）
export-ignore 规则      7 项逐项验证通过
platform_check          PHP_VERSION_ID >= 70400
```

### 6.1 负向对照

| 注入的缺陷 | 期望 | 实测 |
|---|---|---|
| `canonicalQueryString` 的 `sort` 改为 `rsort` | `vectors-check` 失败 | FAIL，提示须升协议版本 |
| 同上 + 重新生成向量掩盖改动 | Python 一致性仍失败 | FAIL，逐条打印 expected/actual |

两项均在恢复后通过。

## 7. 准入建议剩余项

v0.0.5 §6 九项中，跨语言向量和 CI 已落地。当前 checkout 的自动化门禁已扩展到 284 个测试/1151 个断言，lint 已覆盖 121 个项目 PHP 文件；四系统配置包另有专项测试覆盖 8 套环境、24 个 Profile 和 48 个示例 PHP 文件；显式路由 Profile 的 `client_id` 绑定回归也已纳入测试；剩余项及其可执行性：

| 项 | 内容 | 本机可执行 |
|---|---|---|
| 1 | 完整 Laravel 8.5 应用集成 | 否，需真实应用骨架；当前 Composer 实际约束 Illuminate Console ^8.83 |
| 2 | Redis 多实例并发重放 | 否，需 Redis 集群 |
| 3 | Guzzle 真实 HTTPS | 否，需网络与证书 |
| 6 | 生产密钥注入与轮换演练 | 否，需部署环境 |
| 7 | 逐路由风险标注 | 否，属项目方业务决策 |
| 8 | 日志脱敏抽查与审计留存 | 否，需生产日志管道 |
| 9 | 高并发性能测试 | 否，需压测环境 |
| 10 | 四个真实业务系统 12 条有向互调 | 否，需四个业务仓库、Redis、TLS 与测试数据 |

**这七项都不是代码问题，而是环境与流程问题。** 代码侧当前无已知缺陷，但这七项中任何一项都可能在真实环境暴露新问题——典型如 Redis 驱动的 `add()` 在特定配置下未必原子、反向代理可能改写 Header 大小写或归一化 path、Laravel 的 `config:cache` 可能改变配置数组序列化行为。

## 8. 准备度更新

| 维度 | v0.0.5 | v0.0.6 |
|---|---|---|
| 架构技术可行性 | 90%～93% | **92%～95%** |
| 本地验证环境可用可信度 | 93%～96% | **95%～97%** |
| 生产准备度 | 78%～85% | **82%～88%** |

提升依据：跨语言一致性由"向量已就绪"变为"两种独立实现实测一致"，并因此发现并修复了一项 PHP 语义泄漏；CI 把所有检查固化为可重复执行的门禁。

生产准备度未进入更高区间，仍是因为 §7 的环境验证和四系统真实互调未完成。这一判断不因文档样例已经写出而改变。

## 9. 结论

本轮把 v0.0.5 报告中"最高优先"的两项建议落地，并在过程中发现了一项**只有跨语言验证才能暴露**的规范缺陷（空 query 的 JSON 表示）。这验证了当初"先冻结向量再做互通"判断的必要性——但也说明"向量冻结"本身不等于跨语言就绪。

更重要的收获是建立了两道独立防线：向量漂移检查拦截实现悄悄改协议，独立语言实现拦截"改实现同时改向量"。后者是单靠向量文件无法提供的保障，已用负向对照实测确认。

下一阶段的瓶颈已转移到环境侧：需要真实 Laravel 应用、Redis 集群、HTTPS 链路、四系统 staging 互调和压测环境。代码与协议侧在当前覆盖范围内无已知缺陷，但真实部署前仍需按指南逐项验收。
