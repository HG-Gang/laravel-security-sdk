# Tozo Security SDK 全量审查与可行性报告

版本：v0.0.5（截至 2026-08-28 的状态修订）
审查日期：2026-08-28
运行环境：PHP 8.0.2 当前 checkout 实测；PHP 7.4.3 为此前基线证据；PHPUnit 9.6.36、Windows 10
审查方式：逐文件源码阅读 + 可执行探针 + 负向对照 + 双 PHP 版本运行

## 1. 结论摘要

### 1.1 可行性判断

架构方向合理可行。本轮在当前 checkout 补齐了 Profile 显式 null 拒绝、显式安全开关类型校验、Token 开关方向边界、按模式容器门控、四系统配置、客户端方向边界和显式路由的 `client_id` 强绑定，并保留 Protocol v1 一致性基准和 JWT 算法混淆防护的可执行证据；PHP 7.4.3 仍只有此前 checkout 的历史基线，尚未在当前 checkout 重跑。

| 维度 | v0.0.4 | v0.0.5 |
|---|---|---|
| 架构技术可行性 | 90%～93% | **92%～95%** |
| 本地验证环境可用可信度 | 93%～96% | **95%～97%** |
| 直接作为生产安全基础设施准备度 | 78%～85% | **82%～88%** |

准备度提升的依据是三项**实测**结果，不是自评：

- 当前 PHP 8.0.2 真实运行 284 项测试、1151 个断言全通过；PHP 7.4.3 的 219 项历史基线仍需在当前 checkout 重跑确认
- Protocol v1 向量冻结并通过**不调用 SDK** 的独立手工复算
- 算法混淆攻击面由 7 个负向用例（含正向对照）证明关闭
- 四系统 v0.0.8 配置包专项测试通过：8 套环境各 6 个 Profile、12 条有向关系、24 个 Profile、48 个 PHP 文件语法；请求/响应 key 配对一致且测试/生产 key ID 集合无交叉

### 1.2 仍未闭环的项

准备度未达更高区间，是因为真实环境仍未完成：完整 Laravel 8.5 应用集成、Redis 多实例原子性、真实 HTTPS 传输、四个业务系统双向互调和生产运维演练。Protocol v1 的 Python/Go 向量一致性已完成，但它不等于四个 Laravel 服务已完成双向部署。

## 2. 本轮发现并修复的问题

### R-1 依赖锁定与声明的 PHP 版本矛盾（发布阻断级）

**现象**：`composer.json` 声明 `"php": ">=7.4"`，但 `vendor/composer/platform_check.php` 生成为 `PHP_VERSION_ID >= 80002`。在 PHP 7.4 上启动直接 fatal：

```text
Composer detected issues in your platform:
Your Composer dependencies require a PHP version ">= 8.0.2". You are running 7.4.3.
```

**根因**：依赖在 PHP 8.0.2 开发机上解析，Composer 据此选出 `firebase/php-jwt v6.11.1`（要求 `php ^8.0`）与 `symfony/* v6.0.x`（要求 `php >=8.0.2`）。`composer.json` 的 `require.php` 只约束下游宿主，不约束本地解析结果。

**影响**：任何 PHP 7.4 宿主项目 `composer require tozo/security-sdk` 后无法启动。声明的最低版本承诺是无效的。

**修复**：新增 `config.platform.php = "7.4.0"` 锁定解析目标并重新解析：

| 依赖 | 修复前 | 修复后 |
|---|---|---|
| `firebase/php-jwt` | v6.11.1（需 PHP ^8.0） | **v6.10.0**（支持 ^7.4） |
| `symfony/string` 等 | v6.0.19（需 >=8.0.2） | **v5.4.47** |
| `platform_check.php` 门槛 | `>= 80002` | **`>= 70400`** |

**验证**：此前 PHP 7.4.3 基线实跑 `tools/lint.php`（107 文件 0 失败）与全量测试（219 tests / 592 assertions 全通过）；当前 checkout 的新鲜 PHP 8.0.2 证据见 §5。

### R-2 PHP 7.4 兼容性缺少持续守卫

**问题**：即使当前代码兼容 7.4，后续提交仍可能引入 8.0 专有语法；CI 未必总能提供 7.4 运行时，且语法错误只在被加载的文件上暴露。

**修复**：新增 `tests/Unit/Php74CompatibilityTest.php`，对全量源码做静态扫描，拦截十类 8.0+ 构造（新增字符串/类型函数、`match`、`?->`、构造器属性提升、`mixed`/`static` 类型声明、Attributes、非捕获 `catch`、`throw` 表达式），并断言 `composer.json` 的 `platform.php` 与 `vendor` 门槛。

扫描前用 `token_get_all` 剥离注释与字符串字面量（保留字节偏移以定位行号），避免注释中的示例文本被误判。

**负向对照**：向 `SystemClock.php` 注入 `str_contains()` 与 `?->` 后，测试立即以精确行号失败；移除后恢复通过。

### R-3 Protocol v1 缺少冻结的一致性基准

**问题**：v0.0.4 刚重写了 query 与 path 规范化规则。若不落成只读向量，第二种语言实现会重新引入同类问题——而这正是 v0.0.4 修复的 P0 缺陷类型。

**修复**：新增 `protocol/test-vectors-v1.json`，冻结 10 组 70 条向量；新增 `protocol/README.md` 说明字节级规则与变更纪律；新增 `tests/Unit/ProtocolVectorTest.php` 只读消费（11 用例 / 115 断言）。

**独立复核**：用**不调用 SDK 任何类**的手工脚本重算全部 signature 与 response_signature 向量，并将 base64url 抽样值与 RFC 4648 已知值（`abc` → `YWJj` 等）对照，TTL 公式逐条验算。全部通过——向量不是"实现自证实现"。

### R-4 依赖 CVE 需要明确处置结论

**问题**：`firebase/php-jwt < 7.0.0` 存在 CVE-2025-45769（低危，weak encryption）。修复版本 7.x 要求 PHP ^8.0，与 PHP >= 7.4 基线冲突。

**处置**：锁定 6.10.0，并以可执行证据说明本 SDK 用法不受该攻击面影响：

1. 算法由 Profile driver 固定，SDK 从不读取 Header `alg`。
2. 密钥以 `Key(材料, 算法)` 传入；底层 `JWT.php:141` 以 `constantTimeEquals($key->getAlgorithm(), $header->alg)` 校验，不一致抛异常。
3. `alg=none` 被空算法与不支持算法两道检查拦截。

新增 `tests/Unit/TokenAlgorithmConfusionTest.php` 固化 7 个用例：`alg=none`、RSA 公钥当 HMAC 密钥的 HS256 混淆、不支持算法、未知 `kid`、缺失 `kid`、RS256 Token 交给 HS256 Profile，以及**正向对照**（匹配时必须通过——没有对照，负向用例可能只是"因别的原因失败"）。

同时在说明书 §18 给出宿主项目若可接受 PHP >= 8.0 的替代方案，把版本策略决定权交回项目方。

### R-5 发布与验证工程化缺失

| 缺口 | 修复 |
|---|---|
| 无统一验证入口 | `composer run verify`（lint + 规范自查 + 测试），返回码可用于 CI |
| 检查逻辑散落在临时脚本 | 固化为 `tools/lint.php`、`tools/audit.php` |
| 分发包含开发期文件 | `.gitattributes` 的 `export-ignore` 排除 tests/docs/IDE 配置 |
| 行尾未统一 | `.gitattributes` 强制 LF——签名原文含 `\n`，CRLF 会导致跨平台签名不一致 |

`protocol/` **不**排除：它是跨语言实现的协议事实来源，必须随包分发。

### R-6 Profile 显式 null 会静默改变安全语义

**现象**：Profile 原先用 `??` 和非数组归一化读取配置，`enabled=null` 可能被当成关闭，`signature=null` 等整段配置可能被当成空数组，安全字段的显式 null 因而绕过后续校验。

**修复**：`Profile::fromConfig()` 在应用级 defaults 合并前递归检查 Profile 配置树；显式 null 统一抛出 `ConfigurationException`，异常包含 Profile 名称和点号字段路径。`subject_id` 仍保留签发场景可选的 `null` 语义，关闭功能必须明确写 `false`，使用默认值则省略字段。

**验证**：先向 `GapClosureTest` 加入 32 条路径的失败回归，确认 `enabled=null` 能绕过校验；修复后 `GapClosureTest` 16 tests / 81 assertions 通过，当前 `ProfileValidationTest` 为 20 tests / 34 assertions，全量测试包含这些回归。

### R-7 共享审计后端的多 Profile 冲突

**现象**：多个启用的出站 Profile 共用一个 `AuditSinkInterface`，旧选择逻辑只读取首个声明的 `audit.driver`；当 Profile 分别配置 `cache` 与 `log` 时，后者会被静默忽略。

**修复**：Provider 在注册共享 AuditSink 前遍历全部启用出站 Profile，未声明 driver 按 `cache` 处理；driver 不一致时立即抛出 `ConfigurationException`，一致时才创建共享后端。

**验证**：`ServiceProviderTest` 新增冲突配置回归；本轮专项结果为 21 tests / 98 assertions 全通过。

### R-8 Token 开关与 Profile 方向不一致

**现象**：旧校验只按当前方向读取有效 Token 开关，没有拒绝反方向的 `attach_enabled`、`verify_enabled` 或 `issue_enabled`。例如入站 Profile 可以误配 `attach_enabled=true`，出站 Profile 可以误配 `verify_enabled=true`；`token_revocation.enabled` 也可能出现在没有入站验证腿的 Profile 中。

**影响**：配置表达与实际执行链不一致，可能触发不必要的 Token Issuer/Verifier 或吊销存储依赖，且掩盖 Profile 单向边界错误。

**修复**：`Profile::validateToken()` 现在强制入站只使用 `verify_enabled`，出站只使用 `attach_enabled`/`issue_enabled`；吊销开关必须同时满足 `inbound + verify_enabled=true`。新增 4 个方向边界回归用例。

**验证**：`ProfileValidationTest` 本轮 20 tests / 34 assertions 全通过；完整 `composer run verify` 为 284 tests / 1151 assertions。

### R-9 显式路由 Profile 缺少调用方身份绑定

**现象**：路由通过 `tozo_profile` 直接选定入站 Profile 时，旧逻辑未强制校验 `X-Tozo-Client-Id` 与该 Profile 的 `client_id` 相同。合法签名可以在错误身份 Header 下进入业务层，导致路由绑定的信任关系与请求身份索引不一致。

**修复**：`InboundAuthenticatorMiddleware::resolveProfile()` 在显式路由 Profile 命中后强制要求 `X-Tozo-Client-Id` 非空且与 Profile 的 `client_id` 通过常量时间比较；不一致统一拒绝为 `invalid_request`，不进入业务层。

**验证**：`SecurityBoundaryClosureTest` 以完整协议 Header 重现错误身份请求，修复后 `1 test / 2 assertions` 通过；完整门禁当前为 284 tests / 1151 assertions。

## 3. 累计缺陷修复清单

v0.0.4 修复 16 项（P0 三项：query 双端规范化不一致、嵌套 query 签名碰撞、响应完整性链路开环；P1 三项：Facade 未绑定、必需参数位于可选参数之后、config BOM；P2 十项）。

v0.0.5 修复 5 项（本报告 §2）。

当前补充修复 4 项：Profile 安全配置显式 null 拒绝，并以 `GapClosureTest` 覆盖顶层、段级和关键子键；共享 AuditSink 的多 Profile driver 冲突拒绝，并以 `ServiceProviderTest` 固化；Token 开关方向边界与吊销前置条件，并以 `ProfileValidationTest` 固化；显式路由 Profile 的调用方身份绑定，并以 `SecurityBoundaryClosureTest` 固化。

累计 23 项，每项均先用可执行探针确认可触发，再修复，再用测试固化。

## 4. 模块审查结论

| 模块 | 状态 | 本轮变更 | 剩余风险 |
|---|---|---|---|
| Profile | 方向/模式/driver/密钥用途/三层合并/跨层门控完整；显式 null 与反向 Token 开关拒绝 | **新增显式 null、方向边界回归覆盖** | 生产配置需部署期体检 |
| Protocol | 11 字段规范化；query 原始字节；path 点段解析 | **向量冻结 + 独立复核** | PHP/Python/Go 已完成向量一致性；真实业务互调未验证 |
| Signature | HMAC-SHA256、双向时间窗、Nonce、TTL 公式、密钥状态、fail-closed | 向量覆盖 | Redis `SET NX EX` 真实行为未压测 |
| Authentication | JWT 与 HMAC-Bearer 按 driver 路由，不遍历降级 | 无 | 真实合作方 Header 兼容需互测 |
| Encryption | AES-256-GCM、CSPRNG nonce、七字段方向绑定 AAD、32 字节强校验 | AAD 向量覆盖 | 跨语言密文向量未互测 |
| Response Integrity | 生成 + 验证双向闭环；固定 mode；独立用途密钥 | 响应签名向量覆盖 | 真实代理 Header 归一化未验证 |
| Token | RS256/HS256、kid 白名单、全 claims 绑定、吊销 fail-closed | **算法混淆防护固化** | 真实公钥分发与吊销存储未演练 |
| Scope | 主体类型白名单、精确匹配、禁通配符 | 无 | 路由风险分级由项目方维护 |
| Key | env/file/array、目录穿越防护、轮换状态机 | 无 | 生产密钥加载未演练 |
| Storage | Cache Replay / Revocation / Cache+Log Audit，全部 fail-closed | 无 | Redis 故障与并发未压测 |
| HttpClient | 七步流程、Encrypt-then-Sign、传输结果形态校验 | 无 | Guzzle 真实网络未验证 |
| Laravel Middleware | 入站六步、出站四步、响应保护 | 无 | 真实 Kernel/路由链未验证 |
| Facade/Provider | 容器按需绑定、访问器已绑定 | 无 | 不同宿主 Provider 顺序需验证 |
| Audit/Exceptions | 唯一脱敏来源、稳定原因码、对外安全类别码 | 无 | 集中日志合规由部署方确认 |
| **发布工程** | — | **平台锁定 + 双版本验证 + 分发裁剪** | 无 CI 服务器持续执行 |

## 5. 自动化证据

```text
=== PHP 8.0.2 ===
tools/lint.php            121 个文件，失败 0 个
tools/audit.php           结论：全部检查项通过
phpunit                   OK (284 tests, 1151 assertions)

=== PHP 7.4.3 历史基线 ===
tools/lint.php            107 个文件，失败 0 个
phpunit                   OK (219 tests, 592 assertions；此前 checkout）

=== 规范自查明细（src 320 个具名方法）===
缺少方法级 PHPDoc          0
@param 未覆盖签名参数      0
缺少 @return               0
UTF-8 BOM 文件             0
Tab 缩进文件               0
孤立 PHPDoc 块             0
未使用 use 导入            0

=== 其他 ===
composer validate         ./composer.json is valid
platform_check 门槛       PHP_VERSION_ID >= 70400
协议向量                  10 组 / 70 条，独立手工复核通过
风格约定                  ApiStyleTest + Php74CompatibilityTest 通过
```

### 5.1 本轮新增测试

| 文件 | 用例 | 覆盖内容 |
|---|---:|---|
| `tests/Unit/ProtocolVectorTest.php` | 11 | 只读消费 70 条冻结向量，逐条字节比对 |
| `tests/Unit/TokenAlgorithmConfusionTest.php` | 7 | alg=none、算法混淆、未知/缺失 kid、跨 driver 拒绝 + 正向对照 |
| `tests/Unit/Php74CompatibilityTest.php` | 12 | 十类 8.0+ 语法静态扫描 + platform 锁定断言 |
| `tests/Unit/ProfileValidationTest.php` | 20 | Token 开关方向边界、吊销前置条件与既有 Profile 结构校验 |

### 5.2 负向对照（证明测试有效）

| 注入的缺陷 | 期望结果 | 实测 |
|---|---|---|
| 入站 query 改回 `$request->query->all()` | `QueryInteropTest` 失败 | 3 项 `invalid_signature` 失败 |
| `SystemClock` 注入 `str_contains()` + `?->` | `Php74CompatibilityTest` 失败 | 2 项失败并精确报出行号 |

两项均在移除注入后恢复通过。

## 6. 生产准入建议

按优先级，本机无法完成的项排在前面：

1. **完整 Laravel 8.5 应用集成测试**：HTTP Kernel、路由参数绑定、中间件 alias、`config:cache`、package discovery；当前 Composer 实际约束以 Illuminate Console ^8.83 为准。
2. **Redis 多实例并发重放测试**：`add()` 原子性、TTL 下限、网络分区下的 fail-closed 行为。
3. **Guzzle 真实 HTTPS**：TLS、代理、超时、4xx/5xx、响应 Header 大小写归一化。
4. ~~第二语言实现消费向量~~：已由 v0.0.6 报告中的 Python/Go 独立实现完成；仍需在业务系统完成真实双向互调。
5. ~~CI 矩阵~~：已落地 CI 配置和本地等价入口；仍需在目标 CI 服务执行。
6. 生产密钥注入、权限、轮换与回滚演练。
7. 逐路由标注风险，禁止未评审的 `token_only` 写操作。
8. 日志脱敏抽查、告警、容量与审计留存验证。
9. 高并发签名/加解密与大 Body 内存测试。

四系统可复制文件已落在 `四系统实际配置文件-v0.0.8/`（该版本已被 v0.0.9 取代并删除，现行示例包见 [`四系统实际配置文件-v0.0.9/`](四系统实际配置文件-v0.0.9/README.md)），并按测试/生产拆分。该产物解决的是接入文件和参数口径，不代表四个真实业务仓库、Redis、TLS 或 12 条 staging 有向关系已经验收。

## 7. 关于"百分之百无误"

需要如实区分两件事：

**代码级逻辑闭环**——在当前测试覆盖范围内是完整的：

- 当前 checkout 的 284 项测试在 PHP 8.0.2 上全部通过；PHP 7.4.3 仍有此前 219 项基线证据，需在当前 checkout 重跑
- Profile 显式 null 不能作为关闭或默认值；32 条字段路径由回归测试验证为抛出 `ConfigurationException`；显式安全开关非布尔值也会被拒绝。
- 协议规则有 70 条独立复核过的冻结向量约束
- 关键攻击面（query 不一致、响应开环、算法混淆、空 key_id、fail-open）均有负向用例
- 全部结论可用本报告 §5 的命令复现

**生产无误**——尚不能承诺。第 6 节前四项在本机无法验证，其中任何一项都可能暴露新问题。典型风险：Redis 驱动的 `add()` 在特定配置下未必原子；反向代理可能改写 Header 大小写或归一化 path；真实 Laravel 的 `config:cache` 可能改变配置数组的序列化行为。

因此当前可以负责地说的是：**代码逻辑与协议规则在当前自动化覆盖范围内达到可发布 `0.0.x` 版本供受控试点使用的程度**，但不应在完成第 6 节中的真实 Laravel、Redis、HTTPS、四系统互调和生产运维验证之前直接投入生产关键链路。

## 8. 最终判断

相比 v0.0.4，本轮的实质进展是把跨语言实现建立在经独立复核的协议基准上、补齐显式 null 与 Token 方向配置边界，并验证当前 checkout 的 PHP 8.0.2 全量门禁；“声明支持 PHP 7.4”仍需在当前 checkout 的 PHP 7.4.3 环境重跑确认。PHP 7.4 运行时、真实 Laravel/Redis/HTTPS、四系统互调和生产运维仍属于发布前的重要风险。

建议下一阶段：从 `四系统实际配置文件-v0.0.8/`（该版本已被 v0.0.9 取代并删除，现行示例包见 [`四系统实际配置文件-v0.0.9/`](四系统实际配置文件-v0.0.9/README.md)） 选择对应系统和环境，在四个真实业务项目分别安装并发布配置，先用 `signed_request` 完成 12 条有向 staging 互调，再按风险逐条升级到 `token_plus_request_signature`；同时补做 PHP 7.4.3 当前 checkout、真实 Laravel、Redis、HTTPS、密钥轮换和压测验证。操作步骤见《四系统 Composer 安装与两两互调操作指南》。
