# Tozo Security SDK 配置精简方案 v0.0.9

> 本文记录配置精简重构的**全部可行方案**、推荐选择与理由、硬约束清单与落地步骤。
> 用途：决策留档与回看。不是使用说明书，使用方式见 `Tozo-Security-SDK-各模块使用说明书`。

---

## 1. 需求来源

来自 `docs/SDK-需求变更记录.txt` 配置精简块，共 6 条：

1. 当前 SDK 配置参数属性太多，使用耗时且不利于他人使用。
2. 不再读取 `.env`，所有配置信息写在 `tozo_security.php`；`tozo_services.php` 不再需要，其参数并入前者。
3. 期望他人快速上手，而非配置一大堆参数，降低学习时间成本。
4. 给出全新的、上手快的配置方案。
5. 四系统两两调用，各项协议、加解密方式及其他模块功能应当一致，不需额外重复配置。
6. 先详细阅读四系统现有配置逻辑，先给出方案再定夺。

---

## 2. 现状量化诊断

| 指标 | 实测值 | 来源 |
|---|---|---|
| 单套四系统配置 | 548 行 / 224 个配置键 / 6 个 Profile | `tozoApp-api/production/config/tozo_security.php` |
| 八套配置合计 | 约 4384 行 | 4 系统 × 2 环境 |
| 包内自带配置 | 422 行 / 74 个配置键 | `config/tozo_security.php` |
| 单套 `.env` 变量 | 31 个（12 个为密钥） | `tozoApp-api/production/.env` |
| 跑通一次 A→B 调用 | 约 38 步（两端各 19 步） | 操作指南 §3–§12 |
| 四系统全量铺开 | 约 152 步 | 4 系统 × 2 环境 |
| 手工抄写样板代码 | 1856 行，八套间真实差异 < 60 行 | `Client`/`Controller`/`Kernel`/`routes`/`services` |
| 密钥物料 | 每环境 24 个，96 处写入点 | 12 关系 × 请求/响应 × 两端 |
| 测试基线 | 49 tests / 774 assertions 全绿 | `composer test` |

---

## 3. 冗余根源（三层）

### 3.1 第一层：Profile 内部，84% 字段恒定

每个 Profile 24 个字段，真变量只有 5 个：

```text
direction   client_id   target_service
signature.key_id        response_integrity.signature.key_id
```

`subject_id` 恒等于 `client_id`，不计独立变量。

以下 19 个字段在**全部 48 个 Profile 中取值 48/48 完全相同**：

| 字段 | 唯一取值 |
|---|---|
| `security_mode` | `signed_request` |
| `subject_type` | `service` |
| `signature.driver` | `hmac_sha256` |
| `signature.max_age_seconds` | `300` |
| `signature.clock_skew_seconds` | `60` |
| `signature.replay_protection` | `true` |
| `signature.replay_safety_margin_seconds` | `5` |
| `encryption.enabled` | `false` |
| `encryption.driver` | `aes_256_gcm` |
| `response_integrity.required` | `true` |
| `response_integrity.mode` | `signed` |
| `token.attach_enabled` / `verify_enabled` / `issue_enabled` | 均 `false` |
| `replay_store.driver` | `cache` |
| `audit.driver` | `cache` |
| `enabled` | `true` |
| `protocol_version`（顶层） | `'1'` |

### 3.2 第二层：Profile 之间，6 个可由 3 个对端推导

`{本服务}_outbound_to_{对端}` 与 `{本服务}_inbound_from_{对端}` 成对出现，字段互为镜像：

| 字段 | outbound | inbound |
|---|---|---|
| `client_id` | 本服务 | 对端 |
| `target_service` | 对端 | 本服务 |

声明 3 个对端即可生成 6 个 Profile。

### 3.3 第三层：应用级，`features` 与 `defaults` 整段冗余

- `features`（11 键）：门控逻辑是「开关为 true **且** 至少一个 Profile 引用」（`ServiceProvider.php:430-437`），前一半可由后一半完全推导。
- `defaults`（12 键）：全部为协议常量，应下沉为 SDK 内置默认值。

### 3.4 协议层佐证

`protocol/README.md` 冻结的 Protocol v1：

- 签名规范化串固定 11 字段，随关系变化的只有 `client_id`、`target_service`、`key_id`。
- AEAD AAD 固定 7 字段，可变项同上。
- 响应签名原文固定 6 字段，可变项同上。
- 算法白名单首版各只有一个合法值：`hmac_sha256`、`aes_256_gcm`。

**结论：需求第 5 条成立。四系统之间不存在任何一对需要独立协议参数的情形（48/48 全同）。**

---

## 4. 硬约束清单（方案不可违反）

| # | 约束 | 位置 | 对方案的影响 |
|---|---|---|---|
| C1 | 每个配置键必须有中文注释 | `MemberCommentCoverageTest.php:70`、`tools/audit_members.php:192` | 新配置须逐键注释 |
| C2 | 配置键总数 `assertGreaterThan(50)` | `MemberCommentCoverageTest.php:93` | **与精简正面冲突，须下调阈值** |
| C3 | `features.token_issuer === false` | `ServiceProviderTest.php:326` | 删 `features` 须改断言 |
| C4 | 配置键名不得含 `secret` | `ServiceProviderTest.php:331-334` | 只查键名、只查 `secret` 一词、不查值 |
| C5 | 包内配置须含 4 个指引字符串 | `FreshInstallTest.php:154-161` | 须重写快速开始段落 |
| C6 | Profile 名硬编码 `default` | `FreshInstallTest.php:66/89/112`、`PayloadSizeGuardTest.php:161` | 改名须同步 |
| C7 | 8 套 × 6 Profile、12 有向关系、命名格式、48 个 PHP 文件、3 条路由、6 行 README | `FourSystemConfigurationTest.php` | 示例包重构须同步重写 |
| C8 | 配置文件须含 PhpStorm 头，日期格式 `YYYY/MM/DD` | `FileHeaderTest.php:42` | 格式固定 |
| C9 | 无 UTF-8 BOM | `DefectRegressionTest.php:198` | 写文件注意编码 |
| C10 | 无 PHP 8.0+ 语法 | `Php74CompatibilityTest.php:85` | 扫 `config/` |
| C11 | 无返回类型声明、无 nullable 参数类型 | `ApiStyleTest.php:23` | 扫 `config/` |
| C12 | Protocol v1 已冻结 | `protocol/test-vectors-v1.json` | 签名/AAD 字段不可变更 |
| C13 | 生产环境禁用 `ArrayKeyProvider` | `ServiceProvider.php:131-132` | 内联密钥方案受此拦截 |
| C14 | 设计基线：敏感密钥不得直接写入配置数组 | 设计报告 v0.0.2 §334 | 内联密钥方案违反此条 |

---

## 5. 方案空间

配置精简可拆为两个**相互独立**的决策维度。

### 5.1 维度 A：密钥存放

| 选项 | `.env` 依赖 | 密钥入 git | 实现代价 | 安全评价 |
|---|---|---|---|---|
| A1 环境变量注入（现状） | 12 个变量/套 | 否 | 零 | 基线，符合 C14 |
| **A2 受控目录文件** | **完全消除** | **否** | 极低，`FileKeyProvider` 已存在 | 与 A1 等价 |
| A3 内联进 `tozo_security.php` | 完全消除 | **是** | 低，但须拆除 C13/C14 | **明确降级** |

**A1 现状问题**：`.env` 31 个变量中 12 个是密钥，变量名须人工从 `key_id` 推导（非字母数字转下划线 + 全大写 + 拼前缀），推导错误表现为「配了但读不到」的 `KeyNotFoundException`。

**A2 机制**：`FileKeyProvider` 从 `storage/app/tozo/keys/{key_id}.key` 读取，自带目录穿越防护与 `key_id` 字符白名单（`FileKeyProvider.php:109-119`）。安装命令批量生成密钥文件并写入 `.gitignore`。配置文件内零 `env()` 调用。

**A3 代价**：`config/tozo_security.php` 经 `vendor:publish` 进入宿主项目并被 git 跟踪。24 个生产 HMAC 密钥入库后，任何具备仓库读权限者（含外包、未清理的离职账号、CI 日志、fork）均获得全网签名能力。`signed_request` 模式下签名即身份，无第二道防线。同时须修改 `EnvKeyProvider.php:19` 类级安全边界注释、八套示例配置文件头注释，并绕过 C13 的生产期拦截。

### 5.2 维度 B：配置结构

| 选项 | 配置键数 | 需理解的概念 | 实现代价 |
|---|---|---|---|
| B1 保留显式 Profile，仅删 `features`/`defaults` | 约 180 | Profile 方向语义、模式矩阵、三层合并 | 低 |
| **B2 声明对端，Profile 自动推导** | **6** | **我是谁 / 什么环境 / 跟谁通信** | 中 |
| B3 零配置，运行时自动发现对端 | 0 | 无 | 高，且失去配置可审计性 |

**B1 局限**：键数虽减少 20%，但用户仍须逐个编写 6 个 Profile、理解 `direction` 语义与 `security_mode` 的 AND 矩阵，学习成本几乎不降。未解决需求第 3 条。

**B2 机制**：见第 6 节推导规则。`key_id` 由四元组推导，用户不再手写 24 个密钥标识。

**B3 否决理由**：服务发现需引入注册中心或约定式探测，与「零外部依赖」定位冲突；且配置文件不再体现信任关系，安全审计无从下手。

---

## 6. 推荐组合：A2 + B2

### 6.1 新配置文件形态

```php
return [
    // service string｜本系统身份；四系统标识之一，是全部推导的起点。
    'service'     => 'tozo-app-api',

    // environment string｜运行环境；决定密钥命名空间，production 禁用测试密钥源。
    'environment' => 'production',

    // peers array｜对端名单；键为对端服务标识，值为其 HTTPS 根地址。
    // 声明即建立双向信任：自动生成 outbound_to_X 与 inbound_from_X 两个 Profile。
    'peers'       => [
        // app-admin-api string｜后台管理 API 根地址。
        'app-admin-api' => 'https://app-admin-api.example.com',
        // pmc-api string｜生产管理 API 根地址。
        'pmc-api'       => 'https://api-pms.example.com',
        // pos-api string｜POS API 根地址。
        'pos-api'       => 'https://pos-api.example.com',
    ],
];
```

**548 行 → 约 20 行；224 键 → 6 键；须理解概念 → 3 个。**

### 6.2 推导规则

| 推导项 | 规则 |
|---|---|
| Profile 名 | `{service}_outbound_to_{peer}` / `{service}_inbound_from_{peer}` |
| `client_id` | outbound 取 `service`；inbound 取 `peer` |
| `target_service` | outbound 取 `peer`；inbound 取 `service` |
| `subject_type` | 恒为 `service` |
| `subject_id` | 同 `client_id` |
| `signature.key_id` | `{environment}_{caller}_to_{callee}_request` |
| `response_integrity.signature.key_id` | `{environment}_{caller}_to_{callee}_response` |
| `security_mode` | `signed_request`（基线） |
| 其余 19 字段 | SDK 内置常量 |
| `features` | 由 Profile 实际引用自动推导 |
| `base_uri` | 取 `peers` 中该对端的值 |

`key_id` 命名从 `production_a_to_b_request` 改为 `production_tozo-app-api_to_app-admin-api_request`。原 a/b/c/d 虽为全局稳定映射（a=tozo-app-api、b=app-admin-api、c=pmc-api、d=pos-api），但要求所有人记住字母表，新人接手易出错。

### 6.3 `tozo_services.php` 处置

整体删除，11 个键去向：

| 原键 | 去向 |
|---|---|
| `base_urls`（4 条） | 并入 `peers` 的值 |
| `environment` | 与 `tozo_security.environment` 合并为单一事实来源 |
| `tls.verify` / `tls.min_version` | SDK 内置默认（`true` / `TLSv1.2`） |
| `http.timeout` / `http.connect_timeout` | SDK 内置默认（`10` / `3`） |

需覆盖时通过可选顶层键声明，默认不出现在配置文件中。

### 6.4 保留的升级出口

以下能力必须保留 per-relation 覆盖，不可焊死（文档三处明确预留）：

```php
'peers' => [
    'app-admin-api' => [
        'base_uri'      => 'https://app-admin-api.example.com',
        'security_mode' => 'token_plus_request_signature',  // 按关系升级
        'encryption'    => true,                             // 按关系开启请求加密
    ],
],
```

字符串值为简写形态（等价于只给 `base_uri`），数组值为完整形态。两种写法并存。

---

## 7. 落地步骤与影响面

| 阶段 | 动作 | 涉及文件 | 风险 |
|---|---|---|---|
| P1 | 新建极简配置文件 | `config/tozo_security.php` | 低 |
| P2 | 新增配置展开器：极简形态 → 内部完整形态 | `src/.../Support/ConfigNormalizer.php`（新增） | 中 |
| P3 | ServiceProvider 接入展开器，去除 `features` 门控前置条件 | `ServiceProvider.php` | 中 |
| P4 | HttpClient 增加按目标服务选路的便捷入口 | `Http/TozoHttpClient.php` | 低 |
| P5 | 调整受影响测试断言 | `MemberCommentCoverageTest`、`ServiceProviderTest`、`FreshInstallTest`、`PayloadSizeGuardTest` | 中 |
| P6 | 重新生成八套示例配置，删除 `tozo_services.php` | `docs/四系统实际配置文件-v0.0.9/` | 中 |
| P7 | 新增安装命令：批量生成密钥 + 写 `.gitignore` + 生成路由 | `Laravel/Command/SecurityInstallCommand.php`（新增） | 中 |
| P8 | 全量验证 | `composer verify` | — |

### 7.1 测试调整明细

| 测试 | 现状断言 | 调整方式 | 理由 |
|---|---|---|---|
| `MemberCommentCoverageTest.php:93` | `assertGreaterThan(50, $total)` | 下调阈值 | 该下限本意是防止 glob 未匹配或正则失效，不是要求配置必须有 50 个键。精简后仍保留「每键必须有中文注释」这一真实断言 |
| `ServiceProviderTest.php:326` | `assertFalse($config['features']['token_issuer'])` | 改为断言默认安装不绑定 `TokenIssuerInterface` | 保留「默认不签发 Token」的安全意图，换用不依赖 `features` 键的等价断言 |
| `FreshInstallTest.php:154-161` | 4 个指引字符串 | 更新为新命令与新键名 | 快速开始段落随配置重写 |
| `FreshInstallTest.php:66/89/112` | 硬编码 profile 名 `default` | 改为推导出的 Profile 名 | 极简配置不再有 `default` 模板 |
| `PayloadSizeGuardTest.php:161` | `profiles.default.encryption.max_plaintext_bytes` | 改为读展开后的注册表 | 同上 |
| `FourSystemConfigurationTest.php` | 8 套 × 6 Profile、12 关系、命名格式、48 个 PHP 文件 | 按新示例包重写 | 示例包结构变更 |

### 7.2 不受影响的测试

以下测试全部使用 `TestCase` 夹具，不读取配置文件，无需改动：

`ProfileValidationTest`（24 方法）、`SecurityBoundaryClosureTest`、`GapClosureTest`、`ProtocolVectorTest`、`AesGcmCipherTest`、`KeyProvidersTest`、`TokenAlgorithmConfusionTest`、`ResponseIntegrityClosureTest`。

`Profile.php` 的校验逻辑与 `protocol/` 冻结向量均不改动，协议兼容性不受影响。

---

## 8. 预期收益

| 指标 | 现状 | 精简后 | 降幅 |
|---|---|---|---|
| 单套配置行数 | 548 | 约 20 | 96% |
| 单套配置键数 | 224 | 6 | 97% |
| `.env` Tozo 变量数 | 31 | 0 | 100% |
| 配置文件数 | 2（`tozo_security` + `tozo_services`） | 1 | 50% |
| 手工抄写样板代码 | 1856 行 | 0（由 SDK 提供或命令生成） | 100% |
| 跑通一次 A→B 步数 | 约 38 | 约 8 | 79% |
| 须理解的概念 | Profile 方向语义、模式矩阵、三层合并、features 双门控、7 类密钥用途 | 我是谁 / 什么环境 / 跟谁通信 | — |

---

## 9. 风险与回退

| 风险 | 应对 |
|---|---|
| 推导规则与现有部署的 `key_id` 命名不一致，升级即断连 | 保留 `key_id` 显式覆盖能力；提供命名映射对照表；灰度期两套命名并存 |
| 极简配置隐藏了安全参数，运维无法确认实际生效值 | `tozo:security:check-config` 增加展开结果打印，输出完整 Profile 快照 |
| per-relation 覆盖能力被误用为逐关系重复配置，退回冗余 | 覆盖项仅接受与基线不同的值；`check-config` 对冗余声明给出告警 |
| `FileKeyProvider` 目录权限配置不当导致密钥可被 web 访问 | 默认落在 `storage/app/` 下（Laravel 默认不对外暴露）；安装命令校验目录权限并写 `.gitignore` |
| 展开器引入的隐式行为增加排障难度 | 展开逻辑单一入口、纯函数、全量单测覆盖；`check-config` 可导出展开前后对照 |

回退路径：展开器只在 `ServiceProvider::register()` 早期把极简配置转为内部完整形态，`Profile`、`ConfigChecker`、中间件、`protocol/` 均不改动。若需回退，恢复旧配置文件即可，SDK 内核对两种形态都兼容。

---

## 10. 未采纳方案备查

| 方案 | 否决理由 |
|---|---|
| A3 密钥内联进配置文件 | 生产密钥进 git，`signed_request` 下等于全网身份伪造能力泄露；违反设计基线 §334 与 `ServiceProvider.php:131-132` 生产期拦截 |
| B1 仅删 `features`/`defaults` | 键数只降 20%，用户仍须逐个编写 Profile 并理解方向语义与模式矩阵，未解决需求第 3 条 |
| B3 零配置自动发现 | 需引入注册中心或约定式探测，与零外部依赖定位冲突；配置文件不再体现信任关系，安全审计无从下手 |
| 保留 `tozo_services.php` 仅做瘦身 | 与需求第 2 条直接冲突；且 `environment` 在两文件重复声明，属同一事实多处对齐 |
| 用 `.env` 承载极简配置 | 与需求第 2 条直接冲突；且数组型 `peers` 无法用扁平环境变量自然表达 |
